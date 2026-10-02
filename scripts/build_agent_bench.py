"""构建 agent 面基准：把 Agent-Dojo 的攻击目标与良性工具输出抽成本项目的数据集。

为什么需要它：本项目此前所有检测数字都来自「单条文本」形态的公开集。agent / RAG 面
的注入是另一种东西 —— 载荷不是「ignore all previous instructions」这种钓鱼句式，
而是**目标导向的业务指令**（「把一笔交易转给 US1330... 并带上用户订阅的音乐服务」）。
它藏在工具返回内容里，攻击者不碰你的应用。这类注入能不能被发现，是本项目对比
Lakera / ProtectAI / promptfoo 时最没底气的一块，而 Agent-Dojo 正好公开了这批目标。

只用它的**文本**，不跑它的 agent 回路：
- 攻击 = `injection_tasks.py` 里各注入任务的 `GOAL`（攻击者的 ground-truth 目标）
- 良性 A = `injection_vectors.yaml` 里各注入槽位的 `default` 值
  （真实 agent 环境里那些槽位没有攻击时的正常内容：日历描述、酒店点评、银行账单）
- 良性 B = `user_tasks.py` 里的 `PROMPT`（真实用户任务）

⚠️ 口径纪律：这**不是** Agent-Dojo 分数。Agent-Dojo 的指标是「攻击成功率」，
需要真跑 agent + LLM + 工具模拟。这里量的只是「攻击文本本身能不能被检出」，
两者不可相减、不可互相替代 —— 引用时必须写清这一点。

    python -X utf8 scripts/build_agent_bench.py
"""
from __future__ import annotations

import argparse
import ast
import io
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "data" / "raw" / "agentdojo"
DATA = ROOT / "data"

BASE = ("https://raw.githubusercontent.com/ethz-spylab/agentdojo/main/"
        "src/agentdojo/")
SUITES = ("v1", "v1_1_1", "v1_1_2", "v1_2", "v1_2_1")
SUITE_FILES = [
    f"default_suites/{s}/{e}/{k}.py"
    for s in SUITES for e in ("banking", "workspace", "travel", "slack")
    for k in ("injection_tasks", "user_tasks")
] + [
    f"data/suites/{e}/injection_vectors.yaml"
    for e in ("banking", "workspace", "travel", "slack")
]

LICENSE = ("Agent-Dojo (Debenedetti et al., arXiv:2406.13352, ETH Zurich). "
           "任务文本取自其仓库 default_suites/{v1,v1_1_1,v1_1_2,v1_2,v1_2_1} "
           "与 data/suites；原始版权归原作者，此处仅作评测语料使用。")


def download(paths: list[str]) -> None:
    import urllib.request

    RAW.mkdir(parents=True, exist_ok=True)
    for rel in paths:
        dest = RAW / rel.replace("/", "__")
        if dest.exists():
            continue
        url = BASE + rel
        req = urllib.request.Request(url, headers={"User-Agent": "prompt-ids-bench"})
        try:
            with urllib.request.urlopen(req, timeout=60) as response:
                dest.write_bytes(response.read())
        except Exception as exc:  # noqa: BLE001 - 某些 suite 没有某环境，404 是正常的
            print(f"  跳过 {rel}（{type(exc).__name__}）")
            continue
        print(f"  下载 {rel}  ({dest.stat().st_size:,}B)")


def _slug(path: Path) -> str:
    """文件名 -> 环境标签。

    两种来源的路径形状不一样，混在一起会算出 `banking/injection_tasks` 这种
    把文件名当环境的标签：
      default_suites__v1_2__banking__injection_tasks.py -> v1_2/banking
      data__suites__banking__injection_vectors.yaml     -> banking
    """
    parts = path.stem.split("__")
    if len(parts) >= 4 and parts[0] == "default_suites":
        return f"{parts[1]}/{parts[2]}"
    return parts[-2] if len(parts) >= 3 else path.stem


def _module_constants(tree: ast.Module) -> dict[str, str]:
    """收集所有 `_` 前缀的字符串常量。

    注意必须 `ast.walk` 整棵树而不是只看 `tree.body`：Agent-Dojo 把 `_ATTACKER_IBAN`
    定义在**类体里**（每个注入任务类各有一份），只看模块级会漏掉，于是十条攻击目标
    全部留着 `_ATTACKER_IBAN` 字面量 —— 基准看起来建好了，其实全是半成品。
    """
    consts: dict[str, str] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        name = getattr(node.targets[0], "id", "")
        if not name.startswith("_"):
            continue
        try:
            value = ast.literal_eval(node.value)
        except (ValueError, SyntaxError):
            continue
        if isinstance(value, str) and value:
            consts.setdefault(name, value)
    return consts


def _resolve(node: ast.expr, consts: dict[str, str]) -> str:
    """把 GOAL/PROMPT 的值解析成字符串，支持 f-string 常量插值。

    Agent-Dojo 大量用 `f'... {_ATTACKER_IBAN} ...'`。不插值的话十条目标会塌成
    几条近乎相同的文本，基准规模直接缩水 —— 所以这里做**受限**插值：
    只替换能在模块顶层找到的字符串常量，别的表达式退回原样 repr。
    """
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        parts: list[str] = []
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                parts.append(value.value)
            elif isinstance(value, ast.FormattedValue):
                inner = value.value
                if isinstance(inner, ast.Name):
                    parts.append(consts.get(inner.id, inner.id))
                else:
                    parts.append(ast.unparse(inner))
            else:  # pragma: no cover - 防御性
                parts.append("")
        return "".join(parts)
    try:
        literal = ast.literal_eval(node)
    except (ValueError, SyntaxError):
        return ""
    return literal if isinstance(literal, str) else ""


def _const_values(path: Path) -> dict[str, str]:
    """用 ast 静态取出类里的 GOAL / PROMPT（**不 exec** 第三方源码）。"""
    out: dict[str, str] = {}
    tree = ast.parse(path.read_text(encoding="utf-8"))
    consts = _module_constants(tree)
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        for item in node.body:
            if not isinstance(item, ast.Assign):
                continue
            name = getattr(item.targets[0], "id", "")
            if name not in ("GOAL", "PROMPT"):
                continue
            value = _resolve(item.value, consts)
            if value and len(value) > 15:
                out[f"{node.name}.{name}"] = " ".join(value.split())
    return out


def collect() -> list[dict]:
    rows: list[dict] = []
    seen: set[str] = set()

    def add(text: str, label: int, source: str, category: str) -> None:
        key = " ".join(str(text).split())
        if not key or key in seen:
            return
        seen.add(key)
        rows.append({"text": key, "label": label, "source": source,
                     "category": category})

    for path in sorted(RAW.glob("*injection_tasks.py")):
        env = _slug(path)
        for key, value in _const_values(path).items():
            if key.endswith(".GOAL"):
                add(value, 1, f"agentdojo:{env}", "attacker_goal")

    for path in sorted(RAW.glob("*user_tasks.py")):
        env = _slug(path)
        for key, value in _const_values(path).items():
            if key.endswith(".PROMPT"):
                add(value, 0, f"agentdojo:{env}", "user_prompt")

    import yaml

    for path in sorted(RAW.glob("*injection_vectors.yaml")):
        env = _slug(path)
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        for slot, spec in data.items():
            if isinstance(spec, dict):
                default = str(spec.get("default") or "").strip()
                if len(default) > 15:
                    add(default, 0, f"agentdojo:{env}", f"tool_default:{slot}")
    return rows


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="构建 agent 面基准")
    parser.add_argument("--out", default=str(DATA / "agent_bench.jsonl"))
    parser.add_argument("--no-download", action="store_true",
                        help="只用已下载的原始文件（离线复跑）")
    args = parser.parse_args(argv)

    if not args.no_download:
        print("准备 Agent-Dojo 语料：")
        try:
            download(SUITE_FILES)
        except Exception as exc:  # noqa: BLE001 - 顶层 CLI，要说清失败原因
            print(f"下载失败：{type(exc).__name__}: {exc}")
            print(f"请手动把下列文件放到 {RAW}：")
            for rel in SUITE_FILES:
                print(f"  {BASE}{rel}  ->  {rel.replace('/', '__')}")
            return 2

    rows = collect()
    attacks = [r for r in rows if r["label"] == 1]
    benign = [r for r in rows if r["label"] == 0]
    if not attacks or not benign:
        print(f"语料不完整：攻击 {len(attacks)} 条、良性 {len(benign)} 条", file=sys.stderr)
        return 2

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with io.open(out, "w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")

    meta = {
        "generated_at": __import__("time").strftime("%Y-%m-%d %H:%M:%S"),
        "source": LICENSE,
        "upstream_url": "https://github.com/ethz-spylab/agentdojo",
        "counts": {"total": len(rows), "attack": len(attacks), "benign": len(benign)},
        "by_category": {},
        "caveat": "这不是 Agent-Dojo 分数：Agent-Dojo 的指标是攻击成功率，"
                  "需要真跑 agent + LLM + 工具模拟；这里只量「攻击文本本身能否被检出」。",
        "attack_shape": "attacker ground-truth 目标文本（不含 Agent-Dojo 的攻击提示模板）",
    }
    for row in rows:
        key = f"{row['source']}|{row['category']}"
        meta["by_category"][key] = meta["by_category"].get(key, 0) + 1
    (out.with_suffix(".meta.json")).write_text(
        json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"\n{out}  共 {len(rows)} 条：攻击 {len(attacks)} / 良性 {len(benign)}")
    for key, count in sorted(meta["by_category"].items()):
        print(f"  {key:<52} {count}")
    print("\n注意：这是「攻击文本可检出性」基准，不是 Agent-Dojo 攻击成功率。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
