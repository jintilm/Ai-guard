"""出站密钥扫描的取证脚本（先量后用，不先定默认值）。

两件事：
1. **召回**：一组合成的高信号凭据，看是不是全都能抓到。
2. **误报**：真实的良性语料（PINT 良性样本、agent 面良性样本、本仓库自己的源文件、
   本仓库的规则 YAML —— 它们字面写着各种密钥正则，最容易自造过防御）。
   这一项才是决定「默认开不开」的依据。

合成凭据是**假的**（随机后缀），但形状是真的；本脚本不会写出可用的密钥。
"""
from __future__ import annotations

import io
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.stdout.reconfigure(encoding="utf-8")

from prompt_ids.output import scan_secrets, summary  # noqa: E402

# 形状正确、后缀随机的假凭据（不可用，只测「格式能不能被识别」）
SYNTHETIC: tuple[tuple[str, str], ...] = (
    ("aws_access_key", "AKIAIOSFODNN7EXAMPLE"),
    ("aws_session_key", "ASIAY34FZKBOKMUTVV7A"),
    ("anthropic_key", "sk-ant-api03-Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2RlZmdoamts"),
    ("openai_key", "sk-proj-T0pmaDEyMzQ1Njc4OTBhYmNkZWZnaGlqa2xtbm9wcXJz"),
    ("openai_legacy_key", "sk-abcdefghijklmnopqrstuvwxyz0123456789ABCD"),
    ("google_api_key", "AIzaSyD-1234567890abcdefghijklmnopqrstu"),
    ("slack_token", "xoxb-123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx"),
    ("slack_app_token", "xapp-1-A012345678-1234567890123-abcdef"),
    ("github_pat", "ghp_1234567890abcdefghijklmnopqrstuvwxyzAB"),
    ("github_oauth", "gho_abcdefghijklmnopqrstuvwxyz0123456789"),
    ("gitlab_pat", "glpat-ABCdef1234567890abcdef12"),
    ("jwt", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
            ".eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
    ("rsa_private_key", "-----BEGIN RSA PRIVATE KEY-----\nMIIEow...\n-----END RSA PRIVATE KEY-----"),
    ("openssh_private_key", "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNza\n-----END OPENSSH PRIVATE KEY-----"),
    ("pgp_private_key", "-----BEGIN PGP PRIVATE KEY BLOCK-----\nlQOYBF\n-----END PGP PRIVATE KEY BLOCK-----"),
    ("bearer_header", "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9abcdefghijklmnop"),
)

BENIGN_JSONL = (
    ROOT / "data" / "pint_shape_full.jsonl",
    ROOT / "data" / "agent_bench.jsonl",
    ROOT / "data" / "public_deepset.jsonl",
    ROOT / "data" / "public_garak.jsonl",
)


def benign_texts() -> list[tuple[str, str, str]]:
    """良性语料：数据集里的正常样本 + 本仓库自己的源文件与规则定义。

    返回 (来源, 文本, 组)：组为 `corpus`（真实语料）或 `repo`（仓库文件）。
    **两组必须分开报**：仓库里的测试夹具与文档示例按设计就写着凭据形状的串
    （`test_output_secrets.py` 里躺着 AWS/Slack/JWT 样例，README 里贴着 `AKIA…`），
    扫到它们不是误报而是检测成立。把两组混在一起算一个「误报率」，
    得到的数字既不是语料误报率、也不是检测召回，只是自指。

    另外排除两处，否则数字被自己污染：
    - `.workbuddy/`（助理的临时草稿目录，不是仓库代码）
    - 本文件自己（它的合成凭据就是检测目标）
    """
    out: list[tuple[str, str, str]] = []
    for path in BENIGN_JSONL:
        if not path.exists():
            continue
        for line in io.open(path, encoding="utf-8"):
            if not line.strip():
                continue
            row = json.loads(line)
            if row.get("label"):
                continue
            out.append((path.name, row["text"], "corpus"))
    for path in sorted(ROOT.glob("**/*.py")) + sorted(ROOT.glob("prompt_ids/rules/*.yaml")) + \
            [ROOT / "README.md", ROOT / "AGENTS.md", ROOT / ".env.example"]:
        if not path.exists() or "__pycache__" in path.parts:
            continue
        if ".workbuddy" in path.parts or path.resolve() == Path(__file__).resolve():
            continue
        out.append((path.name, io.open(path, encoding="utf-8", errors="replace").read(), "repo"))
    return out


def self_detection() -> dict:
    """扫描自己的 fixture 文件：这里命中不是误报，是召回的旁证。"""
    here = io.open(Path(__file__), encoding="utf-8").read()
    hits = scan_secrets(here)
    return {"file": Path(__file__).name, "hits": len(hits),
            "kinds": sorted({h.kind for h in hits})}


def main() -> int:
    report: dict = {"synthetic": {}, "benign": {}}

    missed: list[dict] = []
    for kind, text in SYNTHETIC:
        if not scan_secrets(text):
            missed.append({"expect": kind, "text": text[:40]})
    report["synthetic"] = {
        "n": len(SYNTHETIC),
        "caught": len(SYNTHETIC) - len(missed),
        "missed": missed,
    }
    print(f"合成凭据召回：{len(SYNTHETIC) - len(missed)}/{len(SYNTHETIC)}")
    for m in missed:
        print(f"  未抓到 {m['expect']}: {m['text']!r}")

    by_source: dict[str, dict] = {}
    flagged: list[dict] = []
    groups: dict[str, dict] = {}
    total = 0
    for source, text, group in benign_texts():
        total += 1
        slot_g = groups.setdefault(group, {"n": 0, "flagged": 0})
        slot_g["n"] += 1
        hits = scan_secrets(text)
        if not hits:
            continue
        slot_g["flagged"] += 1
        slot = by_source.setdefault(source, {"n": 0, "fp": 0, "group": group, "kinds": {}})
        slot["n"] += 1
        slot["fp"] += 1
        for k, c in summary(hits).items():
            slot["kinds"][k] = slot["kinds"].get(k, 0) + c
        flagged.append({"source": source, "group": group,
                        "kinds": sorted({h.kind for h in hits}),
                        "masked": [h.masked() for h in hits][:3]})
    corpus = groups.get("corpus", {"n": 0, "flagged": 0})
    repo = groups.get("repo", {"n": 0, "flagged": 0})
    report["benign"] = {"n": total, "groups": groups, "flagged": flagged, "by_source": by_source}
    print(f"\n真实语料（PINT/deepset/garak/agent 面良性样本）：{corpus['n']} 条，"
          f"命中 {corpus['flagged']} 条  ← 这才是可引用的误报率")
    print(f"仓库文件（源码/规则/文档/测试夹具）：{repo['n']} 个，命中 {repo['flagged']} 个")
    for source, slot in sorted(by_source.items(), key=lambda kv: -kv[1]["fp"]):
        print(f"  [{slot['group']}] {source:<28} {slot['kinds']}")
    for f in flagged[:12]:
        print(f"    [{f['group']}] {f['source']} {f['kinds']} {f['masked']}")
    print("\n注：仓库文件里的命中按设计就含凭据形状（测试夹具与 README 示例），"
          "属检测成立而非误报；别把它算进语料误报率。")
    self_hit = self_detection()
    report["self_detection"] = self_hit
    print(f"自检（扫本脚本的合成凭据，命中 {self_hit['hits']} 处）：{self_hit['kinds']}")

    out = ROOT / "reports" / "output_scan.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    io.open(out, "w", encoding="utf-8").write(
        json.dumps(report, ensure_ascii=False, indent=2))
    print(f"\nJSON 已保存 -> {out}")
    return 1 if missed else 0


if __name__ == "__main__":
    raise SystemExit(main())
