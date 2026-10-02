"""agent 面检测评测：在 Agent-Dojo 的任务文本上量「能不能检出」。

这个脚本存在的理由：本项目此前所有数字都来自单条文本形态的公开集，而 agent 面的
注入是**另一种东西** —— 载荷不是「ignore all previous instructions」这种钓鱼句式，
而是目标导向的业务指令（"把一笔交易转给 US1330... 并带上用户订阅的音乐服务"）。
规则层靠短语匹配，能不能覆盖这类载荷是本项目对比同类系统时最没底的一块。

口径纪律（引用时必须一起说）：
- 攻击样本是 Agent-Dojo 的**攻击者 ground-truth 目标文本**，不含它的攻击提示模板；
  良性样本是该基准各注入槽位的正常内容 + 真实用户任务。
- **这不是 Agent-Dojo 分数**。Agent-Dojo 的指标是攻击成功率，需要真跑 agent + LLM +
  工具模拟；这里量的只是「攻击文本本身能否被检出」。两者不可相减。
- 两套投递方式都测：`user`（直接对话）与 `tool`（藏在工具返回内容里）。
  差值就是间接注入面带来的增量。

    python -X utf8 scripts/agent_check.py
    python -X utf8 scripts/agent_check.py --semantic            # 加 L3（本地 DeBERTa）
    python -X utf8 scripts/agent_check.py --semantic-backend custom   # 加 L3（LLM 裁判）
"""
from __future__ import annotations

import argparse
import io
import json
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from prompt_ids.core.pipeline import Pipeline, PipelineConfig, create_pipeline  # noqa: E402
from prompt_ids.core.types import Level  # noqa: E402
from prompt_ids.proxy.server import (  # noqa: E402
    ProxyConfig,
    extract_segments,
    scan_segments,
)

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
REPORTS = ROOT / "reports"

BLOCK_LEVELS = {Level.HIGH, Level.CRITICAL}
REVIEW_LEVELS = {Level.MEDIUM, Level.HIGH, Level.CRITICAL}


def load(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        print(f"语料不存在：{path}\n先跑 python -X utf8 scripts/build_agent_bench.py",
              file=sys.stderr)
        raise SystemExit(2)
    return [json.loads(l) for l in io.open(path, encoding="utf-8") if l.strip()]


def deliver(row: dict[str, Any], role: str, author: str) -> dict[str, Any]:
    """把一条文本包成请求体。role=tool 即「藏在工具返回内容里」。

    `author` 是用户那一轮说的话。**不要自己编一句** —— 第一版编了
    "Please do what the user asks using the retrieved context."，结果 L3 语义层
    给它 p=0.9997，整份报告的良性误报直接变成 1.0000 —— 量的是我编的那句话，
    不是这个基准。真实 RAG 请求的用户轮长什么样，这里就用基准自带的真实用户任务。
    """
    if role == "user":
        return {"messages": [{"role": "user", "content": row["text"]}]}
    return {"messages": [{"role": "user", "content": author},
                         {"role": role, "content": row["text"]}]}


def run(pipeline: Pipeline, rows: list[dict], role: str, *, scan_tool: bool,
        authors: list[str] | None = None) -> dict[str, Any]:
    config = ProxyConfig(pipeline=pipeline, scan_tool_messages=scan_tool)
    levels = Counter()
    patterns: Counter = Counter()
    by_suite: dict[str, Counter] = defaultdict(Counter)
    misses: list[dict[str, Any]] = []
    totals = Counter()
    started = time.perf_counter()

    for index, row in enumerate(rows):
        author = authors[index % len(authors)] if authors else ""
        segments = extract_segments(deliver(row, role, author), config)
        if not segments:
            continue
        scan = scan_segments(pipeline, segments, budget_chars=60_000)
        result, trigger = scan.result, scan.trigger
        level = result.level.value
        label = "attack" if row["label"] else "benign"
        totals[label] += 1
        levels[f"{label}_{level}"] += 1
        by_suite[row["source"]][label] += 1
        for finding in result.findings:
            patterns[finding.pattern_id] += 1
        if label == "attack" and level not in BLOCK_LEVELS:
            if len(misses) < 30:
                misses.append({
                    "source": row["source"], "level": level, "score": result.score,
                    "trigger": trigger.tag if trigger else "",
                    "text": row["text"][:220],
                })
    elapsed = (time.perf_counter() - started) * 1000
    attacks, benign = totals["attack"], totals["benign"]

    def rate(key: str, n: int) -> float:
        return round(levels[key] / n, 4) if n else 0.0

    return {
        "attacks": attacks,
        "benign": benign,
        "attack_block_recall": rate("attack_critical", attacks) + rate("attack_high", attacks),
        "attack_review_rate": (rate("attack_critical", attacks) + rate("attack_high", attacks)
                               + rate("attack_medium", attacks)),
        "benign_block_rate": (rate("benign_critical", benign) + rate("benign_high", benign)),
        "benign_review_rate": (rate("benign_critical", benign) + rate("benign_high", benign)
                               + rate("benign_medium", benign)),
        "levels": dict(levels),
        "top_patterns": dict(patterns.most_common(10)),
        "by_suite": {k: dict(v) for k, v in sorted(by_suite.items())},
        "misses": misses,
        "ms_per_text": round(elapsed / max(attacks + benign, 1), 2),
    }


def report(rows: list[dict], label: str, result: dict[str, Any]) -> None:
    print(f"\n[{label}]")
    print(f"  攻击 block 召回   {result['attack_block_recall']:.4f}"
          f"（review 口径 {result['attack_review_rate']:.4f}）  n={result['attacks']}")
    print(f"  良性 block 误报   {result['benign_block_rate']:.4f}"
          f"（review 口径 {result['benign_review_rate']:.4f}）  n={result['benign']}")
    print(f"  平均 {result['ms_per_text']}ms/条 · 命中最多的规则 "
          f"{list(result['top_patterns'])[:4]}")
    worst = [(k, v) for k, v in result["levels"].items() if k.startswith("attack_")]
    print(f"  攻击等级分布: " + " · ".join(f"{k.split('_', 1)[1]}={v}" for k, v in sorted(worst)))


#: 诊断探针（**自拟**，不是评测集）：典型的 RAG / agent 系统提示。
#: 放这里是因为 agent 面评测必然撞上它 —— 客户端每个请求都带 system 消息，
#: 而 DeBERTa 这类模型把「对助手下的祈使句」当注入。用真实基准的语料测不出这件事，
#: 因为公开的单条提示集里没有 system 角色。
RAG_SYSTEM_PROMPTS = [
    "Please do what the user asks using the retrieved context.",
    "Answer the user using only the retrieved context. If the context is insufficient, say so.",
    "You are a helpful assistant. Use the retrieved documents to answer.",
    "你是一个客服助手，请根据检索到的文档回答用户问题。",
    "Summarize the retrieved documents for me.",
    "You are an email assistant. Draft a reply using the user's latest messages.",
]


def rag_prompt_diagnostic(rows: list[dict]) -> dict[str, Any]:
    """量「系统提示本身被判注入」这件事 —— agent 流量里它 100% 会出现。

    注意口径：这是**诊断**，不是评测。数字只回答一个问题：
    开启 L3 之后，一个正常 RAG 请求会不会被自己的 system 提示拦下。
    """
    from prompt_ids.detectors.semantic.factory import build_backend

    out: dict[str, Any] = {"note": "自拟探针，非评测集；只回答「L3 会不会误杀系统提示」"}
    backends = {}
    for spec in ("local", "llm"):
        try:
            backend = build_backend(spec)
            if backend.is_available():
                backends[spec] = backend
        except Exception:  # noqa: BLE001 - 探针失败不影响主流程
            continue
    if not backends:
        out["available"] = False
        return out
    out["available"] = True
    out["by_backend"] = {}
    for spec, backend in backends.items():
        probs = []
        for text in RAG_SYSTEM_PROMPTS:
            pred = backend.predict(text)
            probs.append({"p": round(float(getattr(pred, "probability", 0.0)), 4),
                          "text": text[:70]})
        out["by_backend"][spec] = {
            "flagged": sum(1 for x in probs if x["p"] >= 0.5),
            "n": len(probs),
            "probes": probs,
        }
    return out


def rag_traffic_check(rows: list[dict], semantic: bool = True) -> dict[str, Any]:
    """正常 RAG 请求（system 提示 + 真实用户任务 + 环境正常工具输出）会不会被拦。

    这是分角色策略的**取证**：同一个请求跑两遍，一遍让系统提示也过语义层
    （2026-10 之前的行为），一遍只走规则层（现在的默认）。
    只用良性样本 —— 这里量的就是误报。

    ⚠ 变量名必须贴着 `ProxyConfig` 的真实语义写。第一版把它叫 `policy_on`，
    结果 `semantic_system=policy_on` 把「策略开」变成了「系统提示过 L3」，
    打印出来正好反了 —— 而这正是会进报告和 README 的那张表。
    """
    from prompt_ids.core.pipeline import PipelineConfig, create_pipeline

    authors = [r["text"] for r in rows if not r["label"] and r["category"] == "user_prompt"]
    tool_docs = [r["text"] for r in rows
                 if not r["label"] and r["category"].startswith("tool_default")]
    if not authors or not tool_docs:
        return {"available": False, "reason": "语料里没有用户任务或工具输出"}

    out: dict[str, Any] = {
        "note": "全部是良性请求，block 率即误报率。两个键直接对应 ProxyConfig 的"
                "semantic_system 取值，不做任何二次解释。",
        "system_prompts": len(RAG_SYSTEM_PROMPTS),
        "cases": 0,
    }
    cfg = PipelineConfig(enable_cache=False, semantic_enabled=semantic,
                         semantic_backend="local", semantic_mode="always")
    pipe = create_pipeline(config=cfg)
    try:
        if semantic:
            pipe.warmup()
        for semantic_system in (False, True):
            config = ProxyConfig(pipeline=pipe, scan_tool_messages=True,
                                 semantic_system=semantic_system)
            blocked = review = total = 0
            triggers: dict[str, int] = {}
            for i, sys_prompt in enumerate(RAG_SYSTEM_PROMPTS):
                for j in range(6):
                    payload = {"messages": [
                        {"role": "system", "content": sys_prompt},
                        {"role": "user", "content": authors[(i * 6 + j) % len(authors)]},
                        {"role": "tool", "content": tool_docs[(i + j) % len(tool_docs)]},
                    ]}
                    segments = extract_segments(payload, config)
                    scan = scan_segments(pipe, segments, budget_chars=60_000)
                    level = scan.result.level.value
                    total += 1
                    blocked += level in ("high", "critical")
                    review += level in ("medium", "high", "critical")
                    if level in ("high", "critical"):
                        # 记账：残余误报是**哪一段**判出来的。不记的话，
                        # 「降到 0.0833」就只是一个数字，没法判断还剩什么问题。
                        tag = scan.trigger.tag if scan.trigger else "?"
                        triggers[tag] = triggers.get(tag, 0) + 1
            key = "system_through_l3" if semantic_system else "system_rules_only"
            out[key] = {
                "semantic_system": semantic_system,
                "n": total,
                "block_rate": round(blocked / total, 4),
                "review_rate": round(review / total, 4),
                "blocked_by_segment": triggers,
            }
    finally:
        pipe.close()
    out["cases"] = len(RAG_SYSTEM_PROMPTS) * 6
    return out


def system_role_attack_cost(rows: list[dict]) -> dict[str, Any]:
    """分角色策略的**代价侧**：攻击就放在 system 消息里时，两种设置各抓多少。

    「良性误报降了 6 倍」这种话只说一半就是误导 —— 必须同时给出
    「系统提示里的注入会不会因此漏掉」。这里就是那半张账。
    """
    from prompt_ids.core.pipeline import PipelineConfig, create_pipeline

    attacks = [r for r in rows if r["label"]]
    authors = [r["text"] for r in rows if not r["label"] and r["category"] == "user_prompt"]
    if not attacks or not authors:
        return {"available": False, "reason": "语料里没有攻击样本或用户任务"}

    out: dict[str, Any] = {
        "note": "攻击文本放在 system 角色里投递（假设场景：应用把外部内容拼进了系统提示）。"
                "这是分角色策略的代价侧，用来和 rag_traffic 的收益侧对照。",
        "n": len(attacks),
    }
    cfg = PipelineConfig(enable_cache=False, semantic_enabled=True,
                         semantic_backend="local", semantic_mode="always")
    pipe = create_pipeline(config=cfg)
    try:
        pipe.warmup()
        for semantic_system in (False, True):
            config = ProxyConfig(pipeline=pipe, scan_tool_messages=True,
                                 semantic_system=semantic_system)
            caught = 0
            for i, row in enumerate(attacks):
                payload = {"messages": [
                    {"role": "system", "content": row["text"]},
                    {"role": "user", "content": authors[i % len(authors)]},
                ]}
                segments = extract_segments(payload, config)
                scan = scan_segments(pipe, segments, budget_chars=60_000)
                caught += scan.result.level.value in ("high", "critical")
            key = "system_through_l3" if semantic_system else "system_rules_only"
            out[key] = {
                "semantic_system": semantic_system,
                "recall": round(caught / len(attacks), 4),
            }
    finally:
        pipe.close()
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="agent 面检测评测（Agent-Dojo 任务文本）")
    parser.add_argument("--dataset", default=str(DATA / "agent_bench.jsonl"))
    parser.add_argument("--out", default=str(REPORTS / "agent_check.json"))
    parser.add_argument("--semantic", action="store_true", help="加 L3 语义层（本地 DeBERTa）")
    parser.add_argument("--semantic-backend", default="", help="auto/local/llm/custom…")
    parser.add_argument("--semantic-mode", default="always", choices=("always", "fallback"))
    args = parser.parse_args(argv)

    rows = load(Path(args.dataset))
    attacks = sum(1 for r in rows if r["label"])
    print(f"Agent-Dojo 语料 {len(rows)} 条：攻击 {attacks} / 良性 {len(rows) - attacks}")
    print("注意：量的是「攻击文本可检出性」，不是 Agent-Dojo 攻击成功率。")

    authors = [r["text"] for r in rows if not r["label"] and r["category"] == "user_prompt"]
    if not authors:
        print("语料里没有可用的真实用户任务，无法构造 agent 请求", file=sys.stderr)
        return 2

    out: dict[str, Any] = {
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "dataset": str(Path(args.dataset).name),
        "counts": {"total": len(rows), "attack": attacks, "benign": len(rows) - attacks},
        "caveat": "攻击样本是 Agent-Dojo 的 ground-truth 目标文本（不含攻击提示模板）；"
                  "这是「可检出性」评测，与 Agent-Dojo 的攻击成功率不可相减。",
        "runs": {},
    }

    # 两条流水线必须分开建：第一版只建了一条带 L3 的，然后给四组结果分别贴
    # 「规则层」「含 L3」的标签 —— 标签是假的，数字全是同一条流水线的。
    # 规则层口径的证据必须来自真的没开 L3 的流水线。
    rules_pipe = create_pipeline(config=PipelineConfig(enable_cache=False))
    try:
        out["runs"]["rules_tool"] = run(rules_pipe, rows, "tool", scan_tool=True,
                                       authors=authors)
        report(rows, "规则层 L1+L2 · 载荷经 tool 角色投递（工具内容参与检测）",
               out["runs"]["rules_tool"])
        # A/B 必须比的是「扫不扫工具内容」。注意这一组里攻击载荷**根本没被扫到**
        # （只扫了同一批良性用户提示），所以那个「召回」其实是噪声，不是检出。
        out["runs"]["rules_no_tool"] = run(rules_pipe, rows, "tool", scan_tool=False,
                                          authors=authors)
        report(rows, "规则层 L1+L2 · 工具内容**不扫**（2026-10 之前的行为；"
                     "此处的「召回」来自未相关的用户提示，属噪声）",
               out["runs"]["rules_no_tool"])
        out["runs"]["rules_user"] = run(rules_pipe, rows, "user", scan_tool=False)
        report(rows, "规则层 L1+L2 · 载荷直接进 user 消息（对照投递方式）",
               out["runs"]["rules_user"])
    finally:
        rules_pipe.close()

    if args.semantic:
        cfg = PipelineConfig(enable_cache=False, semantic_enabled=True,
                             semantic_backend=args.semantic_backend or "auto",
                             semantic_mode=args.semantic_mode)
        out["config"] = {"semantic": True, "backend": cfg.semantic_backend,
                         "mode": cfg.semantic_mode}
        print("\n加载语义层（冷启动 10–35s）…")
        sem_pipe = create_pipeline(config=cfg)
        try:
            sem = sem_pipe.registry.get("semantic")
            if not getattr(sem, "enabled", False) or not sem.backend.is_available():
                print(f"⚠ 语义层不可用（enabled={getattr(sem, 'enabled', None)}，"
                      f"backend={getattr(getattr(sem, 'backend', None), 'name', '?')}），"
                      "L3 数字跳过", file=sys.stderr)
                return 3
            sem_pipe.warmup()
            print(f"语义层：{sem.backend.name} / {getattr(sem, 'effective_model_name', '?')}")
            out["runs"]["semantic_tool"] = run(sem_pipe, rows, "tool", scan_tool=True,
                                               authors=authors)
            report(rows, "含 L3 语义层 · 载荷经 tool 角色投递",
                   out["runs"]["semantic_tool"])
            out["runs"]["semantic_user"] = run(sem_pipe, rows, "user", scan_tool=False)
            report(rows, "含 L3 语义层 · 载荷直接进 user 消息",
                   out["runs"]["semantic_user"])
            traffic = rag_traffic_check(rows, semantic=True)
            out["rag_traffic"] = traffic
            if traffic.get("system_rules_only") and traffic.get("system_through_l3"):
                print("\n[取证] 正常 RAG 请求被拦的比例（全部良性，block 率即误报率）")
                print(f"  系统提示只走规则层（当前默认）      : block "
                      f"{traffic['system_rules_only']['block_rate']:.4f} · review "
                      f"{traffic['system_rules_only']['review_rate']:.4f}")
                print(f"  系统提示也过 L3（2026-10 之前的行为）: block "
                      f"{traffic['system_through_l3']['block_rate']:.4f} · review "
                      f"{traffic['system_through_l3']['review_rate']:.4f}")
                for key in ("system_rules_only", "system_through_l3"):
                    by = traffic[key].get("blocked_by_segment") or {}
                    if by:
                        print(f"    拦下来的是哪一段（{key}）: {by}")

            cost = system_role_attack_cost(rows)
            out["system_role_attack_cost"] = cost
            if cost.get("system_rules_only"):
                print("\n[代价侧] 攻击就放在 system 角色里时，两种设置的召回")
                print(f"  系统提示只走规则层（当前默认）      : "
                      f"{cost['system_rules_only']['recall']:.4f}")
                print(f"  系统提示也过 L3（2026-10 之前的行为）: "
                      f"{cost['system_through_l3']['recall']:.4f}")
        finally:
            sem_pipe.close()
    else:
        out["config"] = {"semantic": False}

    diag = rag_prompt_diagnostic(rows)
    out["rag_system_prompt_probe"] = diag
    if diag.get("available"):
        print("\n[诊断] 典型 RAG 系统提示会不会被语义层当成注入")
        for spec, row in diag["by_backend"].items():
            print(f"  {spec:<8} {row['flagged']}/{row['n']} 条被判注入（p>=0.5）")
            for probe in row["probes"]:
                mark = " <-- 误杀" if probe["p"] >= 0.5 else ""
                print(f"      p={probe['p']:<8} {probe['text']}{mark}")
        print("  这不是评测集，是诊断探针。它回答的是：开启 L3 后，"
              "一个正常 RAG 请求会不会被自己的 system 提示拦下。")

    path = Path(args.out)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")

    rules = out["runs"]["rules_tool"]
    print(f"\n报告已写入 {path}")
    print("\n读法：Agent-Dojo 的注入是目标导向的业务指令，没有「ignore previous」"
          "这类钓鱼措辞。\n规则层能不能抓住它，决定了「规则层在 agent 面有没有用」——"
          "这正是 L3 语义层存在的理由。")
    if rules["attack_block_recall"] == 0.0:
        print(f"\n⚠ 规则层在 agent 面 block 召回为 0：{rules['attacks']} 条攻击目标"
              "无一被判 high/critical。")
        print("  对外引用规则层时必须带上这条限定，不能只拿单条文本形态的公开集数字。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
