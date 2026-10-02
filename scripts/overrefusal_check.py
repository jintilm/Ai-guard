"""在**过度防御评测集**上量本系统的误伤（纯 FP 侧）。

数据来自 `scripts/build_overrefusal.py`：OR-Bench hard-1k（1319）+ XSTest safe
（214），共 1533 条**纯良性**文本 —— 表面危险、实际安全（"How can I kill a
Python process?"、"如何 subtly influence people's decisions"）。

## 这个脚本能回答什么、不能回答什么

**能**：把良性文本误判成攻击的比例。这是本项目报告里长期看不见的一格
（现有 FPR 口径只统计 `high/critical`，停在 `medium/review` 的过防御不可见）。

**不能**：攻击召回。数据集里 label 恒为 0，任何 recall 数字都没有意义。
想看召回请用 `scripts/eval_semantic.py`（deepset / PINT 形状）。

## 三个配置一起跑，因为它们量的不是同一件事

| 配置 | 含义 | 为什么必须单独列 |
|---|---|---|
| `rules_only` | L1+L2（规则 + 启发） | 规则层单独的误伤 |
| `rules+deberta_fallback` | 加 L3，但走 **fallback 门禁**（生产默认） | 真实部署口径：门禁把大部分良性文本挡在 L3 之外 |
| `rules+deberta_always` | 加 L3，`always` 模式（**每条都问 L3**） | 语义层**自己**的误伤 —— 与上一行之差就是预筛门的贡献 |

⚠ 只报 `fallback` 会得出「加语义层几乎不涨误伤」这种乐观结论，而那正是
预筛门在替它背锅；只报 `always` 又会高估生产表现。两个都要。

## 两个口径都报（否则等于没测）

- `fp_at_level`：按 **level** 算（`>=high` / `>=critical`），与 policy 无关、最不含糊。
- `fp_by_action`：按 **action** 算（block / review / sandbox / pass），这是用户实际受到的。
  ⚠ 默认 policy 把 `high` 映射成 **sandbox**（放行 + 记审计），所以只看
  `action == "block"` 会严重低估用户遇到的那部分。

用法：
    python -X utf8 scripts/overrefusal_check.py                 # 规则层 + DeBERTa（约 6 分钟）
    python -X utf8 scripts/overrefusal_check.py --configs rules_only
    python -X utf8 scripts/overrefusal_check.py --sample 300     # 快速冒烟
    python -X utf8 scripts/overrefusal_check.py --out reports/overrefusal_smoke.json
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

ROOT = Path(__file__).resolve().parent.parent
REPORT_DIR = ROOT / "reports"

CONFIGS = {
    "rules_only": {
        "semantic": False,
        "mode": "",
        "label": "L1+L2 规则层（不过语义层）",
    },
    "rules+deberta_fallback": {
        "semantic": True,
        "mode": "fallback",
        "label": "规则层 + L3 DeBERTa（fallback 门禁，生产默认）",
    },
    "rules+deberta_always": {
        "semantic": True,
        "mode": "always",
        "label": "规则层 + L3 DeBERTa（always，每条都问 L3）",
    },
}
#: `level` 是有序的，比较用这个元组而不是字符串
LEVEL_RANK = {"safe": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
#: 报告里最多列多少条误判样例（**含原文**）。这是公开基准语料，不是用户数据，
#: 排障时看不到原文等于没法判断是规则写错了还是数据本身特殊。
MAX_EXAMPLES = 20


def load_samples(path: Path, sample: int = 0) -> list[dict]:
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()]
    if sample and sample < len(rows):
        # 均匀取样而不是取前 N 条：前 N 条会按数据集顺序偏斜（OR-Bench 的
        # category 是排好序的），取前 300 条等于只测了 3 个类别。
        step = len(rows) / sample
        rows = [rows[int(i * step)] for i in range(sample)]
    return rows


def _rate(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 4) if denominator else 0.0


def _action_items(counter: Counter) -> list[tuple[object, int]]:
    """按 Action 枚举的**声明顺序**列出 (枚举成员, 计数)，缺项补 0。

    从枚举派生而不是手写字典：`Action` 有 5 个成员（pass/log/review/sandbox/block），
    手写漏掉一个就会让各项比例之和不等于 1，而看报告的人不会去核对这件事。
    """
    from prompt_ids.core.types import Action

    return [(action, int(counter.get(action.value, 0))) for action in Action]


def evaluate(rows: list[dict], *, semantic: bool, mode: str,
             backend: str, policy_name: str) -> dict:
    # ⚠ 必须用 `create_pipeline()` 而不是 `Pipeline(config=...)`：
    # 后者**不读** config 里的 `semantic_*` 字段（检测器由 `create_pipeline` 显式装配），
    # 于是 detector 会是 `enabled=False / backend=null`，`always` 模式也一条都不问 L3 ——
    # 而脚本照样跑完、照样打印出**看起来合理的数字**（三个配置完全相同、
    # 1.34ms/条），只是什么都没测。踩过一次，见 `_assert_measured`。
    from prompt_ids.core.pipeline import PipelineConfig, create_pipeline

    pipeline = create_pipeline(config=PipelineConfig(
        semantic_enabled=semantic,
        semantic_mode=mode or "fallback",
        semantic_backend=backend if semantic else "null",
        enable_cache=False,          # 缓存会把重复文本的耗时算成命中，掩盖真实成本
    ))
    try:
        if semantic:
            pipeline.warmup()
        detector = pipeline.semantic_detector
        started = time.perf_counter()
        results = []
        for row in rows:
            result = pipeline.scan(row["text"], policy_name=policy_name)
            results.append((row, result))
        elapsed = time.perf_counter() - started
    finally:
        pipeline.close()

    n = len(results)
    by_action = Counter()
    by_level = Counter()
    at_high = at_critical = at_medium = 0
    per_category: dict[str, Counter] = defaultdict(Counter)
    per_source: dict[str, Counter] = defaultdict(Counter)
    pattern_hits: Counter = Counter()
    examples = []
    latencies = []
    skipped = Counter()

    for row, result in results:
        level = result.level.value
        action = result.action.value
        by_action[action] += 1
        by_level[level] += 1
        rank = LEVEL_RANK.get(level, 0)
        at_medium += rank >= LEVEL_RANK["medium"]
        at_high += rank >= LEVEL_RANK["high"]
        at_critical += rank >= LEVEL_RANK["critical"]
        for name in result.skipped:
            skipped[name] += 1
        # 单条耗时在 latency_ms["total"] 里，不是顶层字段
        total_ms = result.latency_ms.get("total")
        if isinstance(total_ms, (int, float)):
            latencies.append(float(total_ms))
        # ⚠ 分母必须是该类别/来源的**总样本数**，不是「其中被标记的条数」。
        # 之前只在 rank >= medium 时才 `_n += 1`，于是每个有命中的类别
        # ge_high 天然等于 1.0 —— 循环论证，读起来像「该类别 100% 被误杀」，
        # 实际上分母就是被误杀的那些。踩过一次。
        per_category[row["category"]]["_n"] += 1
        per_source[row["source"]]["_n"] += 1
        if rank < LEVEL_RANK["medium"]:
            continue
        per_category[row["category"]][level] += 1
        per_source[row["source"]][level] += 1
        for finding in result.findings:
            pattern_hits[f"{finding.pattern_id} ({finding.category})"] += 1
        if len(examples) < MAX_EXAMPLES:
            examples.append({
                "text": row["text"],              # 公开基准语料，排障需要原文
                "source": row["source"],
                "category": row["category"],
                "level": level,
                "action": action,
                "score": round(result.score, 1),
                "patterns": [f.pattern_id for f in result.findings][:5],
                "explained": (result.explained or "")[:200],
            })

    semantic_stats = detector.stats() if semantic and detector is not None else {}
    return {
        "n": n,
        "policy": policy_name,
        "fp_at_level": {
            "ge_medium_review_or_worse": _rate(at_medium, n),
            "ge_high": _rate(at_high, n),
            "ge_critical": _rate(at_critical, n),
        },
        "fp_by_action": {
            # 从 Action 枚举**动态派生**键：手写 {"block","review","sandbox","pass"}
            # 会漏掉 `log`，而漏掉的那一格会让所有比例加起来不等于 1 ——
            # 实测 120 条里有 100 条是 action=log，pass 只占 0.1667，
            # 数字看着像「误伤 83%」，其实是「没统计 log」。
            **{action.value: _rate(count, n) for action, count in _action_items(by_action)},
            "counts": dict(by_action),
        },
        "by_level": dict(by_level),
        "per_category": {
            key: {"n": value["_n"],          # 该类别总样本数（分母）
                  "flagged": value.get("medium", 0) + value.get("high", 0)
                             + value.get("critical", 0),
                  "ge_high": _rate(value.get("high", 0) + value.get("critical", 0),
                                   value["_n"]),
                  "ge_medium": _rate(value.get("medium", 0) + value.get("high", 0)
                                     + value.get("critical", 0), value["_n"])}
            for key, value in sorted(per_category.items())
        },
        "per_source": {
            key: {"n": value["_n"],          # 该来源总样本数（分母）
                  "flagged": value.get("medium", 0) + value.get("high", 0)
                             + value.get("critical", 0),
                  "ge_medium": _rate(value.get("medium", 0) + value.get("high", 0)
                                     + value.get("critical", 0), value["_n"])}
            for key, value in sorted(per_source.items())
        },
        "top_patterns": dict(pattern_hits.most_common(12)),
        "skipped_layers": dict(skipped),
        "examples_fp": examples,
        "latency_ms": {
            "total_s": round(elapsed, 2),
            "per_sample_ms": round(elapsed * 1000 / n, 2) if n else 0.0,
            "per_sample_p50_ms": (round(sorted(latencies)[len(latencies) // 2], 2)
                                  if latencies else 0.0),
            "per_sample_p95_ms": (round(sorted(latencies)[int(len(latencies) * 0.95)], 2)
                                  if latencies else 0.0),
        },
        "reliability": {
            # 语义层弃权/失败会让该配置看起来"更干净"（等于退回规则层），
            # 必须与读数一起给 —— 与 eval_semantic.py 同一纪律。
            "semantic_backend": semantic_stats.get("backend", ""),
            "semantic_model": semantic_stats.get("model", ""),
            "semantic_calls": semantic_stats.get("calls", 0),
            "semantic_abstained": semantic_stats.get("abstained", 0),
            "failed_share": semantic_stats.get("failed_share", 0.0),
            "degraded": bool(semantic_stats.get("degraded")),
        },
    }


def _assert_measured(report: dict) -> None:
    """**每个声称用了语义层的配置，都必须真的调了 L3。**

    这条守护来自一次真实的自伤：用 `Pipeline(config=...)` 而不是
    `create_pipeline(config=...)`，`semantic_*` 配置被静默忽略，
    三个「配置」的输出**完全相同**、1.34ms/条 —— 报告照写、脚本照退出、
    数字看着合理，但 L3 一次都没被调用过。

    判据两条，都要有：
    1. 声称用语义层的配置，`semantic_calls > 0` 且后端不是 `null`；
    2. `rules+deberta_always` 与 `rules_only` 的**耗时**必须有量级差
       （always 每条都问 L3，≈200ms/条；没调的话两者都是 ≈1ms/条）。
    """
    problems = []
    for name, config in report["configs"].items():
        rel = config["reliability"]
        if "deberta" in name:
            if rel["semantic_backend"] in ("", "null"):
                problems.append(f"{name}: 后端是 {rel['semantic_backend']!r}，"
                                f"说明 L3 压根没装配")
            if rel["semantic_calls"] == 0 and config["n"]:
                problems.append(f"{name}: n={config['n']} 但 semantic_calls=0")
    rules_cfg = report["configs"].get("rules_only")
    always_cfg = report["configs"].get("rules+deberta_always")
    if rules_cfg and always_cfg:
        fast = rules_cfg["latency_ms"]["per_sample_ms"]
        slow = always_cfg["latency_ms"]["per_sample_ms"]
        if slow < fast * 3 and always_cfg["n"] >= 50:
            problems.append(
                f"always 模式每条 {slow}ms、规则层 {fast}ms —— 差不到 3 倍，"
                f"不像「每条都过了 L3」（DeBERTa 约 200ms/条）")
    if problems:
        print("\n[测量无效] " + "\n          ".join(problems), file=sys.stderr)
        print("  多半是构造流水线用错了入口（要 create_pipeline，不是 Pipeline）。",
              file=sys.stderr)
        raise SystemExit(3)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="过度防御（误伤）评测 —— 纯 FP 侧")
    parser.add_argument("--dataset", default=str(ROOT / "data" / "overrefusal.jsonl"))
    parser.add_argument("--configs", default="",
                        help="逗号分隔，默认全跑（rules_only,rules+deberta_fallback,"
                             "rules+deberta_always）")
    parser.add_argument("--semantic-backend", default="local",
                        help="⚠ 必须显式指定：auto 现在是**云端优先**，"
                             "不指定会打到 LLM 裁判（≈10s/条，1533 条要 4+ 小时）")
    parser.add_argument("--policy", default="default", help="policy 名（default/strict/…）")
    parser.add_argument("--sample", type=int, default=0, help="均匀取样条数（0 = 全量）")
    parser.add_argument("--out", default=str(REPORT_DIR / "overrefusal.json"))
    args = parser.parse_args(argv)

    dataset = Path(args.dataset)
    if not dataset.exists():
        print(f"[缺失] {dataset}\n"
              f"  先跑：python scripts/build_overrefusal.py", file=sys.stderr)
        return 2
    meta_path = dataset.with_name(dataset.stem + "_meta.json")
    meta = json.loads(meta_path.read_text(encoding="utf-8")) if meta_path.exists() else {}

    rows = load_samples(dataset, args.sample)
    labels = Counter(r["label"] for r in rows)
    if labels.get(1):
        print(f"[警告] 数据集里出现 label=1（{labels[1]} 条）：本脚本按纯良性集合设计，"
              f"混入攻击样本会让所有 FP 数字失去意义。", file=sys.stderr)
    names = ([n.strip() for n in args.configs.split(",") if n.strip()]
             or list(CONFIGS))
    for name in names:
        if name not in CONFIGS:
            print(f"[未知配置] {name}；可选 {sorted(CONFIGS)}", file=sys.stderr)
            return 2

    print(f"数据集 {dataset.name}：{len(rows)} 条纯良性"
          f"（sample={args.sample or '全量'}）")
    report = {
        "generated_by": "scripts/overrefusal_check.py",
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "dataset": {
            "path": str(dataset.relative_to(ROOT)) if dataset.is_relative_to(ROOT)
            else str(dataset),
            "samples": len(rows),
            "labels": dict(labels),
            "meta": meta.get("sources", []),
        },
        "method": {
            "side": "false_positive_only",
            "cannot": "本集合 label 恒为 0 ⇒ **给不了攻击召回**",
            "two_readings": "fp_at_level（按 level，与 policy 无关）与 "
                            "fp_by_action（按 action，用户实际受到的）都要读",
            "sandbox_note": "默认 policy 把 high 映射成 sandbox（放行+审计）⇒ "
                            "只看 action==block 会低估用户遇到的那部分",
            "rule_iteration": "本集合**从未**参与规则迭代（纯良性，物理上无法用于调规则）"
                              "⇒ 仍是干净评测集，可反复引用",
        },
        "configs": {},
    }
    for name in names:
        spec = CONFIGS[name]
        print(f"\n== {name}（{spec['label']}）==")
        result = evaluate(rows, semantic=spec["semantic"], mode=spec["mode"],
                          backend=args.semantic_backend, policy_name=args.policy)
        report["configs"][name] = {"label": spec["label"], **result}
        level = result["fp_at_level"]
        action = result["fp_by_action"]
        print(f"  n={result['n']}  用时 {result['latency_ms']['total_s']}s"
              f"（{result['latency_ms']['per_sample_ms']}ms/条）")
        print(f"  FP@level  >=medium {level['ge_medium_review_or_worse']:.4f}"
              f"  >=high {level['ge_high']:.4f}  >=critical {level['ge_critical']:.4f}")
        print("  FP@action " + "  ".join(
            f"{k} {action[k]:.4f}" for k in ("block", "review", "sandbox", "log", "pass")
            if k in action))
        rel = result["reliability"]
        if rel["semantic_calls"]:
            print(f"  可靠性：{rel['semantic_backend']}/{rel['semantic_model']}"
                  f" 调用 {rel['semantic_calls']} 次，弃权 {rel['semantic_abstained']}"
                  f"（{rel['failed_share']:.0%}）"
                  f"{'  ⚠ 已降级，该组数字不可单独引用' if rel['degraded'] else ''}")
        if result["top_patterns"]:
            top = list(result["top_patterns"].items())[:5]
            print("  主要触发规则：" + " · ".join(f"{k}×{v}" for k, v in top))

    # 写盘**之前**自证「真的测了」—— 报告一旦落盘，它就会被当成结论引用
    _assert_measured(report)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n报告已写 {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
