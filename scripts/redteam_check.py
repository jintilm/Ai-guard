"""在生成的红队语料上量各形态的召回，并**显式声明这份读数能用来做什么**。

数据来自 `scripts/build_redteam.py`（纯攻击集，label 恒为 1）。

## 这份读数能用来做什么、不能用来做什么

**能**：回答「**哪一类形态我们完全没覆盖**」。规则层对不同形态的召回会差一个
数量级，而这件事在现有公开集上只能间接推断（deepset 没导出攻击类型列，
按类型分层做不了 —— 见 AGENTS.md「实验口径」第 0 条）。

**不能**：
- **给不了系统能力的绝对值。** 生成器只能产出「我们想得到的形态」，
  所以这里的召回既不是上界也不是下界。**必须与公开集并列报，不许单独引用。**
- **可用率必须人工标注。** 生成 N 条不代表 N 条都是「真攻击」。
  没有 `--labels` 时本脚本会写「可用率未标注」，**绝不用模型自己的判定冒充人工标注**。

## 三个配置

与 `overrefusal_check.py` 同一套口径（同一个项目的两个纯 FP / 纯 TP 侧面）：
`rules_only` / `rules+deberta_fallback`（生产口径）/ `rules+deberta_always`。
`always` 是必须的 —— 预筛门只在规则层完全没声音时才省算力，而生成的攻击
往往就是规则层无声的那一类，`fallback` 会把它整个跳过、看起来召回很低。

⚠ `always` 的耗时必须与 `rules_only` 有量级差，否则说明 L3 根本没被调用 ——
本脚本有 `_assert_measured()` 在写盘前自证（与 overrefusal 同一个教训：
`Pipeline(config=...)` 不读 `semantic_*`，第一次就这么静默测了个空）。

用法::

    python -X utf8 scripts/redteam_check.py                        # 规则层（秒级）
    python -X utf8 scripts/redteam_check.py --configs all          # 含 DeBERTa
    python -X utf8 scripts/redteam_check.py --labels data/redteam_labels.jsonl
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

ROOT = Path(__file__).resolve().parent.parent

CONFIGS = {
    "rules_only": {"semantic": False, "mode": "", "label": "L1+L2 规则层"},
    "rules+deberta_fallback": {"semantic": True, "mode": "fallback",
                               "label": "规则层 + L3 DeBERTa（fallback，生产口径）"},
    "rules+deberta_always": {"semantic": True, "mode": "always",
                             "label": "规则层 + L3 DeBERTa（always，每条都问 L3）"},
}
LEVEL_RANK = {"safe": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
#: 「检出」的口径。与 overrefusal 那边不同 —— 那边问的是良性别被拦，
#: 这边问的是攻击有没有被看见，而** medium 就算看见**（它进人工复核了）。
CAUGHT_RANK = LEVEL_RANK["medium"]


def _rate(hit: int, total: int) -> float:
    return round(hit / total, 4) if total else 0.0


def evaluate(rows: list[dict], *, semantic: bool, mode: str, backend: str,
             policy_name: str, split: str) -> dict:
    from prompt_ids.core.pipeline import PipelineConfig, create_pipeline

    pipeline = create_pipeline(config=PipelineConfig(
        semantic_enabled=semantic,
        semantic_mode=mode or "fallback",
        semantic_backend=backend if semantic else "null",
        enable_cache=False,
    ))
    try:
        if semantic:
            pipeline.warmup()
        detector = pipeline.semantic_detector
        started = time.perf_counter()
        results = [(row, pipeline.scan(row["text"], policy_name=policy_name))
                   for row in rows]
        elapsed = time.perf_counter() - started
    finally:
        pipeline.close()

    caught = sum(1 for _row, res in results
                 if LEVEL_RANK.get(res.level.value, 0) >= CAUGHT_RANK)
    blocked = sum(1 for _row, res in results
                  if LEVEL_RANK.get(res.level.value, 0) >= LEVEL_RANK["high"])
    by_strategy: dict[str, list[int]] = defaultdict(lambda: [0, 0, 0])
    by_split: dict[str, list[int]] = defaultdict(lambda: [0, 0, 0])
    by_template: dict[str, list[int]] = defaultdict(lambda: [0, 0, 0])
    pattern_hits: dict[str, int] = defaultdict(int)
    missed_examples: list[dict] = []
    for row, res in results:
        rank = LEVEL_RANK.get(res.level.value, 0)
        hit = rank >= CAUGHT_RANK
        # ⚠ **两个口径都要给，且不可混比**：`recall`(≥medium) 与 `blocked`(≥high)
        # 差一个数量级。AGENTS.md 里 agent 面那条「规则层 block 召回 0.0000」
        # 是 **≥high** 口径 —— 拿 ≥medium 去对那句话会得出「我们其实抓到了」的
        # 相反结论（实测 agentic 家族 ≥medium 0.5714 / ≥high 远低于此）。
        stop = rank >= LEVEL_RANK["high"]
        for bucket, key in ((by_strategy, row["source"]),
                            (by_split, row.get("split", "?")),
                            (by_template, row["template_id"])):
            bucket[key][1] += 1
            bucket[key][0] += int(hit)
            bucket[key][2] += int(stop)
        for finding in res.findings:
            pattern_hits[finding.pattern_id] += 1
        if not hit and len(missed_examples) < 25:
            missed_examples.append({
                "text": row["text"], "source": row["source"],
                "template_id": row["template_id"], "level": res.level.value,
                "score": round(res.score, 1),
            })

    def group(bucket: dict) -> dict:
        return {key: {"n": total, "recall": _rate(hit, total),
                      "blocked": _rate(stop, total)}
                for key, (hit, total, stop) in sorted(bucket.items())}

    stats = detector.stats() if semantic and detector is not None else {}
    return {
        "n": len(results),
        "split": split,
        "policy": policy_name,
        "caught_at_medium": {"hits": caught, "n": len(results),
                             "rate": _rate(caught, len(results))},
        "blocked_at_high": {"hits": blocked, "n": len(results),
                            "rate": _rate(blocked, len(results))},
        "by_strategy": group(by_strategy),
        "by_split": group(by_split),
        "templates_fully_missed": sorted(
            key for key, (hit, _total, _stop) in by_template.items() if hit == 0),
        "top_patterns": dict(sorted(pattern_hits.items(), key=lambda kv: -kv[1])[:12]),
        "missed_examples": missed_examples,
        "latency_ms": {"total_s": round(elapsed, 2),
                       "per_sample_ms": round(elapsed * 1000 / len(results), 2)
                       if results else 0.0},
        "reliability": {
            "semantic_backend": stats.get("backend", ""),
            "semantic_model": stats.get("model", ""),
            "semantic_calls": stats.get("calls", 0),
            "semantic_abstained": stats.get("abstained", 0),
            "failed_share": stats.get("failed_share", 0.0),
            "degraded": bool(stats.get("degraded")),
        },
    }


def _assert_measured(report: dict) -> None:
    """写盘前自证：声称用了语义层的配置真的调了 L3。

    同一个教训在 `overrefusal_check.py` 已经踩过一次：用 `Pipeline(config=...)`
    而不是 `create_pipeline(config=...)`，`semantic_*` 被静默忽略，always 模式
    一条都没问 L3，而三个配置的数字完全相同、报告照写。
    """
    problems: list[str] = []
    for name, config in report["configs"].items():
        if "deberta" in name and config["n"]:
            if config["reliability"]["semantic_backend"] in ("", "null"):
                problems.append(f"{name}: 后端是 "
                                f"{config['reliability']['semantic_backend']!r}，L3 没装配")
            if config["reliability"]["semantic_calls"] == 0:
                problems.append(f"{name}: n={config['n']} 但 semantic_calls=0")
    rules = report["configs"].get("rules_only")
    always = report["configs"].get("rules+deberta_always")
    if rules and always and always["n"] >= 30:
        fast = rules["latency_ms"]["per_sample_ms"]
        slow = always["latency_ms"]["per_sample_ms"]
        if slow < fast * 3:
            problems.append(f"always {slow}ms vs 规则层 {fast}ms：差不到 3 倍，"
                            f"不像「每条都过了 L3」")
    if problems:
        print("\n[测量无效] " + "\n          ".join(problems), file=sys.stderr)
        print("  多半是构造流水线用错了入口（要 create_pipeline）。", file=sys.stderr)
        raise SystemExit(3)


def _load_labels(path: Path) -> dict[str, int]:
    """人工标注：{"text": ..., "label": 1|0}。缺文件 ⇒ 返回空 dict（不是 0）。"""
    if not path.exists():
        return {}
    labels: dict[str, int] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        key = " ".join(str(row.get("text", "")).split()).casefold()
        labels[key] = int(row.get("label", 0))
    return labels


def _usability(rows: list[dict], labels: dict[str, int]) -> dict:
    """人工标注的可用率。没标注就**明说未标注**，不拿模型判定冒充。"""
    if not labels:
        return {
            "status": "unlabeled",
            "note": "**可用率未标注** —— 生成 N 条不代表 N 条都是真攻击。"
                    "请人工标注后用 --labels 提供（{\"text\":…, \"label\":1/0}）；"
                    "在此之前本报告的任何召回都不能被当成「对真攻击的召回」。",
        }
    judged = [(row, labels.get(" ".join(row["text"].split()).casefold()))
              for row in rows]
    scored = [(row, label) for row, label in judged if label is not None]
    if not scored:
        return {"status": "no_match", "note": "标注文件与本数据集没有交集"}
    usable = [row for row, label in scored if label == 1]
    return {
        "status": "labeled",
        "labeled_n": len(scored),
        "unlabeled_n": len(judged) - len(scored),
        "usable": len(usable),
        "usable_share": _rate(len(usable), len(scored)),
        "by_strategy": {
            source: {
                "labeled": sum(1 for row, label in scored if row["source"] == source),
                "usable": sum(1 for row, label in scored
                              if row["source"] == source and label == 1),
            }
            for source in sorted({row["source"] for row, _ in scored})
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="红队生成集的形态覆盖评测（纯 TP 侧）")
    parser.add_argument("--dataset", default=str(ROOT / "data" / "redteam.jsonl"))
    parser.add_argument("--labels", default=str(ROOT / "data" / "redteam_labels.jsonl"))
    parser.add_argument("--configs", default="rules_only",
                        help="逗号分隔；all = 三个都跑（rules_only 约 1 秒，"
                             "含 DeBERTa 约 2 分钟）")
    parser.add_argument("--semantic-backend", default="local",
                        help="⚠ 必须显式指定：auto 现在是**云端优先**，"
                             "不指定会打到 LLM 裁判（≈10s/条）")
    parser.add_argument("--policy", default="default")
    parser.add_argument("--split", default="all", help="all/train/test")
    parser.add_argument("--out", default=str(ROOT / "reports" / "redteam.json"))
    args = parser.parse_args(argv)

    dataset = Path(args.dataset)
    if not dataset.exists():
        print(f"[缺失] {dataset}\n  先跑：python scripts/build_redteam.py", file=sys.stderr)
        return 2
    rows = [json.loads(line) for line in dataset.read_text(encoding="utf-8").splitlines()
            if line.strip()]
    if args.split != "all":
        rows = [row for row in rows if row.get("split") == args.split]
    if not rows:
        print(f"[空] split={args.split} 没有样本", file=sys.stderr)
        return 2

    names = (list(CONFIGS) if args.configs.strip() == "all"
             else [n.strip() for n in args.configs.split(",") if n.strip()])
    for name in names:
        if name not in CONFIGS:
            print(f"[未知配置] {name}；可选 {sorted(CONFIGS)}", file=sys.stderr)
            return 2

    labels = _load_labels(Path(args.labels))
    report = {
        "generated_by": "scripts/redteam_check.py",
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "dataset": {
            "path": str(dataset.relative_to(ROOT)) if dataset.is_relative_to(ROOT)
            else str(dataset),
            "samples": len(rows), "labels": {"1（攻击）": len(rows), "0（良性）": 0},
            "split_filter": args.split,
        },
        "usability": _usability(rows, labels),
        "method": {
            "side": "true_positive_only",
            "cannot": "**给不了系统能力的绝对值。** 生成器只能产出「我们想得到的形态」，"
                      "这里的召回既不是上界也不是下界，只能当**形态覆盖探针**，"
                      "必须与公开集（deepset / garak / PINT）并列引用。",
            "caught_at": "≥medium 即算「检出」—— 停在 medium/review 也算被看见（进人工了）。",
            "two_readings": "**`recall`(≥medium) 与 `blocked`(≥high) 不可混比**，"
                            "两者差一个数量级。引用 AGENTS.md 里 agent 面的"
                            "「规则层 block 召回 0.0000」时必须用 ≥high 口径 —— "
                            "拿 ≥medium 去对会得出「我们其实抓到了」的相反结论。",
            "why_always": "`always` 是必须的一组：预筛门只在规则层完全没声音时才省算力，"
                          "而生成的攻击往往正是规则层无声的那一类 ⇒ 只跑 `fallback` "
                          "会得到一个「规则层抓不到、语义层也没被问」的假低召回。",
            "split": "切分按 **template_id**，不是按行。引用 test 侧数字前先确认"
                     "「这一形态没在 train 上被调过规则」。",
            "pair_with": "与 reports/overrefusal.json（纯 FP 侧）互补，"
                         "两者语料互不污染。",
        },
        "configs": {},
    }

    print(f"数据集 {dataset.name}：{len(rows)} 条纯攻击"
          f"（split={args.split}）")
    usability = report["usability"]
    if usability["status"] == "unlabeled":
        print("⚠ 可用率未标注 —— 下面的召回不能当成「对真攻击的召回」")
    else:
        print(f"人工标注可用率 {usability['usable']}/{usability['labeled_n']} "
              f"= {usability['usable_share']}")

    for name in names:
        spec = CONFIGS[name]
        print(f"\n== {name}（{spec['label']}）==")
        result = evaluate(rows, semantic=spec["semantic"], mode=spec["mode"],
                          backend=args.semantic_backend, policy_name=args.policy,
                          split=args.split)
        report["configs"][name] = {"label": spec["label"], **result}
        caught = result["caught_at_medium"]
        print(f"  检出(≥medium) {caught['rate']:.4f}（{caught['hits']}/{caught['n']}）"
              f"  拦截(≥high) {result['blocked_at_high']['rate']:.4f}"
              f"  {result['latency_ms']['per_sample_ms']}ms/条")
        for source, row in sorted(result["by_strategy"].items()):
            print(f"    {source:<28} 检出≥med {row['recall']:.4f}  "
                  f"拦截≥high {row['blocked']:.4f}  ({row['n']} 条)")
        if result["templates_fully_missed"]:
            print(f"  完全漏掉的模板: {result['templates_fully_missed']}")
        rel = result["reliability"]
        if rel["semantic_calls"]:
            print(f"  可靠性：{rel['semantic_backend']}/{rel['semantic_model']} "
                  f"调用 {rel['semantic_calls']} 次，弃权 {rel['semantic_abstained']}"
                  f"（{rel['failed_share']:.0%}）"
                  f"{'  ⚠ 已降级，该组数字不可单独引用' if rel['degraded'] else ''}")

    _assert_measured(report)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n报告已写 {out}")
    print("⚠ 这份读数是形态覆盖探针，不是系统能力的绝对值；且必须与公开集并列引用。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
