"""三层消融评测 —— 论文实验章节的主力脚本。

跑 5 组配置，输出 Precision/Recall/F1/误报率/延迟分位/语义调用率，
同时产出可直接贴进论文的 markdown 表格与供画图的 JSON。

    python scripts/eval_semantic.py
    python scripts/eval_semantic.py --no-semantic      # 只跑规则/启发，不加载大模型
    python scripts/eval_semantic.py --dataset data/x.jsonl
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from prompt_ids.core.pipeline import Pipeline, PipelineConfig  # noqa: E402
from prompt_ids.core.verdict import FusionConfig  # noqa: E402
from prompt_ids.detectors import DetectorContext, DetectorRegistry, HeuristicDetector, RuleDetector  # noqa: E402
from prompt_ids.detectors.semantic.detector import SemanticDetector  # noqa: E402
from prompt_ids.eval.datasets import BUILTIN, Dataset, source_label  # noqa: E402
from prompt_ids.eval.metrics import BLOCK_LEVELS, Confusion, latency_stats, markdown_table  # noqa: E402
from prompt_ids.preprocess.guard import Guard  # noqa: E402
from prompt_ids.rules.loader import RuleBook  # noqa: E402

REPORT_DIR = Path(__file__).resolve().parent.parent / "reports"


def build_pipeline(
    use_rule: bool = True,
    use_heuristic: bool = True,
    semantic: dict | None = None,
    short_circuit: bool = False,
    enable_cache: bool = False,
) -> Pipeline:
    detectors = []
    if use_rule:
        detectors.append(RuleDetector(rules=RuleBook()))
    if use_heuristic:
        detectors.append(HeuristicDetector())
    if semantic:
        detectors.append(SemanticDetector(**semantic))
    return Pipeline(
        registry=DetectorRegistry(detectors=detectors),
        guard=Guard(),
        config=PipelineConfig(
            fusion=FusionConfig(),
            enable_cache=enable_cache,
            short_circuit_on_critical=short_circuit,
            budget_ms=5000.0,
        ),
    )


ABLATIONS = {
    "L1 仅规则": dict(use_rule=True, use_heuristic=False),
    "L1+L2 规则+启发": dict(use_rule=True, use_heuristic=True),
    "L1+L2+L3 (fallback 门禁)": dict(
        use_rule=True, use_heuristic=True, semantic=dict(mode="fallback", enabled=True)
    ),
    "L1+L2+L3 (always 全量)": dict(
        use_rule=True, use_heuristic=True, semantic=dict(mode="always", enabled=True)
    ),
    "L3 仅语义": dict(use_rule=False, use_heuristic=False, semantic=dict(mode="always", enabled=True)),
}


def run_group(name: str, spec: dict, dataset: Dataset, no_semantic: bool) -> dict:
    if no_semantic and spec.get("semantic"):
        return {"skipped": True}
    pipeline = build_pipeline(**spec)
    pipeline.warmup()  # 模型冷启动不计入延迟统计

    y_true: list[int] = []
    y_pred: list[int] = []
    latencies: list[float] = []
    # 按数据来源分别统计，用来对比「公开集 vs 自建集」上的表现差异
    per_source: dict[str, tuple[list[int], list[int]]] = {}
    semantic_calls = 0

    det = pipeline.semantic_detector
    before = det.calls if det else 0

    for sample in dataset:
        result = pipeline.scan(sample.text)
        prediction = 1 if result.level.value in BLOCK_LEVELS else 0
        y_true.append(sample.label)
        y_pred.append(prediction)
        latencies.append(result.latency_ms.get("total", 0.0))
        bucket = per_source.setdefault(sample.source, ([], []))
        bucket[0].append(sample.label)
        bucket[1].append(prediction)

    if det:
        semantic_calls = det.calls - before
        stats = det.stats()
    else:
        stats = {}

    confusion = Confusion.from_pairs(y_true, y_pred)
    row = confusion.as_row()
    latency = latency_stats(latencies)
    return {
        "confusion": row,
        "latency_ms": latency,
        "semantic_calls": semantic_calls,
        "semantic_call_rate": round(semantic_calls / max(len(dataset), 1), 4),
        "semantic": stats,
        "by_source": {
            source: Confusion.from_pairs(trues, preds).as_row()
            for source, (trues, preds) in sorted(per_source.items())
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="三层消融评测")
    parser.add_argument("--dataset", nargs="*", help="外部数据集（.jsonl / .csv）")
    parser.add_argument("--no-semantic", action="store_true", help="跳过含语义层的组，不加载大模型")
    parser.add_argument("--only", action="store_true", help="只用外部数据集，不拼接内置种子集")
    parser.add_argument("--out", default=str(REPORT_DIR / "ablation.json"))
    args = parser.parse_args()

    if args.only and args.dataset:
        data = Dataset(())
    else:
        data = BUILTIN
    for spec in args.dataset or []:
        path = Path(spec)
        extra = Dataset.from_jsonl(path) if path.suffix == ".jsonl" else Dataset.from_csv(path)
        data = data.concat(extra)
    counts = data.counts()
    print(f"数据集：{counts['total']} 条（攻击 {counts['attack']} / 正常 {counts['benign']}）")
    print(f"判定阈 level ∈ {sorted(BLOCK_LEVELS)} 记为预测攻击\n")

    results: dict[str, dict] = {}
    for name, spec in ABLATIONS.items():
        outcome = run_group(name, spec, data, args.no_semantic)
        if outcome.get("skipped"):
            print(f"[skip] {name}")
            continue
        results[name] = outcome
        row = outcome["confusion"]
        print(
            f"[done] {name:<24} P={row['precision']:.3f} R={row['recall']:.3f} "
            f"F1={row['f1']:.3f} FPR={row['false_positive_rate']:.3f} "
            f"P95={outcome['latency_ms']['p95']:.1f}ms "
            f"语义调用={outcome['semantic_calls']}"
        )

    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    out = Path(args.out)
    out.write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")

    rows = []
    for name, outcome in results.items():
        row = outcome["confusion"]
        rows.append([
            name,
            f"{row['precision']:.4f}",
            f"{row['recall']:.4f}",
            f"{row['f1']:.4f}",
            f"{row['false_positive_rate']:.4f}",
            f"{outcome['latency_ms']['p50']:.1f}",
            f"{outcome['latency_ms']['p95']:.1f}",
            str(outcome["semantic_calls"]),
        ])
    table = markdown_table(
        ["配置", "Precision", "Recall", "F1", "误报率", "P50(ms)", "P95(ms)", "语义调用次数"],
        rows,
        aligns="lrrrrrrr",
    )
    print("\n" + table)

    sources = sorted({s for outcome in results.values() for s in outcome.get("by_source", {})})
    if len(sources) > 1:
        print("\n按数据来源拆分（同一套配置的泛化表现）：")
        for source in sources:
            sub_rows = []
            for name, outcome in results.items():
                row = outcome.get("by_source", {}).get(source)
                if not row:
                    continue
                sub_rows.append([
                    name, row["precision"], row["recall"], row["f1"],
                    row["false_positive_rate"], row["tp"] + row["fn"],
                ])
            print(f"\n[{source_label(source)}]")
            print(markdown_table(
                ["配置", "Precision", "Recall", "F1", "误报率", "样本数"],
                sub_rows,
                aligns="lrrrrr",
            ))

    print(f"\nJSON 已保存 -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
