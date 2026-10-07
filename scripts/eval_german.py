"""德语子集评测。

验证多语言规则补全是靠数据而不是拍脑袋：分别报告
训练集（参与过规则迭代）与留出集（未参与）上的德语攻击召回，
以及德语正常样本的误报率。两者差距就是过拟合程度。

用法：
    python scripts/eval_german.py
    python scripts/eval_german.py --rules-only     # 只看 L1 规则层
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from prompt_ids.core.pipeline import Pipeline, PipelineConfig
from prompt_ids.detectors import DetectorRegistry, HeuristicDetector, RuleDetector
from prompt_ids.eval.datasets import INJECTION
from prompt_ids.eval.metrics import BLOCK_LEVELS, Confusion, markdown_table
from prompt_ids.preprocess.guard import Guard
from prompt_ids.rules.loader import load_rules

DATA = Path(__file__).resolve().parent.parent / "data" / "public_deepset.jsonl"

_GERMAN = re.compile(
    r"\b(der|die|das|und|ich|nicht|für|mit|wir|sie|ein|eine|ist|auf|wie|was|warum|"
    r"bitte|jetzt|vergiss|ignoriere|alle|vorherigen|dich|deine|neue|den|dem|des)\b",
    re.IGNORECASE,
)


def is_german(text: str) -> bool:
    return len(_GERMAN.findall(text)) >= 3


def main() -> int:
    parser = argparse.ArgumentParser(description="德语子集评测")
    parser.add_argument("--rules-only", action="store_true", help="只评估 L1 规则层")
    parser.add_argument("--exclude", help="排除指定规则 ID（逗号分隔），用于量这批规则的贡献")
    args = parser.parse_args()

    rows = [json.loads(line) for line in DATA.open(encoding="utf-8")]
    german = [r for r in rows if is_german(r["text"])]
    if not german:
        print("未找到德语样本")
        return 1

    # 手工装配流水线，才能在规则集合上做增删
    excluded = {s.strip() for s in (args.exclude or "").split(",") if s.strip()}
    rules = [r for r in load_rules() if r.id not in excluded]
    detectors = [RuleDetector(rules=rules)]
    if not args.rules_only:
        detectors.append(HeuristicDetector())
    pipeline = Pipeline(
        registry=DetectorRegistry(detectors=detectors),
        guard=Guard(),
        config=PipelineConfig(enable_cache=False),
    )
    if excluded:
        print(f"（已排除 {len(excluded)} 条规则：{', '.join(sorted(excluded))}）")

    buckets: dict[str, tuple[list[int], list[int]]] = {}
    for record in german:
        result = pipeline.scan(record["text"])
        predicted = 1 if result.level.value in BLOCK_LEVELS else 0
        trues, preds = buckets.setdefault(record["source"], ([], []))
        trues.append(record["label"])
        preds.append(predicted)

    # 本脚本只装配规则层与启发层：验证规则贡献不需要带语义层
    mode = "L1 仅规则" if args.rules_only else "L1+L2（不含语义层）"
    print(f"德语样本 {len(german)} 条（攻击 "
          f"{sum(1 for r in german if r['label'] == INJECTION)}），模式：{mode}\n")

    rows_out = []
    for source, (trues, preds) in sorted(buckets.items()):
        confusion = Confusion.from_pairs(trues, preds)
        row = confusion.as_row()
        rows_out.append([
            source, len(trues), row["precision"], row["recall"], row["f1"],
            row["false_positive_rate"],
        ])
    print(markdown_table(
        ["数据源", "样本数", "Precision", "Recall", "F1", "误报率"],
        rows_out,
        aligns="lrrrrr",
    ))

    train_recall = next((r[3] for r in rows_out if "train" in r[0]), None)
    test_recall = next((r[3] for r in rows_out if "test" in r[0]), None)
    if train_recall is not None and test_recall is not None and test_recall > 0:
        print(f"\n训练/留出召回比：{train_recall:.3f} / {test_recall:.3f} "
              f"（差距越小说明规则泛化越好，而非记住了样本）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
