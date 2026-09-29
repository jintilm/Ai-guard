"""漏检分析 —— 论文「规则层失效分析」章节的取数脚本。

回答三个问题：
  1. 规则层到底漏了哪些攻击
  2. 漏检样本集中在哪个数据源 / 哪个类别
  3. 漏检样本的高频措辞是什么（给补规则提供线索，务必在留出集上验证）

用法：
    python scripts/miss_analysis.py
    python scripts/miss_analysis.py --dataset data/public_combined.jsonl --top 25
"""
from __future__ import annotations

import argparse
import re
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from prompt_ids.core.pipeline import PipelineConfig, create_pipeline  # noqa: E402
from prompt_ids.core.types import Variant  # noqa: E402
from prompt_ids.detectors import DetectorContext  # noqa: E402
from prompt_ids.eval.datasets import BUILTIN, Dataset  # noqa: E402
from prompt_ids.eval.metrics import markdown_table  # noqa: E402

_STOPWORDS = {
    "the", "a", "an", "and", "or", "to", "of", "in", "for", "on", "with", "is", "are",
    "you", "your", "will", "be", "i", "it", "that", "this", "me", "my", "we", "as", "at",
    "ja", "der", "die", "das", "und", "ich", "sie", "zu", "ein", "eine", "ist", "nicht",
}


def _tokens(text: str) -> list[str]:
    raw = re.findall(r"[A-Za-z\u4e00-\u9fff]{3,}", text.lower())
    return [t for t in raw if t not in _STOPWORDS]


def main() -> int:
    parser = argparse.ArgumentParser(description="规则层漏检分析")
    parser.add_argument("--dataset", default="data/full.jsonl")
    parser.add_argument("--only", action="store_true", help="不拼接内置种子集")
    parser.add_argument("--top", type=int, default=20, help="展示多少条漏检样例")
    args = parser.parse_args()

    path = Path(args.dataset)
    data = Dataset(()) if args.only else BUILTIN
    data = data.concat(Dataset.from_jsonl(path))

    pipeline = create_pipeline(config=PipelineConfig(enable_cache=False))
    rule_det = pipeline.registry.get("rule")

    missed_by_source: Counter = Counter()
    missed_by_category: Counter = Counter()
    total_by_source: Counter = Counter()
    token_counter: Counter = Counter()
    examples: list[tuple[str, int]] = []

    attacks = [s for s in data if s.label == 1]
    for sample in attacks:
        findings = rule_det.detect(
            DetectorContext(
                raw=sample.text,
                canonical=sample.text,
                variants=[Variant(kind="original", text=sample.text)],
            )
        )
        total_by_source[sample.source] += 1
        if findings:
            continue
        missed_by_source[sample.source] += 1
        missed_by_category[sample.category] += 1
        token_counter.update(set(_tokens(sample.text)))
        examples.append((sample.text, 0))

    print(f"攻击样本 {len(attacks)} 条，规则层漏检 {len(examples)} 条 "
          f"（覆盖率 {1 - len(examples) / max(len(attacks), 1):.2%}）\n")

    rows = []
    for source, total in sorted(total_by_source.items(), key=lambda kv: -kv[1]):
        missed = missed_by_source.get(source, 0)
        rows.append([source, total, missed, f"{missed / total:.1%}", f"{1 - missed / total:.1%}"])
    print(markdown_table(["数据源", "攻击数", "漏检数", "漏检率", "覆盖率"], rows, aligns="lrrrr"))

    if missed_by_category:
        print("\n漏检样本的类别分布：")
        cat_rows = [[cat, cnt] for cat, cnt in missed_by_category.most_common(10)]
        print(markdown_table(["类别", "漏检数"], cat_rows, aligns="lr"))

    print("\n漏检样本高频词（补规则的线索）：")
    print("  " + ", ".join(f"{w}({c})" for w, c in token_counter.most_common(25)))

    print(f"\n漏检样例 Top{args.top}：")
    for text, _ in examples[: args.top]:
        print(f"  - {text[:130]}")

    print("\n提示：用这些措辞补规则后，务必在留出集（而非本文件所用的同一批数据）上复测，")
    print("     否则等同于用测试集调参，指标会虚高。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
