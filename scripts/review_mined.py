"""把复核语料接进**已有的**规则调优链路（不是另造一套自动改规则）。

    复核  ->  review_corpus.jsonl（含原文） -> 本脚本 -> review_mined.jsonl
          ->  miss_analysis / eval_semantic 现成脚本 -> 人工改规则 -> 复跑看数字

刻意不做的事：**不自动改规则、不自动降权**。理由写在 `audit.query.rule_suspects`
的 docstring 里 —— 那几个数字（分母偏向已触发的规则、3 次误报证明不了什么、
降权会毁掉可解释性且等于告诉攻击者打哪条）每一条都成立。
本脚本的职责只是「把人的结论变成现成脚本能吃的语料」，让闭环有落脚点。

口径纪律：
- 语料里的 `label` 就是人工结论，不是模型自标注 —— 这是它比 `data/full.jsonl`
  更可信的地方，但**样本量小、分布有偏**（偏向进了复核队列的那些）。
- **不要把 review_mined 混进公开集一起报数字**。它是内部诊断集，混进去会把
  公开集口径污染掉。要报就单独报，并写清来源。

    python -X utf8 scripts/review_mined.py --corpus data/review_corpus.jsonl
    python -X utf8 scripts/miss_analysis.py --dataset data/review_mined.jsonl --only
"""
from __future__ import annotations

import argparse
import io
import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"


def load_corpus(path: Path) -> list[dict]:
    if not path.exists():
        print(f"复核语料不存在：{path}", file=sys.stderr)
        print("先启动服务时加 --review-corpus <路径>，或 python -m prompt_ids.web "
              "--review-corpus <路径>", file=sys.stderr)
        raise SystemExit(2)
    rows = []
    for line in io.open(path, encoding="utf-8"):
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        # 第一行是 header（说明文件含原文），不是样本
        if row.get("type") == "prompt-ids-review-corpus":
            continue
        if not row.get("text"):
            continue
        rows.append(row)
    return rows


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="复核语料 -> 规则调优语料")
    parser.add_argument("--corpus", default=str(DATA / "review_corpus.jsonl"))
    parser.add_argument("--out", default=str(DATA / "review_mined.jsonl"))
    args = parser.parse_args(argv)

    rows = load_corpus(Path(args.corpus))
    if not rows:
        print("语料里没有样本。先在检测台复核几条，或调 POST /v1/review。", file=sys.stderr)
        return 2

    seen: set[str] = set()
    out_rows = []
    for row in rows:
        text = " ".join(str(row["text"]).split())
        key = str(row.get("fp") or text)
        if key in seen:
            continue
        seen.add(key)
        out_rows.append({
            "text": text,
            "label": 1 if row.get("label") else 0,
            "source": "review_corpus",
            "category": row.get("category") or f"review:{row.get('top_pattern', 'unknown')}",
            "patterns": row.get("patterns") or [],
            "top_pattern": row.get("top_pattern", ""),
            "level": row.get("level", ""),
        })

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with io.open(out, "w", encoding="utf-8") as fh:
        for row in out_rows:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")

    # 产物同样是**原文**（它就是语料换个格式），必须挡住误提交。
    # 之前只有 review_corpus 被自动加进 .gitignore，mined 这条路是空的 ——
    # 也就是说「跑一次 mining 就可能把复核原文提交上去」。
    from prompt_ids.audit.review_corpus import add_to_gitignore

    if add_to_gitignore(out):
        print(f"已把 {out} 加进 .gitignore（含原文，刻意不入库）")

    attacks = sum(r["label"] for r in out_rows)
    print(f"{out}  共 {len(out_rows)} 条：人工确认攻击 {attacks} / 误报 {len(out_rows) - attacks}")
    print("按归因规则分布（误报侧就是「该查哪些规则」的线索）：")
    for pattern, count in Counter(
            r["top_pattern"] for r in out_rows if not r["label"]).most_common(12):
        print(f"  {pattern or '(未归因)':<14} {count}")
    print("\n下一步：")
    print(f"  python -X utf8 scripts/miss_analysis.py --dataset {out} --only")
    print("  改完规则后用同一个脚本复跑，对比数字；规则迭代只用 train 侧，别碰留出集。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
