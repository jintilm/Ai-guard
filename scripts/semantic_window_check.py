"""Measure LLM input coverage using training payloads; no model accuracy claims."""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from prompt_ids.detectors.semantic.windowing import sample_text
from prompt_ids.eval.datasets import Dataset

ROOT = Path(__file__).resolve().parent.parent


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, default=ROOT / "data/full.jsonl")
    parser.add_argument("--out", type=Path, default=ROOT / "reports/semantic_windows.json")
    args = parser.parse_args()
    train = Dataset.from_jsonl(args.dataset).filter_sources(include=["deepset_train"])
    payloads = [sample.text for sample in train.attacks()]
    if not payloads:
        parser.error("No deepset_train attack payloads found")
    budget = 3000
    rows = []
    for length in (3000, 12000, 30000):
        for position in ("head", "middle", "tail"):
            for strategy in ("head", "stratified"):
                whole = touched = count = sampled_chars = prompt_chars = 0
                max_hole = 0
                for payload in payloads:
                    if len(payload) > length:
                        continue
                    count += 1
                    start = {"head": 0, "middle": (length - len(payload)) // 2,
                             "tail": length - len(payload)}[position]
                    filler = ("Project notes and routine status updates. " * length)[:length]
                    text = filler[:start] + payload + filler[start + len(payload):]
                    selected = sample_text(text, budget=budget, strategy=strategy)
                    spans = selected.coverage.ranges
                    end = start + len(payload)
                    whole += int(any(a <= start and end <= b for a, b in spans))
                    touched += int(any(a < end and start < b for a, b in spans))
                    sampled_chars += selected.coverage.sampled_chars
                    prompt_chars = max(prompt_chars, len(selected.text))
                    ends = (0, *(b for _, b in spans))
                    starts = (*(a for a, _ in spans), length)
                    max_hole = max(max_hole, max(b - a for a, b in zip(ends, starts)))
                rows.append({"document_chars": length, "position": position, "strategy": strategy,
                             "n": count, "whole_payload_visible": whole, "payload_touched": touched,
                             "whole_payload_share": round(whole / count, 4),
                             "mean_sampled_chars": round(sampled_chars / count, 1),
                             "max_payload_chars": prompt_chars, "max_unread_gap": max_hole,
                             "planned_logical_judge_calls": 1})
    report = {"generated_at": datetime.now(timezone.utc).isoformat(),
              "dataset": {"path": args.dataset.name,
                          "sha256": hashlib.sha256(args.dataset.read_bytes()).hexdigest(),
                          "source_used": "deepset_train", "attack_payloads": len(payloads)},
              "method": {"budget_chars": budget, "max_windows": 3,
                         "metric": "Payload visibility in selected text, not detection recall.",
                         "calls": "One planned logical judge call; retries are separate HTTP attempts.",
                         "model_invoked": False, "holdout_used": False}, "rows": rows}
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    for row in rows:
        print(f"{row['document_chars']:>6} {row['position']:<6} {row['strategy']:<10} "
              f"whole={row['whole_payload_visible']}/{row['n']} "
              f"selected={row['mean_sampled_chars']} gap={row['max_unread_gap']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
