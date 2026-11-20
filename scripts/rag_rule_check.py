"""Measure PV-C008 changes on development/training data; holdouts are opt-in final checks."""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from prompt_ids.eval.datasets import Dataset
from prompt_ids.eval.rag import load_corpus, sha256
from prompt_ids.eval.rag_sampling import balanced_rows
from scripts.eval_rag_bench import metrics, write_report
from scripts.eval_semantic import build_pipeline

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--previous", type=Path)
    parser.add_argument("--holdout", action="store_true")
    args = parser.parse_args()
    rag, manifest = load_corpus(ROOT / "data/rag_bench.jsonl.gz")
    split = "test" if args.holdout else "dev"
    selected = [r for r in rag if r["split"] == split]
    selected = selected if args.holdout else balanced_rows(selected, 120)
    datasets = {"rag": selected}
    public = Dataset.from_jsonl(ROOT / "data/full.jsonl").filter_sources(
        include=["deepset_test" if args.holdout else "deepset_train"])
    pint = Dataset.from_jsonl(ROOT / f"data/pint_shape_{'test' if args.holdout else 'train'}.jsonl")
    for name, data in (("deepset", public), ("pint_shape", pint)):
        datasets[name] = [{"id": sha256(s.text.encode()), "text": s.text,
                           "label": s.label, "kind": "attack" if s.label else "clean"}
                          for s in data]
    pipeline = build_pipeline(short_circuit=False, enable_cache=False)
    pipeline.warmup()
    report = {"generated_at": datetime.now(timezone.utc).isoformat(), "split": split,
              "rag_dataset_sha256": manifest["sha256"],
              "rules_sha256": {p.name: sha256(p.read_bytes()) for p in sorted((ROOT / "prompt_ids/rules").glob("*.yaml"))},
              "results": {}}
    try:
        for name, rows in datasets.items():
            records = []
            for row in rows:
                result = pipeline.scan(row["text"])
                hits = [f for f in result.findings if f.pattern_id == "PV-C008"]
                records.append({"id": row["id"], "label": row["label"], "kind": row["kind"],
                                "risk": int(result.level.value in ("high", "critical")),
                                "blocked": int(result.action.value == "block"),
                                "flagged": int(result.level.value in ("medium", "high", "critical")),
                                "action": result.action.value, "pv_c008": bool(hits),
                                "variants": sorted({h.variant for h in hits})})
            summary = metrics(records)
            summary["pv_c008_hits"] = dict(Counter("attack" if r["label"] else "benign"
                                                   for r in records if r["pv_c008"]))
            report["results"][name] = {"summary": summary, "records": records}
            print(f"{name}: {json.dumps(summary)}", flush=True)
    finally:
        pipeline.close()
    if args.previous:
        previous = json.loads(args.previous.read_text("utf-8"))
        if previous["split"] != split:
            raise ValueError("Comparison split mismatch")
        changes = {}
        for name, data in report["results"].items():
            old = {r["id"]: r for r in previous["results"][name]["records"]}
            if set(old) != {r["id"] for r in data["records"]}:
                raise ValueError("Comparison samples differ")
            changes[name] = [{"id": r["id"], "label": r["label"],
                              "before": old[r["id"]]["action"], "after": r["action"],
                              "old_hit": old[r["id"]]["pv_c008"], "new_hit": r["pv_c008"]}
                             for r in data["records"] if any(r[k] != old[r["id"]][k]
                             for k in ("risk", "blocked", "pv_c008"))]
        report["changes"] = changes
        report["previous_sha256"] = sha256(args.previous.read_bytes())
    write_report(args.out, report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
