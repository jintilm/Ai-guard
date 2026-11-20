"""Measure sample composition before changing RAG evaluation defaults; no models."""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from prompt_ids.eval.datasets import Dataset, Sample
from prompt_ids.eval.rag import SEED, load_corpus, sha256
from prompt_ids.eval.rag_sampling import (
    SAMPLING_VERSION,
    balanced_rows,
    length_band,
    sample_summary,
)
from scripts.eval_semantic import stratified_slice

ROOT = Path(__file__).resolve().parents[1]


def legacy_rows(rows: list[dict], count: int) -> list[dict]:
    data = Dataset(tuple(Sample(r["text"], r["label"], source="|".join((
        r["language"], r["kind"], r["position"], length_band(r["document_chars"])))) for r in rows))
    hashes = {sha256(r.text.encode("utf-8")) for r in stratified_slice(data, count, SEED)}
    return [r for r in rows if r["text_sha256"] in hashes]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=ROOT / "reports/rag_sampling.json")
    args = parser.parse_args()
    rows, manifest = load_corpus(ROOT / "data/rag_bench.jsonl.gz")
    dev = [r for r in rows if r["split"] == "dev"]
    measures = []
    for count in (24, 120):
        selected = balanced_rows(dev, count)
        invariant = [r["id"] for r in selected] == [r["id"] for r in balanced_rows(list(reversed(dev)), count)]
        if not invariant:
            raise ValueError("Balanced sample depends on source order")
        summary = sample_summary(selected)
        expected = {"en": count // 2, "zh": count // 2}
        if summary["by_language"] != expected:
            raise ValueError("Language quotas were not met")
        if summary["by_kind"] != {"attack": count // 2, "clean": count // 4, "quoted_attack": count // 4}:
            raise ValueError("Label/control quotas were not met")
        measures.append({"sample_size": count, "legacy": sample_summary(legacy_rows(dev, count)),
                         "balanced": summary, "source_order_invariant": invariant,
                         "selected_ids": [r["id"] for r in selected]})
    report = {"generated_at": datetime.now(timezone.utc).isoformat(), "seed": SEED,
              "dataset_sha256": manifest["sha256"], "split": "dev", "model_invoked": False,
              "sampling_version": SAMPLING_VERSION,
              "sampler_sha256": sha256((ROOT / "prompt_ids/eval/rag_sampling.py").read_bytes()),
              "method": "Equal language and label quotas; benign kinds equal; spread groups then position/length.",
              "population_note": "Diagnostic quotas, not a prevalence estimate; variants share parent groups.",
              "measurements": measures}
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n",
                        encoding="utf-8", newline="\n")
    for measure in measures:
        print(json.dumps({"n": measure["sample_size"], "legacy": measure["legacy"]["by_language"],
                          "balanced": measure["balanced"]["by_language"],
                          "kinds": measure["balanced"]["by_kind"],
                          "groups": measure["balanced"]["groups"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
