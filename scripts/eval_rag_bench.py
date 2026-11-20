"""Evaluate contextual RAG data without conflating payload visibility and detection.

Default: offline L1/L2 baseline plus head/stratified visibility measurements.
--mode llm explicitly compares the production pipelines with an always-on judge,
interleaving the two strategies. A call limit is required, retries/fallbacks are
disabled, successful predictions are cached under logs/ for resumability.
"""
from __future__ import annotations

import argparse
import json
import random
import re
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from prompt_ids.core.context import ScanContext
from prompt_ids.detectors.semantic.detector import DEGRADED_CALL_FAIL_SHARE
from prompt_ids.detectors.semantic.llm import CONTEXT_JUDGE_PROMPT, JUDGE_PROMPT, LLMBackend
from prompt_ids.detectors.semantic.windowing import sample_text
from prompt_ids.eval.datasets import Dataset, Sample
from prompt_ids.eval.metrics import Confusion, latency_stats, percentile
from prompt_ids.eval.rag import SEED, load_corpus, sha256
from prompt_ids.eval.rag_sampling import (
    SAMPLING_VERSION,
    balanced_rows,
    length_band,
    sample_summary,
)
from scripts.eval_semantic import CachedSemanticBackend, build_pipeline, stratified_slice

ROOT = Path(__file__).resolve().parents[1]


def failure_kind(pipeline) -> str | None:
    """Persist a diagnostic class, never gateway error bodies or credentials."""
    detector = pipeline.semantic_detector
    prediction = detector.last_prediction if detector else None
    if prediction is None:
        return "not_invoked" if detector else None
    if prediction.ok:
        return None
    code = getattr(prediction, "failure_code", "")
    if code:
        http_status = getattr(prediction, "http_status", None)
        return f"http_{http_status}" if code == "http_error" and http_status else code
    reason = prediction.rationale.casefold()
    codes = re.findall(r"\bhttp\s+([45][0-9]{2})\b", reason)
    if codes:
        return "http_" + codes[0]
    if any(word in reason for word in ("timeout", "timed out", "超时")):
        return "timeout"
    if any(word in reason for word in ("json", "解析")):
        return "invalid_response"
    return "backend_unavailable"


def select_rows(rows: list[dict], count: int, sampling: str = "balanced") -> list[dict]:
    # scripts/rag_sampling_check.py records the old 22en/2zh pilot and verifies
    # equal language/label quotas before adopting this default.
    if sampling == "balanced":
        return balanced_rows(rows, count)
    if sampling != "legacy":
        raise ValueError(f"Unknown sampling method: {sampling}")
    if not count or count >= len(rows):
        selected = list(rows)
    else:
        dataset = Dataset(tuple(Sample(
            r["text"], r["label"], source="|".join(
                (r["language"], r["kind"], r["position"], length_band(r["document_chars"]))))
            for r in rows))
        hashes = {sha256(s.text.encode("utf-8")) for s in stratified_slice(dataset, count, SEED)}
        selected = [row for row in rows if row["text_sha256"] in hashes]
    random.Random(SEED).shuffle(selected)
    return selected


def coverage(rows: list[dict], budget: int, windows: int) -> dict:
    output = {}
    for strategy in ("head", "stratified"):
        buckets: dict[str, list] = defaultdict(list)
        for row in rows:
            if row["label"] != 1:
                continue
            spans = sample_text(row["text"], budget=budget, strategy=strategy,
                                max_windows=windows).coverage.ranges
            start, end = row["inserted_span"]
            visible = any(a <= start and end <= b for a, b in spans)
            touched = any(a < end and start < b for a, b in spans)
            bucket = f"{length_band(row['document_chars'])}/{row['position']}"
            buckets[bucket].append((visible, touched))
        output[strategy] = {
            key: {"n": len(items), "whole_payload_visible": sum(a for a, _ in items),
                  "payload_touched": sum(b for _, b in items),
                  "whole_payload_share": round(sum(a for a, _ in items) / len(items), 4)}
            for key, items in sorted(buckets.items())}
    return {"basis": "raw_document, before production preprocessing",
            "metric": "Inserted payload visibility, not detection recall or attack success",
            "budget_chars": budget, "windows": windows, "strategies": output}


def metrics(records: list[dict]) -> dict:
    truth = [r["label"] for r in records]
    benign = [r for r in records if not r["label"]]
    return {
        "n": len(records), "attacks": sum(truth), "benign": len(benign),
        "risk": Confusion.from_pairs(truth, (r["risk"] for r in records)).as_row(),
        "blocking": Confusion.from_pairs(truth, (r["blocked"] for r in records)).as_row(),
        "benign_flagged_ge_medium_rate": (
            round(sum(r["flagged"] for r in benign) / len(benign), 4) if benign else None),
        "benign_review_action_rate": (
            round(sum(r["action"] == "review" for r in benign) / len(benign), 4) if benign else None),
    }


def grouped(records: list[dict], field: str) -> dict:
    buckets: dict[str, list] = defaultdict(list)
    for row in records:
        buckets[row[field]].append(row)
    return {key: metrics(items) for key, items in sorted(buckets.items())}


def group_intervals(records: list[dict]) -> dict:
    """Bootstrap parent groups, never treat derived placements as independent."""
    groups = grouped(records, "group_id")
    result = {"method": "95% percentile bootstrap of group-macro rates; resample group_id",
              "iterations": 2000, "groups": len(groups)}
    for name, side, field, denominator in (
        ("risk_recall", "risk", "recall", "attacks"),
        ("block_recall", "blocking", "recall", "attacks"),
        ("block_fpr", "blocking", "false_positive_rate", "benign"),
    ):
        values = [g[side][field] for g in groups.values() if g[denominator]]
        rng = random.Random(SEED)
        if len(values) < 3:
            result[name] = {"eligible_groups": len(values), "mean": None, "ci95": None}
            continue
        draws = [sum(rng.choices(values, k=len(values))) / len(values) for _ in range(2000)]
        result[name] = {"eligible_groups": len(values), "mean": round(sum(values) / len(values), 4),
                        "ci95": [round(percentile(draws, q), 4) for q in (0.025, 0.975)]}
    return result


def summarize(records: list[dict], semantic: bool) -> dict:
    successes = sum(r["semantic_ok"] is True for r in records)
    failed = len(records) - successes if semantic else 0
    share = failed / len(records) if semantic and records else 0.0
    return {
        **metrics(records),
        "by_language": grouped(records, "language"), "by_kind": grouped(records, "kind"),
        "by_position": grouped(records, "position"), "by_length": grouped(records, "length_band"),
        "by_split": grouped(records, "split"), "by_group": grouped(records, "group_id"),
        "group_intervals": group_intervals(records),
        "uncached_latency_ms": latency_stats([r["latency_ms"] for r in records if not r["cache_hit"]]),
        "cache_hits": sum(r["cache_hit"] for r in records),
        "reliability": {"semantic_expected": semantic, "valid_verdicts": successes,
                        "failed_or_skipped": failed, "failed_share": round(share, 4),
                        "failure_kinds": {kind: sum(r.get("failure_kind") == kind for r in records)
                                          for kind in sorted({r.get("failure_kind") for r in records
                                                              if r.get("failure_kind")})},
                        "degraded": share > DEGRADED_CALL_FAIL_SHARE,
                        "usable_for_comparison": bool(records) and (not semantic or successes > 0)
                        and share <= DEGRADED_CALL_FAIL_SHARE},
        "reliability_slices": {
            field: {value: {
                "n": sum(r[field] == value for r in records),
                "failed": sum(r[field] == value and r["semantic_ok"] is not True for r in records),
            } for value in sorted({r[field] for r in records})}
            for field in ("language", "kind", "group_id")
        } if semantic else {},
    }


def paired_difference(records: dict[str, list[dict]], reference: str = "head",
                      candidate: str = "stratified") -> dict | None:
    if candidate not in records:
        return None
    left, right = records[reference], records[candidate]
    if [r["id"] for r in left] != [r["id"] for r in right]:
        raise ValueError("Strategy comparison must use exactly the same cases in the same order")
    groups_a, groups_b = grouped(left, "group_id"), grouped(right, "group_id")
    delta = []
    for group in groups_a:
        if groups_a[group]["attacks"]:
            delta.append(groups_b[group]["risk"]["recall"] - groups_a[group]["risk"]["recall"])
    if len(delta) < 3:
        return {"eligible_groups": len(delta), "risk_recall_delta": None, "ci95": None}
    rng = random.Random(SEED)
    draws = [sum(rng.choices(delta, k=len(delta))) / len(delta) for _ in range(2000)]
    return {"metric": f"{candidate} minus {reference}, paired group-macro risk recall",
            "eligible_groups": len(delta), "risk_recall_delta": round(sum(delta) / len(delta), 4),
            "ci95": [round(percentile(draws, q), 4) for q in (0.025, 0.975)]}


def valid_pair_analysis(records: dict[str, list[dict]]) -> dict | None:
    if len(records) != 2:
        return None
    valid = set.intersection(*({r["id"] for r in items if r["semantic_ok"] is True}
                               for items in records.values()))
    return {"n": len(valid), "excluded": len(next(iter(records.values()))) - len(valid),
            "note": "Conditional on both judges succeeding; excludes failures, not an unbiased correction.",
            "results": {name: metrics([r for r in items if r["id"] in valid])
                        for name, items in records.items()}}


def write_report(path: Path, report: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8",
                         newline="\n")
    for attempt in range(5):
        try:
            temporary.replace(path)
            break
        except PermissionError:
            # Windows readers/indexers may briefly hold a handle without delete
            # sharing; retain the complete temporary file if the lock persists.
            if attempt == 4:
                raise
            time.sleep(0.05 * (attempt + 1))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, default=ROOT / "data/rag_bench.jsonl.gz")
    parser.add_argument("--split", choices=("dev", "test", "all"), default="dev")
    parser.add_argument("--mode", choices=("rules", "llm"), default="rules")
    parser.add_argument("--sample", type=int, default=0, help="quota-balanced subset; 0 means full split")
    parser.add_argument("--sampling", choices=("balanced", "legacy"), default="balanced")
    parser.add_argument("--plan-only", action="store_true", help="write sample plan without calling detectors")
    parser.add_argument("--compare-context", action="store_true",
                        help="compare text-only vs trusted task context, both using head sampling")
    parser.add_argument("--provider", default="auto")
    parser.add_argument("--model", default="")
    parser.add_argument("--timeout", type=float, default=30)
    parser.add_argument("--max-llm-calls", type=int, default=0)
    parser.add_argument("--budget", type=int, default=3000)
    parser.add_argument("--windows", type=int, default=3)
    parser.add_argument("--cache-dir", type=Path, default=ROOT / "logs/rag_eval_cache")
    parser.add_argument("--out", type=Path, default=None)
    args = parser.parse_args()
    if args.compare_context and args.mode != "llm":
        parser.error("--compare-context requires --mode llm")
    if args.sample < 0 or args.timeout <= 0 or args.budget < 1 or not 1 <= args.windows <= 8:
        parser.error("Sample size must be nonnegative; timeout/budget positive; windows 1..8")
    rows, manifest = load_corpus(args.dataset)
    eligible = [r for r in rows if args.split == "all" or r["split"] == args.split]
    try:
        selected = select_rows(eligible, args.sample, args.sampling)
    except ValueError as exc:
        parser.error(str(exc))
    selection = {"method": (SAMPLING_VERSION if args.sampling == "balanced" else "legacy-proportional")
                 if args.sample else "full-split",
                 "composition": sample_summary(selected),
                 "population_note": "Balanced diagnostic quotas do not estimate corpus or production prevalence.",
                 "selected_ids": [r["id"] for r in selected]}
    if args.plan_only:
        path = args.out or ROOT / f"reports/rag_sample_{args.split}.json"
        write_report(path, {"dataset_sha256": manifest["sha256"], "split": args.split,
                            "selection": selection,
                            "planned_logical_calls": len(selected) * 2 if args.mode == "llm" else 0,
                            "model_invoked": False})
        print(json.dumps(selection["composition"], ensure_ascii=False, indent=2))
        return 0
    if args.mode == "llm" and (args.max_llm_calls <= 0 or len(selected) * 2 > args.max_llm_calls):
        parser.error(f"This comparison needs at most {len(selected) * 2} logical calls. "
                     "Set --max-llm-calls explicitly or reduce --sample (HTTP attempts <= 2x).")
    output = args.out or ROOT / f"reports/rag_{args.mode}_{args.split}.json"
    names = (("rules",) if args.mode == "rules" else
             ("text_only", "task_context") if args.compare_context else ("head", "stratified"))
    pipelines, caches, backend_info = {}, {}, {}
    for name in names:
        semantic = None
        if args.mode == "llm":
            backend = LLMBackend(provider=args.provider, model_name=args.model, max_retries=0,
                                 allow_fallbacks=False, fallbacks=[], extra_body={},
                                 input_strategy="head" if args.compare_context else name,
                                 max_input_chars=args.budget,
                                 max_windows=args.windows)
            if not backend.is_available():
                parser.error("Explicit LLM evaluation requested but no usable backend is configured")
            backend.default_timeout_s = args.timeout
            prompt_hash = sha256((CONTEXT_JUDGE_PROMPT if name == "task_context" else
                                  JUDGE_PROMPT).encode("utf-8"))[:16]
            cache = CachedSemanticBackend(backend, args.cache_dir / f"{prompt_hash}.{name}.json", 1)
            caches[name] = cache
            semantic = {"enabled": True, "mode": "always", "backend": cache,
                        "timeout_s": args.timeout}
            backend_info[name] = {"provider": backend.provider, "model": backend.model_name,
                                  "max_tokens": backend.max_tokens,
                                  "backend_fingerprint": cache._fingerprint,
                                  "task_context": name == "task_context",
                                  "input_sampling": backend.input_sampling,
                                  "judge_prompt_sha256": prompt_hash}
        pipelines[name] = build_pipeline(semantic=semantic, short_circuit=False, enable_cache=False)
        pipelines[name].warmup()
    records: dict[str, list[dict]] = {name: [] for name in names}
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "dataset": {"version": manifest["version"], "sha256": manifest["sha256"],
                    "split": args.split, "eligible": len(eligible), "selected": len(selected),
                    "selected_ids_sha256": sha256("\n".join(r["id"] for r in selected).encode()),
                    "groups": len({r["group_id"] for r in selected}), "sample_seed": SEED,
                    "selection": selection},
        "method": {"mode": args.mode, "policy": "default",
                   "semantic_mode": "always" if args.mode == "llm" else None,
                   "short_circuit": False, "pipeline_budget_ms": 5000,
                   "context_supplied_to_detector": args.compare_context,
                   "context_note": ("Only task_context receives application task and untrusted source role."
                                    if args.compare_context else "No task context supplied."),
                   "order": "paired/interleaved, alternating which strategy runs first",
                   "max_logical_calls": args.max_llm_calls,
                   "max_http_attempts": args.max_llm_calls * 2,
                   "max_retries": 0, "fallbacks": False, "backend": backend_info,
                   "timeout_s": args.timeout, "token_usage": None,
                   "cost_note": "Character budget is not a token count; provider token usage is not collected.",
                   "code_sha256": {name: sha256((ROOT / name).read_bytes()) for name in (
                       "scripts/eval_rag_bench.py", "scripts/eval_semantic.py",
                       "prompt_ids/eval/rag_sampling.py", "prompt_ids/core/context.py",
                       "prompt_ids/core/pipeline.py", "prompt_ids/core/verdict.py",
                       "prompt_ids/detectors/semantic/llm.py")},
                   "rules_sha256": {p.name: sha256(p.read_bytes())
                                    for p in sorted((ROOT / "prompt_ids/rules").glob("*.yaml"))},
                   "scope": manifest["scope"]},
        "coverage": coverage(selected, args.budget, args.windows),
        "complete": False, "records": records,
    }
    print(f"{args.mode}: {len(selected)}/{len(eligible)} rows, "
          f"{report['dataset']['groups']} parent groups, split={args.split}", flush=True)
    consecutive_failed_pairs = 0
    try:
        for index, row in enumerate(selected):
            # Pairing limits the effect of endpoint health drifting over time.
            for name in names if index % 2 == 0 else names[::-1]:
                hits_before = caches[name].hits if name in caches else 0
                context = (ScanContext(row["context"]["user_task"], row["context"]["role"])
                           if name == "task_context" else None)
                result = pipelines[name].scan(row["text"], context=context)
                detector = pipelines[name].semantic_detector
                prediction = detector.last_prediction if detector else None
                record = {key: row[key] for key in
                          ("id", "group_id", "split", "language", "kind", "position", "label")}
                record.update({"length_band": length_band(row["document_chars"]),
                               "risk": int(result.level.value in ("high", "critical")),
                               "blocked": int(result.action.value == "block"),
                               "flagged": int(result.level.value in ("medium", "high", "critical")),
                               "action": result.action.value, "score": result.score,
                               "semantic_ok": result.semantic_ok,
                               "semantic_execution": result.semantic_execution.to_dict()
                               if result.semantic_execution else None,
                               "semantic_context_used": result.semantic_context_used,
                               "context_fingerprint": result.context_fingerprint,
                               "semantic_probability": prediction.probability
                               if prediction and prediction.ok else None,
                               "finding_ids": sorted({f.pattern_id for f in result.findings}),
                               "failure_kind": failure_kind(pipelines[name]),
                               "latency_ms": result.latency_ms.get("total", 0),
                               "cache_hit": name in caches and caches[name].hits > hits_before,
                               "semantic_coverage": result.semantic_coverage.to_dict()
                               if result.semantic_coverage else None})
                records[name].append(record)
                if name in caches:
                    caches[name].flush()
            if args.mode == "llm":
                all_failed = all(records[name][-1]["semantic_ok"] is not True for name in names)
                consecutive_failed_pairs = consecutive_failed_pairs + 1 if all_failed else 0
            if args.mode == "llm" or (index + 1) % 50 == 0 or index + 1 == len(selected):
                write_report(output, report)
                print(f"  completed pairs {index + 1}/{len(selected)}", flush=True)
            if consecutive_failed_pairs >= 3:
                report["stopped_reason"] = "Three consecutive pairs have no valid semantic verdicts"
                print(report["stopped_reason"], flush=True)
                break
    finally:
        for pipeline in pipelines.values():
            pipeline.close()
        write_report(output, report)
    report["complete"] = all(len(items) == len(selected) for items in records.values())
    report["results"] = {name: summarize(items, args.mode == "llm") for name, items in records.items()}
    usable = report["complete"] and all(
        r["reliability"]["usable_for_comparison"] for r in report["results"].values())
    context_observed = (not args.compare_context or all(
        r["semantic_context_used"] for r in records["task_context"] if r["semantic_ok"] is True))
    usable = usable and context_observed
    report["context_observed_when_successful"] = context_observed
    report["paired_difference"] = (paired_difference(records, *names) if usable and len(names) == 2 else None)
    report["valid_pair_analysis"] = valid_pair_analysis(records)
    report["comparison_usable"] = usable
    report["model_calls_this_run"] = {name: cache.misses for name, cache in caches.items()}
    write_report(output, report)
    for name, outcome in report["results"].items():
        if not usable:
            print(f"{name}: comparison unavailable; "
                  f"failed={outcome['reliability']['failed_share']:.1%}, "
                  f"causes={outcome['reliability']['failure_kinds']}", flush=True)
            continue
        print(f"{name}: risk R={outcome['risk']['recall']:.4f}, "
              f"block R={outcome['blocking']['recall']:.4f}, "
              f"block FPR={outcome['blocking']['false_positive_rate']:.4f}, "
              f"failed={outcome['reliability']['failed_share']:.1%}", flush=True)
    return 0 if usable else 3


if __name__ == "__main__":
    raise SystemExit(main())
