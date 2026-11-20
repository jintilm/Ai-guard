"""Diagnose a rejected development document using bounded direct model requests.

No model-list requests, payload obfuscation, or automatic endpoint switching.
Fragments are diagnostic controls only; evaluation data remains byte-for-byte intact.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from prompt_ids.detectors.semantic.llm import LLMBackend
from prompt_ids.detectors.semantic.providers import auth_headers, build_request
from prompt_ids.eval.rag import load_corpus, sha256
from prompt_ids.preprocess import Preprocessor
from scripts.eval_rag_bench import write_report

ROOT = Path(__file__).resolve().parents[1]


def controls(rows: list[dict]) -> tuple[dict, list[dict]]:
    original = next(r for r in rows if r["id"] == "probes:en:3000:quoted_attack:tail")
    clean = next(r for r in rows if r["id"] == "probes:en:3000:clean:none")
    if original["split"] != "dev" or clean["split"] != "dev":
        raise ValueError("Gateway diagnosis must use development data")
    canonical = Preprocessor().variants(original["text"])[0].text
    shell_start = canonical.index("```shell")
    shell_end = canonical.index("```", shell_start + 3) + 3
    quotation_start = canonical.index("Security training appendix:")
    start, end = original["inserted_span"]
    return original, [
        {"name": "neutral_before", "text": "Explain what a Kubernetes Pod is."},
        {"name": "original_quoted_case", "text": canonical},
        {"name": "clean_source", "text": Preprocessor().variants(clean["text"])[0].text},
        {"name": "quotation_only", "text": original["text"][start:end]},
        {"name": "source_before_shell", "text": canonical[:shell_start]},
        {"name": "source_shell_example", "text": canonical[shell_start:shell_end]},
        {"name": "source_after_shell", "text": canonical[shell_end:quotation_start]},
        {"name": "original_without_response_format", "text": canonical, "json_mode": False},
        {"name": "original_accept_json", "text": canonical, "accept_json": True},
        {"name": "neutral_same_length", "text": ("Routine Kubernetes documentation. " * 100)[:len(canonical)]},
        {"name": "neutral_after", "text": "Explain what a Kubernetes Pod is."},
    ]


def request(backend: LLMBackend, case: dict, timeout: float) -> dict:
    ep = backend.endpoints[0]
    if ep.kind != "openai":
        raise ValueError("This diagnostic targets an OpenAI-compatible direct chat endpoint")
    payload = backend._openai_payload(ep, case["text"], case.get("json_mode", True))
    data = json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json", **auth_headers(ep.provider, ep.api_key)}
    if case.get("accept_json"):
        headers["Accept"] = "application/json"
    req = build_request(ep.url, data=data, headers=headers, method="POST")
    result = {"control": case["name"], "input_chars": len(case["text"]),
              "input_sha256": sha256(case["text"].encode("utf-8")),
              "request_body_sha256": sha256(data), "request_bytes": len(data),
              "json_mode": case.get("json_mode", True), "accept_json": case.get("accept_json", False),
              "http_status": None, "valid_verdict": False}
    started = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            blob = response.read(1_000_000)
            result.update(http_status=response.status, content_type=response.headers.get_content_type())
        outer = json.loads(blob)
        choice = outer["choices"][0]
        _, _, parsed = backend._parse_verdict(choice["message"]["content"] or "",
                                             choice.get("finish_reason", ""))
        result["valid_verdict"] = parsed
    except urllib.error.HTTPError as exc:
        blob = exc.read(4096)
        result.update(http_status=exc.code, content_type=exc.headers.get_content_type(),
                      response_excerpt_sha256=sha256(blob),
                      html_error_page=b"<html" in blob.lower())
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        result["transport_error"] = type(exc).__name__
    except (ValueError, KeyError, TypeError, IndexError):
        result["response_error"] = "invalid_json_or_verdict_schema"
    result["elapsed_ms"] = round((time.monotonic() - started) * 1000, 3)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute", action="store_true", help="send the listed direct model requests")
    parser.add_argument("--max-calls", type=int, default=11)
    parser.add_argument("--timeout", type=float, default=30)
    parser.add_argument("--out", type=Path, default=ROOT / "reports/rag_gateway_diagnostic.json")
    args = parser.parse_args()
    rows, manifest = load_corpus(ROOT / "data/rag_bench.jsonl.gz")
    original, cases = controls(rows)
    if args.timeout <= 0 or args.max_calls < len(cases):
        parser.error(f"Positive timeout and --max-calls >= {len(cases)} are required")
    if not args.execute:
        print(json.dumps({"planned_direct_requests": len(cases), "controls": [c["name"] for c in cases]}))
        return 0
    backend = LLMBackend(max_retries=0, allow_fallbacks=False, fallbacks=[], extra_body={},
                         input_strategy="head", max_input_chars=3000)
    if not backend.is_available():
        parser.error("Configure a model and direct endpoint before running the diagnostic")
    report = {"generated_at": datetime.now(timezone.utc).isoformat(),
              "dataset_sha256": manifest["sha256"], "sample_id": original["id"],
              "model": backend.model_name, "provider": backend.provider,
              "method": {"requests": "POST chat/completions only", "retries": 0,
                         "timeout_s": args.timeout, "max_calls": args.max_calls,
                         "code_sha256": sha256(Path(__file__).read_bytes()),
                         "note": "Diagnostic controls do not replace or relabel benchmark cases."},
              "results": [], "complete": False}
    for case in cases:
        result = request(backend, case, args.timeout)
        report["results"].append(result)
        write_report(args.out, report)
        print(f"{result['control']}: HTTP {result['http_status']}, "
              f"valid_verdict={result['valid_verdict']}", flush=True)
    report["complete"] = True
    write_report(args.out, report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
