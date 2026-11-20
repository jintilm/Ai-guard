"""Measure semantic backlog and retry budgets without external requests."""
from __future__ import annotations

import argparse
import json
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from prompt_ids.detectors.semantic.base import Prediction, SemanticBackend
from prompt_ids.detectors.semantic.detector import SemanticDetector
from prompt_ids.detectors.semantic.llm import LLMBackend


class SlowBackend(SemanticBackend):
    name = "synthetic_slow"

    def __init__(self, delay_s: float):
        self.delay_s = delay_s
        self.calls = 0
        self.lock = threading.Lock()

    def predict(self, text: str) -> Prediction:
        with self.lock:
            self.calls += 1
        time.sleep(self.delay_s)
        return Prediction(0.9, "synthetic verdict", self.name)


def burst(requests: int = 16, workers: int = 4, timeout: float = 0.05) -> dict:
    backend = SlowBackend(0.25)
    detector = SemanticDetector(enabled=True, backend=backend, mode="always",
                                timeout_s=timeout, max_workers=workers)
    ready = threading.Barrier(requests)

    def call(index):
        ready.wait(timeout=10)
        started = time.perf_counter()
        prediction = detector.predict(f"synthetic-{index}")
        return prediction.ok, (time.perf_counter() - started) * 1000

    started = time.perf_counter()
    try:
        with ThreadPoolExecutor(max_workers=requests) as clients:
            results = list(clients.map(call, range(requests)))
        at_return = backend.calls
        stats_at_return = detector.stats()
        # Drain only for measurement: count work that continues after clients timed out.
        if detector._executor is not None:
            detector._executor.shutdown(wait=True)
        return {
            "requests": requests, "workers": workers, "timeout_s": timeout,
            "backend_delay_s": backend.delay_s,
            "backend_calls_at_return": at_return,
            "backend_calls_after_drain": backend.calls,
            "late_backend_calls": backend.calls - at_return,
            "successful_predictions": sum(ok for ok, _ in results),
            "max_client_ms": round(max(ms for _, ms in results), 3),
            "drain_total_ms": round((time.perf_counter() - started) * 1000, 3),
            "stats_at_return": stats_at_return,
        }
    finally:
        detector.close()


def retry_budget() -> dict:
    backend = LLMBackend(provider="custom", model_name="synthetic",
                         base_url="http://127.0.0.1:1/v1", api_key="synthetic",
                         fallbacks="ollama", extra_body={}, max_retries=2)
    backend.default_timeout_s = 0.06
    attempts = []

    def timed_out(endpoint, text, timeout_s, use_json):
        attempts.append(timeout_s)
        time.sleep(timeout_s)
        raise TimeoutError("synthetic timeout")

    backend._request = timed_out
    started = time.perf_counter()
    result = backend.predict("synthetic prompt")
    return {"budget_s": backend.default_timeout_s, "attempts": len(attempts),
            "elapsed_ms": round((time.perf_counter() - started) * 1000, 3),
            "ok": result.ok}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    report = {"generated_at": datetime.now(timezone.utc).isoformat(),
              "method": "Synthetic backend and HTTP substitutes; no external requests.",
              "burst": burst(), "retry_budget": retry_budget()}
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
