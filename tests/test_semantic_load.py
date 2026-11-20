"""Bounded work, request deadlines, and graceful semantic shutdown."""
from __future__ import annotations

import io
import json
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace

import pytest

from prompt_ids.detectors.semantic import base
from prompt_ids.detectors.semantic.base import Prediction, SemanticBackend
from prompt_ids.detectors.semantic.detector import SemanticDetector
from prompt_ids.detectors.semantic.llm import LLMBackend


class GatedBackend(SemanticBackend):
    name = "gated"

    def __init__(self):
        self.entered = threading.Event()
        self.release = threading.Event()
        self.closed = threading.Event()
        self.calls = []
        self.close_calls = 0

    def predict(self, text):
        self.calls.append(text)
        self.entered.set()
        if not self.release.wait(5):
            raise TimeoutError("test backend not released")
        return Prediction(0.9, "synthetic verdict", self.name)

    def close(self):
        self.close_calls += 1
        self.closed.set()


def wait_until(predicate):
    deadline = time.monotonic() + 3
    while not predicate() and time.monotonic() < deadline:
        threading.Event().wait(0.005)
    assert predicate()


def test_timeout_keeps_running_slots_and_cancelled_queue_bounded():
    backend = GatedBackend()
    detector = SemanticDetector(enabled=True, backend=backend, timeout_s=0.2,
                                max_workers=1, max_pending=1)
    try:
        with ThreadPoolExecutor(max_workers=1) as clients:
            first = clients.submit(detector.predict, "running")
            assert backend.entered.wait(2)
            assert not first.result(timeout=2).ok
        assert not detector.predict("queued").ok
        for _ in range(20):
            assert not detector.predict("overload").ok
            assert detector.contribution() is None
        stats = detector.stats()
        assert (stats["running"], stats["queued"], stats["in_flight"]) == (1, 1, 2)
        assert stats["capacity"] == 2
        assert stats["overloaded"] == 20
        assert stats["cancelled"] == 1
        assert stats["timeouts"] == 2
        assert stats["abstained"] == stats["calls"] == 22
        assert backend.calls == ["running"]
        assert detector._executor._work_queue.qsize() <= 1
        backend.release.set()
        wait_until(lambda: detector.stats()["in_flight"] == 0)
        assert backend.calls == ["running"], "timed-out queued work reached the backend"
        detector.timeout_s = 2
        assert detector.predict("recovered").ok
        assert detector.contribution() == 90
        assert backend.calls == ["running", "recovered"]
    finally:
        backend.release.set()
        detector.close()
        assert backend.closed.wait(3)


def test_shutdown_cancels_pending_work_and_defers_backend_close():
    backend = GatedBackend()
    detector = SemanticDetector(enabled=True, backend=backend, timeout_s=3,
                                max_workers=1, max_pending=1)
    try:
        with ThreadPoolExecutor(max_workers=2) as clients:
            first = clients.submit(detector.predict, "running")
            assert backend.entered.wait(2)
            second = clients.submit(detector.predict, "queued")
            wait_until(lambda: detector.stats()["queued"] == 1)
            detector.close()
            assert not second.result(timeout=2).ok
            assert not backend.closed.is_set()
            assert not detector.predict("after-close").ok
            assert detector._executor is None
            backend.release.set()
            assert first.result(timeout=2).ok
        assert backend.closed.wait(2)
        assert backend.calls == ["running"]
        assert detector.stats()["in_flight"] == 0
        assert detector.stats()["cancelled"] == 1
        detector.close()
        assert backend.close_calls == 1
    finally:
        backend.release.set()
        detector.close()


def test_failed_executor_submission_releases_admission_slot(monkeypatch):
    backend = GatedBackend()
    backend.release.set()
    detector = SemanticDetector(enabled=True, backend=backend, timeout_s=2,
                                max_workers=1, max_pending=0)
    try:
        assert detector.predict("first").ok
        wait_until(lambda: detector.stats()["in_flight"] == 0)

        def fail(*args):
            raise RuntimeError("submission failed")

        with monkeypatch.context() as patch:
            patch.setattr(detector._executor, "submit", fail)
            assert not detector.predict("failed").ok
        assert detector.stats()["in_flight"] == 0
        assert detector.predict("next").ok
        assert backend.calls == ["first", "next"]
    finally:
        detector.close()


def test_queued_work_succeeds_when_budget_is_still_available():
    backend = GatedBackend()
    detector = SemanticDetector(enabled=True, backend=backend, timeout_s=3,
                                max_workers=1, max_pending=1)
    try:
        with ThreadPoolExecutor(max_workers=2) as clients:
            first = clients.submit(detector.predict, "first")
            assert backend.entered.wait(2)
            second = clients.submit(detector.predict, "second")
            wait_until(lambda: detector.stats()["queued"] == 1)
            backend.release.set()
            assert first.result(timeout=2).ok
            assert second.result(timeout=2).ok
        wait_until(lambda: detector.stats()["in_flight"] == 0)
        assert backend.calls == ["first", "second"]
        assert detector.stats()["calls"] == 2
        assert detector.stats()["abstained"] == detector.stats()["cancelled"] == 0
    finally:
        backend.release.set()
        detector.close()


@pytest.mark.parametrize("workers,pending", [(0, None), (-1, 1), (True, 1), (1, -1), (1, 0.5)])
def test_invalid_capacity_is_rejected(workers, pending):
    with pytest.raises(ValueError):
        SemanticDetector(backend=GatedBackend(), max_workers=workers, max_pending=pending)


class Clock:
    now = 0.0

    def advance(self, seconds):
        self.now += seconds


@pytest.fixture
def clock(monkeypatch):
    from prompt_ids.detectors.semantic import llm

    clock = Clock()
    monkeypatch.setattr(base, "monotonic", lambda: clock.now)
    monkeypatch.setattr(llm, "time", SimpleNamespace(
        monotonic=lambda: clock.now, perf_counter=lambda: clock.now, sleep=clock.advance))
    return clock


def judge(**kwargs):
    return LLMBackend(provider="custom", model_name="synthetic", api_key="synthetic",
                      base_url="http://127.0.0.1:1/v1", extra_body={}, **kwargs)


def test_retry_and_backoff_share_one_deadline(clock, monkeypatch):
    backend = judge(fallbacks="ollama", max_retries=2)
    backend.default_timeout_s = 1
    attempts = []

    def timeout(endpoint, text, timeout_s, use_json):
        attempts.append((endpoint.provider, timeout_s))
        clock.advance(min(0.25, timeout_s))
        raise urllib.error.URLError("temporary network error")

    monkeypatch.setattr(backend, "_request", timeout)
    result = backend.predict("sample")
    assert not result.ok
    assert clock.now == pytest.approx(1)
    assert [name for name, _ in attempts] == ["custom"] * 3
    assert [limit for _, limit in attempts] == pytest.approx([1, 0.75, 0.1])
    assert not backend.last_parsed


@pytest.mark.parametrize("wrapped", [False, True])
@pytest.mark.parametrize("clock_offset,budget", [(0.0, 1.0), (1000.0, 0.1), (1_000_000.0, 0.01)])
def test_budget_limited_socket_timeout_stops_even_before_clock_advances(
        clock, monkeypatch, wrapped, clock_offset, budget):
    clock.now = clock_offset
    backend = judge(fallbacks="ollama", max_retries=2)
    backend.default_timeout_s = budget
    calls = []

    def timeout(endpoint, text, timeout_s, use_json):
        calls.append(endpoint.provider)
        error = TimeoutError("socket timeout rounded before deadline")
        raise urllib.error.URLError(error) if wrapped else error

    monkeypatch.setattr(backend, "_request", timeout)
    result = backend.predict("sample")
    assert not result.ok
    assert calls == ["custom"]
    assert clock.now == clock_offset


def test_per_operation_timeout_can_retry_with_a_larger_shared_budget(clock, monkeypatch):
    backend = judge(allow_fallbacks=False, max_retries=0)
    backend.default_timeout_s = 1
    calls = []

    def reply(endpoint, text, timeout_s, use_json):
        calls.append(timeout_s)
        clock.advance(1)
        if len(calls) == 1:
            raise TimeoutError("per-operation timeout")
        return '{"injection":false,"confidence":1}', "stop"

    monkeypatch.setattr(backend, "_request", reply)
    with base.prediction_deadline(3):
        assert backend.predict("sample").ok
    assert calls == [1, 1]


def test_fallback_receives_only_remaining_budget(clock, monkeypatch):
    backend = judge(fallbacks="ollama")
    backend.default_timeout_s = 1
    limits = []

    def reply(endpoint, text, timeout_s, use_json):
        limits.append(timeout_s)
        clock.advance(0.4)
        if endpoint.provider == "custom":
            raise urllib.error.HTTPError(endpoint.url, 401, "denied", {}, io.BytesIO(b'{}'))
        return json.dumps({"injection": False, "confidence": 1}), "stop"

    monkeypatch.setattr(backend, "_request", reply)
    assert backend.predict("sample").ok
    assert limits == pytest.approx([1, 0.6])
    assert base.current_deadline() is None


def test_scheduler_deadline_takes_precedence_and_late_reply_abstains(clock, monkeypatch):
    backend = judge(allow_fallbacks=False)
    backend.default_timeout_s = 15
    limits = []

    def reply(endpoint, text, timeout_s, use_json):
        limits.append(timeout_s)
        clock.advance(0.6)
        return '{"injection": true, "confidence": 0.99}', "stop"

    monkeypatch.setattr(backend, "_request", reply)
    with base.prediction_deadline(0.5):
        assert not backend.predict("late").ok
    assert limits == [0.5]
    assert base.current_deadline() is None
    assert not backend.last_parsed


def test_deadlines_are_isolated_between_threads():
    barrier = threading.Barrier(2)
    seen = {}

    def work(name, deadline):
        with base.prediction_deadline(deadline):
            barrier.wait(timeout=3)
            seen[name] = base.current_deadline()
        assert base.current_deadline() is None

    with ThreadPoolExecutor(max_workers=2) as pool:
        a = pool.submit(work, "a", 100)
        b = pool.submit(work, "b", 200)
        a.result(timeout=5)
        b.result(timeout=5)
    assert seen == {"a": 100, "b": 200}


def test_slow_http_gateway_does_not_receive_retries_after_deadline():
    calls = []
    finished = threading.Event()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length", "0")))
            calls.append(self.path)
            time.sleep(0.3)
            try:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'{}')
            except OSError:
                pass
            finally:
                finished.set()

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    backend = LLMBackend(provider="custom", model_name="stub", api_key="synthetic",
                         base_url=f"http://127.0.0.1:{server.server_port}/v1",
                         max_retries=2, allow_fallbacks=False, extra_body={})
    backend.default_timeout_s = 0.1
    try:
        assert not backend.predict("sample").ok
        assert finished.wait(3)
    finally:
        server.shutdown()
        server.server_close()
    assert calls == ["/v1/chat/completions"]


def test_api_reports_overload_and_running_work_after_timeout():
    from prompt_ids.api.app import ApiContext
    from prompt_ids.api.server import ApiServerConfig, create_api_server
    from prompt_ids.core.pipeline import PipelineConfig, create_pipeline

    backend = GatedBackend()
    detector = SemanticDetector(enabled=True, backend=backend, mode="always", timeout_s=0.2,
                                max_workers=1, max_pending=0)
    pipeline = create_pipeline(semantic=detector, config=PipelineConfig(
        enable_cache=False, semantic_enabled=True, semantic_mode="always", memory_encoder="hashing"))
    server = create_api_server(ApiContext(pipeline=pipeline), ApiServerConfig(port=0, api_key=""))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{server.server_port}"
    try:
        for text in ("A weather report.", "An ordinary document."):
            request = urllib.request.Request(url + "/v1/scan", headers={"Content-Type": "application/json"},
                                             data=json.dumps({"text": text}).encode("utf-8"))
            with urllib.request.urlopen(request, timeout=3) as response:
                result = json.loads(response.read())
            assert all(hit["detector"] != "semantic" for hit in result["findings"])
        with urllib.request.urlopen(url + "/v1/metrics", timeout=3) as response:
            metrics = json.loads(response.read())["semantic"]["info"]
        assert metrics["timeouts"] == 1
        assert metrics["overloaded"] == 1
        assert metrics["abstained"] == metrics["calls"] == 2
        assert metrics["in_flight"] == metrics["running"] == metrics["capacity"] == 1
        assert metrics["queued"] == 0
        assert metrics["degraded"] is True
    finally:
        backend.release.set()
        server.shutdown()
        server.server_close()
        pipeline.close()


def test_timeout_and_overload_results_do_not_freeze_in_pipeline_cache():
    from prompt_ids.core.pipeline import PipelineConfig, create_pipeline

    backend = GatedBackend()
    detector = SemanticDetector(enabled=True, backend=backend, mode="always", timeout_s=0.2,
                                max_workers=1, max_pending=0)
    pipeline = create_pipeline(semantic=detector, config=PipelineConfig(
        semantic_enabled=True, semantic_mode="always", memory_encoder="hashing"))
    texts = ("An ordinary document.", "A weather report.")
    try:
        for text in texts:
            result = pipeline.scan(text)
            assert result.level.value != "critical"
        assert detector.timeouts == detector.overloaded == 1
        backend.release.set()
        wait_until(lambda: detector.stats()["in_flight"] == 0)
        detector.timeout_s = 2
        for text in texts:
            recovered = pipeline.scan(text)
            assert not recovered.cached
            assert recovered.level.value == "critical"
            assert pipeline.scan(text).cached
        assert detector.calls == 4
    finally:
        backend.release.set()
        pipeline.close()
