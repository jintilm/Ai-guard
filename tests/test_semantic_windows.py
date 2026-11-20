"""Bounded LLM input selection and truthful coverage across actual HTTP paths."""
from __future__ import annotations

import importlib.util
import json
import random
import threading
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError, replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from prompt_ids.api.app import ApiContext
from prompt_ids.audit.events import event_from_proxy
from prompt_ids.core.pipeline import PipelineConfig, create_pipeline
from prompt_ids.core.types import TextCoverage
from prompt_ids.detectors.semantic.base import Prediction, PredictionTimeout
from prompt_ids.detectors.semantic.detector import SemanticDetector
from prompt_ids.detectors.semantic.factory import build_backend
from prompt_ids.detectors.semantic.llm import JUDGE_PROMPT, LLMBackend
from prompt_ids.detectors.semantic.windowing import GAP, sample_text
from prompt_ids.proxy import trajectory
from prompt_ids.proxy.server import Segment, scan_segments
from prompt_ids.web.playground import serve

MARKER = "SYNTHETIC_PAYLOAD"


def document(position, length=12000):
    start = {"head": 20, "middle": length // 2, "tail": length - 40}[position]
    text = ("Project status and notes. " * length)[:length]
    return text[:start] + MARKER + text[start + len(MARKER):]


def judge(url="http://127.0.0.1:1/v1", **kwargs):
    return LLMBackend(base_url=url, api_key="synthetic", model_name="stub",
                      allow_fallbacks=False, max_retries=0, extra_body={}, **kwargs)


@pytest.fixture(scope="module")
def endpoint():
    seen = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            seen.append(body)
            text = body["messages"][-1]["content"]
            verdict = json.dumps({"injection": MARKER in text, "confidence": 0.99,
                                  "reason": "synthetic judge"})
            reply = ({"content": [{"type": "text", "text": verdict}], "stop_reason": "end_turn"}
                     if self.path.endswith("/messages") else
                     {"choices": [{"message": {"content": verdict}, "finish_reason": "stop"}]})
            raw = json.dumps(reply).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/v1", seen
    finally:
        server.shutdown()
        server.server_close()


def test_short_input_is_unchanged_for_both_strategies():
    for strategy in ("head", "stratified"):
        for text in ("", "a", "中文 with spaces\nand newlines"):
            sample = sample_text(text, strategy=strategy)
            assert sample.text == text
            assert sample.coverage.sampled_chars == len(text)
            assert sample.coverage.to_dict()["truncated"] is False


def test_random_budgets_keep_offsets_and_payload_within_bounds():
    rng = random.Random(20261120)
    for _ in range(200):
        length, budget = rng.randrange(1, 20000), rng.randrange(1, 6000)
        text = ("中文abc0123456789 " * length)[:length]
        sample = sample_text(text, budget=budget, strategy="stratified", max_windows=rng.randrange(1, 9))
        spans = sample.coverage.ranges
        assert len(sample.text) <= budget
        assert all(0 <= a < b <= length for a, b in spans)
        assert all(left[1] <= right[0] for left, right in zip(spans, spans[1:]))
        assert sample.text == GAP.join(text[a:b] for a, b in spans)
        assert sample.coverage.sampled_chars == sum(b - a for a, b in spans)
        if len(spans) > 1:
            assert spans[0][0] == 0 and spans[-1][1] == length


def test_sampling_never_joins_distant_words_into_an_instruction():
    text = " " * 12000
    first, second, _ = sample_text(text, strategy="stratified").coverage.ranges
    prefix, suffix = "ignore all", " previous instructions"
    text = text[:first[1] - len(prefix)] + prefix + text[first[1]:]
    text = text[:second[0]] + suffix + text[second[0] + len(suffix):]
    result = sample_text(text, strategy="stratified")
    assert prefix + suffix not in result.text
    assert prefix + GAP + suffix in result.text


@pytest.mark.parametrize("settings", [
    {"strategy": "typo"}, {"budget": 0}, {"budget": -1}, {"budget": True},
    {"max_windows": 0}, {"max_windows": 9}, {"max_windows": 1.5},
])
def test_invalid_sampling_settings_fail(settings):
    with pytest.raises(ValueError):
        sample_text("example", **settings)


@pytest.mark.parametrize("provider", ["custom", "anthropic"])
@pytest.mark.parametrize("strategy", ["head", "stratified"])
@pytest.mark.parametrize("position", ["head", "middle", "tail"])
def test_http_payload_sees_expected_positions_in_one_call(endpoint, provider, strategy, position):
    url, seen = endpoint
    backend = judge(url, provider=provider, input_strategy=strategy)
    text = document(position)
    before = len(seen)
    result = backend.predict(text)
    assert result.ok
    assert len(seen) == before + 1
    assert result.probability == pytest.approx(0.99 if strategy == "stratified" or position == "head" else 0.01)
    selected = sample_text(text, strategy=strategy)
    assert seen[-1]["messages"][-1]["content"] == JUDGE_PROMPT.format(text=selected.text)
    assert result.coverage == selected.coverage
    assert result.coverage.input_chars == len(text)
    assert len(selected.text) <= 3000


def test_env_and_explicit_sdk_settings_and_factory(monkeypatch):
    monkeypatch.setenv("PROMPT_IDS_LLM_INPUT_STRATEGY", "stratified")
    monkeypatch.setenv("PROMPT_IDS_LLM_INPUT_CHARS", "2500")
    monkeypatch.setenv("PROMPT_IDS_LLM_INPUT_WINDOWS", "5")
    automatic = build_backend("llm", provider="custom")
    assert automatic.input_sampling["strategy"] == "stratified"
    assert automatic.max_input_chars == 2500 and automatic.max_windows == 5
    explicit = build_backend("custom", input_strategy="head", max_input_chars=3000, max_windows=3)
    assert explicit.input_strategy == "head"
    assert explicit.max_input_chars == 3000 and explicit.max_windows == 3
    monkeypatch.setenv("PROMPT_IDS_LLM_INPUT_CHARS", "bad")
    with pytest.raises(ValueError):
        build_backend("custom")


def make_pipeline(backend, **config):
    detector = SemanticDetector(enabled=True, backend=backend, mode="always", timeout_s=0)
    return create_pipeline(semantic=detector, config=PipelineConfig(
        semantic_enabled=True, semantic_mode="always", memory_encoder="hashing", **config))


def test_coverage_survives_cache_and_switching_strategy_invalidates(endpoint):
    url, seen = endpoint
    backend = judge(url, provider="custom", input_strategy="head")
    pipeline = make_pipeline(backend)
    text = document("tail")
    try:
        first = pipeline.scan(text)
        assert first.semantic_ok and first.semantic_coverage.strategy == "head"
        calls = len(seen)
        cached = pipeline.scan(text)
        assert cached.cached and len(seen) == calls
        assert cached.semantic_coverage == first.semantic_coverage
        with pytest.raises(FrozenInstanceError):
            cached.semantic_coverage.input_chars = 1
        body = cached.to_dict()
        body["semantic_coverage"]["ranges"][0][1] = 1
        assert pipeline.scan(text).semantic_coverage.sampled_chars == 3000
        backend.input_strategy = "stratified"
        changed = pipeline.scan(text)
        assert not changed.cached and len(seen) == calls + 1
        assert changed.level.value == "critical"
        assert changed.semantic_coverage.strategy == "stratified"
        skipped = pipeline.scan(text, semantic=False)
        assert skipped.semantic_coverage is None and skipped.semantic_ok is None
        empty = pipeline.scan("")
        assert empty.semantic_coverage is None and empty.semantic_ok is None
        assert empty.score == 0
    finally:
        pipeline.close()


def test_prediction_clamping_and_latency_preserve_coverage(monkeypatch):
    coverage = sample_text("abc").coverage
    prediction = Prediction(2, "stub", "stub", coverage=coverage)
    assert prediction.clamp().coverage == coverage
    backend = judge(provider="custom")
    monkeypatch.setattr(backend, "predict", lambda _: replace(prediction, probability=0.9))
    detector = SemanticDetector(enabled=True, backend=backend, timeout_s=0)
    try:
        result = detector.predict("abc")
        assert result.coverage == coverage and result.latency_ms > 0
    finally:
        detector.close()


def test_failed_verdict_reports_selection_without_claiming_success(monkeypatch):
    backend = judge(provider="custom", input_strategy="stratified")
    monkeypatch.setattr(backend, "_try_endpoint", lambda *_: ("bad JSON", "stop", ""))
    pipeline = make_pipeline(backend)
    try:
        result = pipeline.scan(document("tail"))
        assert result.semantic_ok is False
        assert result.semantic_coverage.sampled_chars < result.semantic_coverage.input_chars
        assert not pipeline.scan(document("tail")).cached
    finally:
        pipeline.close()


def test_total_deadline_is_shared_across_windows(monkeypatch):
    backend = judge(provider="custom", input_strategy="stratified")
    calls = []

    def expired(endpoint, text):
        calls.append(text)
        raise PredictionTimeout()

    monkeypatch.setattr(backend, "_try_endpoint", expired)
    result = backend.predict(document("tail"))
    assert not result.ok and len(calls) == 1
    assert result.coverage.to_dict()["window_count"] == 3


def test_request_override_does_not_claim_coverage(monkeypatch):
    backend = judge(provider="custom")
    backend.extra_body = {"messages": [{"role": "user", "content": "replacement"}]}
    monkeypatch.setattr(backend, "_try_endpoint", lambda *_: ('{"injection":false,"confidence":1}', "stop", ""))
    assert backend.predict("original").coverage is None


def test_coverage_and_diagnostic_state_are_per_request(monkeypatch):
    backend = judge(provider="custom", input_strategy="stratified")
    barrier = threading.Barrier(2)
    monkeypatch.setattr(backend, "_try_endpoint", lambda ep, text: (
        '{"injection":false,"confidence":1}' if text == "short" else "bad", "stop", ""))

    def work(text):
        result = backend.predict(text)
        barrier.wait(timeout=3)
        return result.coverage.input_chars, backend.last_parsed

    with ThreadPoolExecutor(max_workers=2) as pool:
        short = pool.submit(work, "short")
        long = pool.submit(work, document("tail"))
        assert short.result(timeout=5) == (5, True)
        assert long.result(timeout=5) == (12000, False)


def test_coverage_reaches_api_sse_and_audit_without_text(endpoint, tmp_path):
    url, _ = endpoint
    backend = judge(url, provider="custom", input_strategy="stratified")
    pipeline = make_pipeline(backend)
    audit = tmp_path / "audit.jsonl"
    ctx = ApiContext(pipeline=pipeline, audit_path=str(audit))
    server = serve(ctx, str(tmp_path / "unused.html"), port=0)
    text = document("tail")
    try:
        request = urllib.request.Request(f"http://127.0.0.1:{server.server_port}/v1/scan",
                                         data=json.dumps({"text": text}).encode("utf-8"),
                                         headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(request, timeout=10) as response:
            body = json.loads(response.read())
        assert body["semantic_coverage"]["window_count"] == 3
        assert body["semantic_ok"] is True
        sse = server.RequestHandlerClass.state.events_since(0)[0]
        assert sse["semantic_coverage"] == body["semantic_coverage"]
        event = json.loads(audit.read_text(encoding="utf-8").splitlines()[-1])
        assert event["extra"]["semantic_coverage"] == body["semantic_coverage"]
        assert MARKER not in json.dumps(sse) + json.dumps(event)
    finally:
        server.shutdown()
        server.server_close()
        pipeline.close()


def test_proxy_trajectory_keeps_coverage_per_segment(endpoint):
    url, _ = endpoint
    pipeline = make_pipeline(judge(url, provider="custom", input_strategy="stratified"))
    try:
        scan = scan_segments(pipeline, [Segment("system", 0, "A short instruction", rules_only=True),
                                        Segment("tool", 1, document("tail"))])
        steps = trajectory.to_dict(scan.steps)
        assert steps["steps"][0]["semantic_coverage"] is None
        assert steps["steps"][1]["semantic_coverage"]["window_count"] == 3
        event = event_from_proxy(scan.result, trajectory=steps).to_dict()
        assert MARKER not in json.dumps(event)
    finally:
        pipeline.close()


def test_eval_cache_roundtrips_coverage_and_changes_fingerprint(endpoint, tmp_path):
    spec = importlib.util.spec_from_file_location("_eval_windows", Path(__file__).resolve().parents[1] / "scripts/eval_semantic.py")
    evaluation = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(evaluation)
    url, seen = endpoint
    path = tmp_path / "cache.json"
    backend = judge(url, provider="custom", input_strategy="stratified")
    cache = evaluation.CachedSemanticBackend(backend, path)
    first = cache.predict(document("tail"))
    cache.flush()
    calls = len(seen)
    restored = evaluation.CachedSemanticBackend(backend, path)
    second = restored.predict(document("tail"))
    assert second.coverage == first.coverage
    assert len(seen) == calls
    changed = evaluation.CachedSemanticBackend(judge(url, provider="custom", input_strategy="head"), path)
    assert changed._data == {}


@pytest.mark.parametrize("ranges", [((1, 0),), ((0, 20),), ((0, 5), (4, 8)), ((False, 3),)])
def test_coverage_rejects_invalid_or_overlapping_ranges(ranges):
    with pytest.raises(ValueError):
        TextCoverage("head", 10, ranges)
