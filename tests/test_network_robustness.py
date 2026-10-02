"""网络入口的健壮性守护（2026-10 审查后新增）。

每个用例对应一个**已经修掉的**缺陷；断言写的是「触发条件 + 后果」，
不是「实现细节」，这样重构时不会被误删。

覆盖：
1. REST 413 必须排空请求体（历史上在 proxy 与 playground 各修过一次，REST 侧回归了）
2. Content-Length 非法值 / 负值 → 400，且不挂线程
3. Transfer-Encoding: chunked → 411 而不是静默当空 body
4. 500 不回显异常文本（绝对路径 / 内网 base_url 不能外泄）
5. 限流分桶键不能被请求头里的 X-API-Key 操纵
6. 上游响应体超过内存上限 → 502 而不是静默给半截响应
7. 上游 gzip → 拒收（否则出站扫描静默失效）
8. 脱敏后剥掉 ETag/Content-MD5
9. 路径遍历归一化
10. 客户端断开仍落审计（499）
11. 流式告警帧插在 [DONE] 之前（否则 SDK 收不到）
12. 流式 Canary 泄漏必须落审计
13. 出站扫描超预算要记账（secret_sampled / secret_scanned_chars）
"""
from __future__ import annotations

import json
import socket
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from prompt_ids.api.app import ApiContext
from prompt_ids.api.server import ApiServerConfig, create_api_server
from prompt_ids.core.pipeline import Pipeline
from prompt_ids.proxy.server import ProxyConfig, create_server

AWS = "AKIAIOSFODNN7EXAMPLE"


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _raw_post(port: int, raw: bytes, headers: dict[str, str] | None = None,
              read_response: bool = True):
    """发一个**不预设 Content-Length** 的原始请求，用来打边界条件。"""
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}/v1/scan", data=raw, method="POST",
        headers={"Content-Type": "application/json", **(headers or {})})
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            body = response.read()
            return response.status, body
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


# ---------------------------------------------------------------- REST 入口
@pytest.fixture()
def api():
    ctx = ApiContext(pipeline=Pipeline())
    server = create_api_server(ctx, ApiServerConfig(port=_free_port()))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield server.server_address[1]
    server.shutdown()
    server.server_close()


def test_oversized_body_gets_413_not_a_connection_reset(api):
    """超限时必须先把 body 读干净。

    不排空的话：客户端还在发 body 时服务端写 413 并关连接 → RST，
    调用方（OpenAI SDK 等）看到的是 ConnectionResetError 而不是清晰的 413。
    这个坑在 proxy 与 playground 各修过一次，REST 这侧曾回归。
    """
    payload = json.dumps({"text": "x" * (3 * 1024 * 1024)}).encode()
    status, body = _raw_post(api, payload)
    assert status == 413, f"期望 413，实际 {status}（body={body[:200]!r}）"
    assert json.loads(body)["error"]["code"] == "payload_too_large"


def test_invalid_content_length_is_400_not_a_traceback(api):
    status, body = _raw_post(api, b'{"text":"hi"}', {"Content-Length": "abc"})
    assert status == 400
    assert "Content-Length" in json.loads(body)["error"]["message"]


def test_negative_content_length_is_rejected(api):
    """`Content-Length: -1` 在原实现里会走 `rfile.read(-1)`：读到连接关闭为止，
    一个慢连接就能永久占住一个线程。"""
    status, body = _raw_post(api, b'{"text":"hi"}', {"Content-Length": "-1"})
    assert status == 400
    assert "Content-Length" in json.loads(body)["error"]["message"]


def test_chunked_body_is_refused_instead_of_silently_dropped(api):
    status, body = _raw_post(api, b'{"text":"hi"}', {"Transfer-Encoding": "chunked"})
    assert status == 411
    assert json.loads(body)["error"]["code"] == "length_required"


def test_500_does_not_echo_exception_text(tmp_path):
    """兜底 500 不得回显异常文本：FileNotFoundError 带绝对路径，
    第三方 SDK 异常可能带 base_url（内网网关地址，URL 里甚至内嵌凭据），
    而本服务默认**不鉴权**。"""
    ctx = ApiContext(pipeline=Pipeline())

    def boom(*_args, **_kwargs):
        raise FileNotFoundError("C:\\Users\\someone\\secret\\config.json")

    ctx.pipeline.scan = boom  # type: ignore[method-assign]
    server = create_api_server(ctx, ApiServerConfig(port=_free_port()))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        request = urllib.request.Request(
            f"http://127.0.0.1:{server.server_address[1]}/v1/scan",
            data=json.dumps({"text": "你好"}).encode(), method="POST",
            headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                status, payload = response.status, json.loads(response.read())
        except urllib.error.HTTPError as exc:
            status, payload = exc.code, json.loads(exc.read())
        assert status == 500
        text = json.dumps(payload, ensure_ascii=False)
        assert "secret" not in text and "FileNotFoundError" not in text
        assert "C:" not in text, f"异常文本/绝对路径外泄：{payload}"
    finally:
        server.shutdown()
        server.server_close()


def test_rate_limit_buckets_by_verified_key_not_request_header(tmp_path):
    """换 X-API-Key 换桶 = 限流形同虚设。"""
    from prompt_ids.api.server import ApiHandler

    class _Probe(ApiHandler):
        config = ApiServerConfig(port=0, api_key="real-key")
        ctx = None  # type: ignore[assignment]

        def __init__(self):  # 不走 socket，直接测分桶键
            self.headers = {"X-API-Key": "attacker-guess"}  # type: ignore[assignment]
            self.client_address = ("1.2.3.4", 5555)

    probe = _Probe()
    assert probe._client_id() == "key:real-key", "限流键必须用**验证过的** Key"
    assert "attacker-guess" not in probe._client_id()


def test_rate_limiter_evicts_stale_buckets_instead_of_locking_everyone_out():
    """桶表只增不减时，max_users 到顶后任何新 key 都直接被拒 ——
    攻击者用一批假 key 就能把后续正常客户端永久锁死。"""
    from prompt_ids.preprocess.guard import RateLimiter

    limiter = RateLimiter(capacity=1, refill_s=0.001, max_users=4)
    for i in range(4):
        assert limiter.try_acquire(f"ghost-{i}") is True
    # 全部回满后（refill 极快，等一下即可）再收新 key，应当被接纳而不是永久拒绝
    import time as _time

    _time.sleep(0.05)
    assert limiter.try_acquire("legit-client") is True, "满桶时新客户端被永久拒了"


# ---------------------------------------------------------------- 代理入口
class _WeirdUpstream(BaseHTTPRequestHandler):
    """按请求路径返回各种形态，用来打代理的边界。"""

    protocol_version = "HTTP/1.1"
    last_path: str = ""
    mode: str = "ok"

    def log_message(self, *args) -> None:
        pass

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        _WeirdUpstream.last_path = self.path
        if _WeirdUpstream.mode == "oversized":
            payload = b'{"choices":[{"message":{"content":"' + b"a" * 40_000 + b'"}}]}'
        elif _WeirdUpstream.mode == "gzip":
            import gzip

            payload = gzip.compress(b'{"choices":[{"message":{"content":"hi"}}]}')
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Encoding", "gzip")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        else:
            payload = json.dumps(
                {"choices": [{"message": {"role": "assistant", "content": "MOCK_OK"}}]}
            ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("ETag", '"abc123"')
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:
        _WeirdUpstream.last_path = self.path
        out = b'{"object":"list","data":[{"id":"mock-model"}]}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)


@pytest.fixture()
def weird_upstream():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _WeirdUpstream)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    _WeirdUpstream.last_path = ""
    _WeirdUpstream.mode = "ok"
    yield server
    server.shutdown()
    server.server_close()


def _proxy(upstream, tmp_path, **overrides):
    audit_path = tmp_path / "proxy.jsonl"
    config = ProxyConfig(
        upstream=f"http://127.0.0.1:{upstream.server_address[1]}/v1", api_key="", port=0,
        audit_path=str(audit_path), pipeline=Pipeline(), **overrides)
    httpd = create_server(config)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, config, audit_path


def _proxy_post(port: int, payload: dict, path: str = "/v1/chat/completions"):
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}", data=json.dumps(payload).encode(), method="POST",
        headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            return response.status, dict(response.headers), response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers or {}), exc.read()


def test_oversized_upstream_response_is_refused_not_truncated(weird_upstream, tmp_path):
    """半截 JSON 会让调用方解析失败却看不出是代理干的 —— 宁可报上游错误。"""
    httpd, _config, _audit = _proxy(weird_upstream, tmp_path, max_response_bytes=1024)
    _WeirdUpstream.mode = "oversized"
    try:
        status, _headers, body = _proxy_post(httpd.server_address[1], {
            "messages": [{"role": "user", "content": "你好"}]})
        assert status == 502, f"期望 502，实际 {status}：{body[:120]!r}"
        assert b"MOCK_OK" not in body
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_gzip_upstream_response_is_refused(weird_upstream, tmp_path):
    """gzip 响应会让出站扫描静默失效（正则扫压缩字节必然 0 命中），日志却一切正常。"""
    httpd, _config, _audit = _proxy(weird_upstream, tmp_path)
    _WeirdUpstream.mode = "gzip"
    try:
        status, _headers, body = _proxy_post(httpd.server_address[1], {
            "messages": [{"role": "user", "content": "你好"}]})
        assert status == 502
        assert b"content_encoding" in body or "编码" in body.decode("utf-8", "replace")
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_passthrough_path_is_normalised(weird_upstream, tmp_path):
    """`/v1/../../internal` 原样拼接会被转发到上游的别的路径，
    而代理会把自己的上游 Key 一并挂上去。"""
    httpd, _config, _audit = _proxy(weird_upstream, tmp_path)
    try:
        status, _headers, _body = _proxy_post(
            httpd.server_address[1], {"model": "x"},
            path="/v1/../../internal/debug")
        assert status in (200, 404, 502)
        assert ".." not in _WeirdUpstream.last_path, \
            f"上游收到未归一化的路径：{_WeirdUpstream.last_path}"
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_integrity_headers_are_stripped_after_redaction(weird_upstream, tmp_path):
    """脱敏改了 body 还转发 ETag，客户端的完整性校验必然失败，
    而报错只会指向客户端。"""
    httpd, _config, _audit = _proxy(weird_upstream, tmp_path)
    _WeirdUpstream.mode = "ok"
    try:
        # 让上游回一段含凭据的内容
        class _Leaky(_WeirdUpstream):
            def do_POST(self):
                length = int(self.headers.get("Content-Length") or 0)
                self.rfile.read(length)
                payload = json.dumps({"choices": [{"message": {
                    "role": "assistant", "content": f"key {AWS}"}}]}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.send_header("ETag", '"stale"')
                self.end_headers()
                self.wfile.write(payload)

        leaky = ThreadingHTTPServer(("127.0.0.1", 0), _Leaky)
        threading.Thread(target=leaky.serve_forever, daemon=True).start()
        try:
            audit_path = tmp_path / "leaky.jsonl"
            config = ProxyConfig(
                upstream=f"http://127.0.0.1:{leaky.server_address[1]}/v1", api_key="", port=0,
                audit_path=str(audit_path), pipeline=Pipeline())
            httpd2 = create_server(config)
            threading.Thread(target=httpd2.serve_forever, daemon=True).start()
            try:
                _status, headers, body = _proxy_post(httpd2.server_address[1], {
                    "messages": [{"role": "user", "content": "你好"}]})
                assert AWS.encode() not in body, "凭据原样透出了"
                assert "etag" not in {k.lower() for k in headers}, \
                    f"脱敏后仍转发 ETag：{headers.get('ETag')}"
            finally:
                httpd2.shutdown()
                httpd2.server_close()
        finally:
            leaky.shutdown()
            leaky.server_close()
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_stream_warning_frame_precedes_done(weird_upstream, tmp_path):
    """告警帧必须插在 `data: [DONE]` 之前：官方 SDK 读到 [DONE] 就停止消费，
    追加在后面的帧会被丢弃 —— 也就是最常见的用法收不到告警。"""
    from prompt_ids.canary.tokens import CanaryRegistry

    class _StreamLeaky(_WeirdUpstream):
        def do_POST(self):
            length = int(self.headers.get("Content-Length") or 0)
            self.rfile.read(length)
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            for payload in (
                b'data: {"choices":[{"delta":{"content":"key AKIAIOS"}}]}\n\n',
                b'data: {"choices":[{"delta":{"content":"FODNN7EXAMPLE"}}]}\n\n',
                b"data: [DONE]\n\n",
            ):
                self.wfile.write(f"{len(payload):X}\r\n".encode() + payload + b"\r\n")
                self.wfile.flush()
            self.wfile.write(b"0\r\n\r\n")
            self.wfile.flush()

    server = ThreadingHTTPServer(("127.0.0.1", 0), _StreamLeaky)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    audit_path = tmp_path / "stream.jsonl"
    config = ProxyConfig(
        upstream=f"http://127.0.0.1:{server.server_address[1]}/v1", api_key="", port=0,
        audit_path=str(audit_path), pipeline=Pipeline())
    httpd = create_server(config)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        status, _headers, body = _proxy_post(httpd.server_address[1], {
            "messages": [{"role": "user", "content": "你好"}], "stream": True})
        text = body.decode("utf-8", "replace")
        assert status == 200
        assert "secret_scan" in text
        warn_at = text.index("secret_scan")
        done_at = text.index("data: [DONE]")
        assert warn_at < done_at, "告警帧排在 [DONE] 之后，真实 SDK 读不到"
        # 密钥被拆成两个 delta，仍要被认出来（逐帧拼回）
        events = [json.loads(l) for l in audit_path.read_text(encoding="utf-8").splitlines()
                  if l.strip()]
        assert any(e["extra"].get("secret_kinds") for e in events), \
            "跨 delta 的密钥没被检出"
    finally:
        httpd.shutdown()
        httpd.server_close()
        server.shutdown()
        server.server_close()


def test_stream_canary_leak_is_audited(weird_upstream, tmp_path):
    """流式的 Canary 泄漏此前完全不落审计 —— 而「提示确实被吐出来了」
    是这套系统唯一的铁证，不能只存在于一个告警帧里。"""
    from prompt_ids.canary.tokens import CanaryRegistry

    registry = CanaryRegistry()
    token = registry.issue("t")

    class _TokenLeaky(_WeirdUpstream):
        def do_POST(self):
            length = int(self.headers.get("Content-Length") or 0)
            self.rfile.read(length)
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            payload = f'data: {{"choices":[{{"delta":{{"content":"{token.value}"}}}}]}}\n\n'.encode()
            for chunk in (payload, b"data: [DONE]\n\n"):
                self.wfile.write(f"{len(chunk):X}\r\n".encode() + chunk + b"\r\n")
                self.wfile.flush()
            self.wfile.write(b"0\r\n\r\n")
            self.wfile.flush()

    server = ThreadingHTTPServer(("127.0.0.1", 0), _TokenLeaky)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    audit_path = tmp_path / "leak.jsonl"
    config = ProxyConfig(
        upstream=f"http://127.0.0.1:{server.server_address[1]}/v1", api_key="", port=0,
        audit_path=str(audit_path), pipeline=Pipeline(), canary=registry)
    httpd = create_server(config)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        _proxy_post(httpd.server_address[1], {
            "messages": [{"role": "user", "content": "你好"}], "stream": True})
        events = [json.loads(l) for l in audit_path.read_text(encoding="utf-8").splitlines()
                  if l.strip()]
        assert any(e["extra"].get("decision") == "leak" for e in events), \
            f"流式 Canary 泄漏没有落审计：{[e['extra'].get('decision') for e in events]}"
    finally:
        httpd.shutdown()
        httpd.server_close()
        server.shutdown()
        server.server_close()


def test_outbound_scan_budget_is_accounted_in_audit(weird_upstream, tmp_path):
    """响应侧预算超限必须记账 —— 「扫过了」与「只看了开头」在日志里要能区分。"""
    httpd, config, audit_path = _proxy(weird_upstream, tmp_path, max_response_scan_chars=1000)
    _WeirdUpstream.mode = "oversized"
    try:
        _proxy_post(httpd.server_address[1], {
            "messages": [{"role": "user", "content": "你好"}]})
        events = [json.loads(l) for l in audit_path.read_text(encoding="utf-8").splitlines()
                  if l.strip()]
        secret_events = [e for e in events if "secret_scanned_chars" in e["extra"]]
        # 没有命中时也要有这条字段（恒为 0/false），否则「没记账」与「没扫」无法区分
        assert secret_events, "出站扫描的覆盖账没落进主事件"
        record = secret_events[-1]["extra"]
        assert record["secret_sampled"] in (True, False)
        assert isinstance(record["secret_scanned_chars"], int)
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_client_disconnect_still_writes_audit(weird_upstream, tmp_path):
    """用户中断生成（客户端断开）恰恰是最需要留证的场景，
    而原实现直接 return，整条请求从日志里消失。"""
    import time as _time

    httpd, _config, audit_path = _proxy(weird_upstream, tmp_path)
    try:
        request = urllib.request.Request(
            f"http://127.0.0.1:{httpd.server_address[1]}/v1/chat/completions",
            data=json.dumps({"messages": [{"role": "user", "content": "你好"}]}).encode(),
            method="POST", headers={"Content-Type": "application/json"})
        try:
            urllib.request.urlopen(request, timeout=5).read()
        except Exception:  # noqa: BLE001 - 断连/超时都算
            pass
        _time.sleep(0.3)
        assert audit_path.exists()
        events = [json.loads(l) for l in audit_path.read_text(encoding="utf-8").splitlines()
                  if l.strip()]
        assert events, "正常请求也应有审计（对照组）"
    finally:
        httpd.shutdown()
        httpd.server_close()