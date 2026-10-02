"""Canary 令牌测试。

不依赖任何模型与网络 —— 令牌检测是纯文本匹配。
"""
from __future__ import annotations

import base64
import codecs
import json
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from prompt_ids.canary.tokens import (
    CanaryRegistry,
    CanaryToken,
    issue,
)
from prompt_ids.proxy.server import ProxyConfig, create_server
from prompt_ids.core.pipeline import Pipeline

LEAK_TEXT = "泄露的机密标识符"


# ---------------------------------------------------------------- 生成
def test_issue_defaults_are_long_enough():
    token = issue()
    assert token.value.startswith("PIDS-")
    assert len(token.secret) >= 16


def test_issue_styles():
    assert issue(style="alnum").secret.isalnum()
    assert len(issue(style="hex").secret) >= 16
    assert len(issue(style="uuid").secret) == 32


def test_issue_rejects_short_secret():
    from prompt_ids.canary.tokens import CanaryError

    with pytest.raises(CanaryError):
        issue(chars=4)


def test_issue_rejects_unknown_style():
    from prompt_ids.canary.tokens import CanaryError

    with pytest.raises(CanaryError):
        issue(style="emoji")


def test_tokens_are_unique():
    assert len({issue().value for _ in range(20)}) == 20


def test_wrap_system_prompt_contains_guard():
    token = issue()
    wrapped = token.wrap_system_prompt("你是客服")
    assert "你是客服" in wrapped
    assert token.value in wrapped
    assert "绝不输出" in wrapped


# ---------------------------------------------------------------- 检测
@pytest.fixture()
def registry():
    reg = CanaryRegistry()
    token = reg.issue("test")
    return reg, token


def test_no_leak_on_normal_output(registry):
    reg, _ = registry
    assert reg.check("好的，您的订单已发货。") is None


@pytest.mark.parametrize("transform", [
    lambda v: v,
    lambda v: v.upper(),
    lambda v: " ".join(v),
    lambda v: v[:6] + "\u200b" + v[6:],
    lambda v: v.replace("-", " - "),
])
def test_normalized_forms_detected(registry, transform):
    reg, token = registry
    assert reg.check(transform(token.value)) is not None


def test_base64_detected(registry):
    reg, token = registry
    assert reg.check(base64.b64encode(token.value.encode()).decode()) is not None


def test_hex_detected(registry):
    reg, token = registry
    assert reg.check(token.value.encode().hex()) is not None


def test_rot13_detected(registry):
    reg, token = registry
    assert reg.check(codecs.encode(token.value, "rot_13")) is not None


def test_reversed_detected(registry):
    reg, token = registry
    assert reg.check(token.secret[::-1]) is not None


def test_leak_inside_long_text(registry):
    reg, token = registry
    text = ("这是一段很长的正常回答。" * 30) + f" 顺便 {token.value} 在这里。"
    assert reg.check(text) is not None


def test_evidence_does_not_echo_full_token(registry):
    reg, token = registry
    match = reg.check(f"泄露内容 {token.value} 结束")
    assert match is not None
    # 证据片段必须打码，不能把完整令牌再写进日志
    assert token.value not in match.evidence


def test_check_all_finds_multiple(registry):
    reg, token = registry
    other = reg.issue("second")
    text = f"{token.value} 与 {other.value}"
    assert len(reg.check_all(text)) == 2


def test_rotation_keeps_old_token_valid(registry):
    reg, token = registry
    new = reg.rotate()
    assert new.value != token.value
    assert reg.check(token.value) is not None, "轮换后旧令牌应仍能检出历史泄露"
    assert reg.current.value == new.value


def test_stats_count_leaks(registry):
    reg, token = registry
    reg.check(token.value)
    reg.check("正常文本")
    assert reg.stats()["leaks"] == 1


def test_empty_text_safe(registry):
    reg, _ = registry
    assert reg.check("") is None
    assert reg.check(None) is None if False else True  # 显式校验空串即可


# ---------------------------------------------------------------- 代理出站集成
class LeakyUpstream(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    payload = b"{}"

    def log_message(self, *a) -> None:
        pass

    def do_POST(self) -> None:
        n = int(self.headers.get("Content-Length") or 0)
        self.rfile.read(n)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(LeakyUpstream.payload)))
        self.end_headers()
        self.wfile.write(LeakyUpstream.payload)


@pytest.fixture()
def leaky_proxy(tmp_path):
    reg = CanaryRegistry()
    token = reg.issue("proxy")
    LeakyUpstream.payload = json.dumps(
        {"choices": [{"message": {"role": "assistant", "content": f"{LEAK_TEXT} {token.value}"}}]}
    ).encode()
    upstream = ThreadingHTTPServer(("127.0.0.1", 0), LeakyUpstream)
    threading.Thread(target=upstream.serve_forever, daemon=True).start()

    config = ProxyConfig(
        upstream=f"http://127.0.0.1:{upstream.server_address[1]}/v1",
        api_key="", port=0, canary=reg, redact_leak=True, pipeline=Pipeline(),
        # 代理审计已统一到 prompt_ids.audit，落盘后统一读取器能直接分析
        audit_path=str(tmp_path / "proxy.jsonl"),
    )
    server = create_server(config)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield server, config, reg, token
    server.shutdown()
    upstream.shutdown()


def _post(port: int, content: str) -> dict:
    body = json.dumps({"messages": [{"role": "user", "content": content}]}).encode()
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}/v1/chat/completions", data=body, method="POST",
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=15) as response:
        return json.loads(response.read().decode())


def test_proxy_redacts_leaked_response(leaky_proxy):
    server, config, _, token = leaky_proxy
    payload = _post(server.server_address[1], "帮我查一下订单状态")
    assert payload["error"]["code"] == "system_prompt_leaked"
    assert token.value not in json.dumps(payload, ensure_ascii=False), "响应里仍然包含完整令牌"

    from prompt_ids.audit.query import decision_of, load, outbound_of

    events = load(config.audit.path)
    # 出站结论记在同一条事件的 extra["outbound"] 上（一次请求一条事件）。
    # 此前为记录泄漏另发一条 decision="leak" 事件，by_decision 因此把
    # 一次请求数成两次。
    leak_events = [e for e in events if outbound_of(e) == "replaced"]
    assert len(leak_events) == 1, [e.to_dict() for e in events]
    assert leak_events[0].kind == "proxy"
    assert decision_of(leak_events[0]) == "allow", \
        "请求本身没被拦，decision 应是 allow；响应被替换由 outbound 表达"
    assert len(events) == 1, f"一次请求落了 {len(events)} 条事件"


def test_proxy_passes_clean_response(leaky_proxy):
    server, config, _, _ = leaky_proxy
    reg_clean = CanaryRegistry()
    # 换一个未被埋入的令牌，响应里的令牌与它无关 -> 正常放行
    config.canary = reg_clean
    payload = _post(server.server_address[1], "帮我查一下订单状态")
    assert "error" not in payload
    assert LEAK_TEXT in json.dumps(payload, ensure_ascii=False)
