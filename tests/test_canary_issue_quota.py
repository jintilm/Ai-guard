"""`POST /v1/canary/issue` 的配额与留痕（AGENTS.md 仍未修清单第 2 项）。

这个端点**明文返回完整令牌**（它必须把值交给调用方去埋进 system prompt），
而此前它既不限流、也不留任何记录：

- 不限流 ⇒ 未鉴权部署时谁都能签走令牌，签发次数还是攻击者可控的
  （注册表内存与热路径已有界，但「令牌是谁的」没人知道）
- 不留痕 ⇒ 出了泄漏只能靠猜：日志里没有任何「谁在什么时候签了多少」的记录

本文件钉三件事：按身份分桶的配额、签发落审计且**不含完整令牌**、
以及 `/v1/metrics` 能看到签发计数与配额配置。
"""
from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

from prompt_ids.api.app import ApiContext, handle_canary_issue, handle_metrics
from prompt_ids.audit.logger import AuditLogger
from prompt_ids.canary.tokens import CanaryRegistry, mask_token


def _events(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()]


# ------------------------------------------------------------ 配额
def _serve(ctx: ApiContext, **config_kwargs):
    from prompt_ids.api.server import ApiServerConfig, create_api_server

    config = ApiServerConfig(port=0, **config_kwargs)
    ctx.canary_issue_limit = config.canary_issue_limit
    ctx.canary_issue_window_s = config.canary_issue_window_s
    httpd = create_api_server(ctx, config)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, config


def _post_issue(port: int, label: str = "t") -> tuple[int, bytes]:
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}/v1/canary/issue",
        data=json.dumps({"label": label}).encode(),
        method="POST", headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def test_issue_is_rate_limited_by_default():
    """默认就该有配额 —— 这个端点明文发令牌，默认关等于默认没有防护。"""
    ctx = ApiContext(canary=CanaryRegistry())
    httpd, config = _serve(ctx)
    try:
        assert config.canary_issue_limiter is not None, "默认必须有配额"
        assert config.canary_issue_limit == 30
        codes = [_post_issue(httpd.server_address[1])[0] for _ in range(32)]
        assert codes[:30] == [200] * 30, codes[:5]
        assert codes[30:] == [429, 429], f"配额没生效：{codes[28:]}"
        _status, body = _post_issue(httpd.server_address[1])
        assert json.loads(body)["error"]["code"] == "canary_issue_rate_limited"
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_issue_quota_is_independent_from_the_general_rate_limit():
    """两个桶必须分开：共用的话 issue 要么占普通请求额度、要么整体额度被抬到几百。"""
    ctx = ApiContext(canary=CanaryRegistry())
    httpd, _config = _serve(ctx, rate_limit=1000, canary_issue_limit=3)
    try:
        # 普通检测请求不受 issue 配额影响
        for _ in range(10):
            request = urllib.request.Request(
                f"http://127.0.0.1:{httpd.server_address[1]}/v1/scan",
                data=json.dumps({"text": "你好"}).encode(),
                method="POST", headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(request, timeout=15) as response:
                assert response.status == 200
        assert [_post_issue(httpd.server_address[1])[0] for _ in range(4)] \
            == [200, 200, 200, 429]
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_issue_quota_can_be_disabled_explicitly():
    """自动化测试要高频签发时得有出口（显式 0），但不能靠「默认关」实现。"""
    ctx = ApiContext(canary=CanaryRegistry())
    httpd, config = _serve(ctx, canary_issue_limit=0)
    try:
        assert config.canary_issue_limiter is None
        codes = [_post_issue(httpd.server_address[1])[0] for _ in range(40)]
        assert set(codes) == {200}, "显式关闭后不该有限流"
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_issue_quota_is_keyed_by_verified_identity_not_request_header():
    """分桶键不能是请求头里的 Key —— 未鉴权时换个 header 就是一个新桶。"""
    ctx = ApiContext(canary=CanaryRegistry())
    httpd, _config = _serve(ctx, canary_issue_limit=2)   # 未鉴权
    try:
        port = httpd.server_address[1]
        codes = []
        for i in range(3):
            request = urllib.request.Request(
                f"http://127.0.0.1:{port}/v1/canary/issue",
                data=json.dumps({"label": "t"}).encode(), method="POST",
                headers={"Content-Type": "application/json",
                         # 每次换 header：若拿它当分桶键，配额就形同虚设
                         "X-API-Key": f"spoof-{i}"})
            try:
                with urllib.request.urlopen(request, timeout=15) as response:
                    codes.append(response.status)
            except urllib.error.HTTPError as exc:
                codes.append(exc.code)
                exc.read()
        assert codes == [200, 200, 429], f"换请求头就能绕过配额：{codes}"
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_client_id_uses_the_verified_key_when_auth_is_on():
    """鉴权开启时，分桶键是**配置里那个** Key，不是请求头里来的值。"""
    from prompt_ids.api.server import ApiHandler, ApiServerConfig

    config = ApiServerConfig(port=0, api_key="configured-key")
    assert config.auth_required

    class _Fake(ApiHandler):
        def __init__(self):  # 绕开 socket，只测分桶键的选取
            self.config = config
            self.headers = {"X-API-Key": "whatever-client-sent"}
            self.client_address = ("10.0.0.9", 5555)

    assert _Fake()._client_id() == "key:configured-key"
    # 未鉴权时只能按来源 IP —— 此时请求头里的任何 Key 都不作数
    open_config = ApiServerConfig(port=0)
    assert not open_config.auth_required

    class _FakeOpen(_Fake):
        def __init__(self):
            self.config = open_config
            self.headers = {"X-API-Key": "spoof"}
            self.client_address = ("10.0.0.9", 5555)

    assert _FakeOpen()._client_id() == "ip:10.0.0.9"


# ------------------------------------------------------------ 留痕
def test_issue_is_audited_without_the_full_token(tmp_path):
    """签发必须留痕，但**只落脱敏令牌** —— 审计文件不能成为第二个泄露源。"""
    audit_path = tmp_path / "audit.jsonl"
    ctx = ApiContext(canary=CanaryRegistry(), audit=AuditLogger(str(audit_path)))
    try:
        _status, body = handle_canary_issue(ctx, {"label": "prod"}, {})
        token = body["token"]
        assert ctx.audit is not None
        ctx.audit.flush()
        events = _events(audit_path)
        issued = [e for e in events if e["kind"] == "canary"]
        assert len(issued) == 1, f"签发没有落审计：{[e['kind'] for e in events]}"
        assert issued[0]["extra"]["label"] == "prod"
        assert token not in json.dumps(issued[0], ensure_ascii=False), \
            "审计里出现了完整令牌"
        assert issued[0]["extra"]["token"] == mask_token(token)
    finally:
        if ctx.audit:
            ctx.audit.flush()


def test_issue_response_reports_the_retention_window():
    """回显保留窗口：不回显的话调用方会以为「签了就有用」，而退役窗口之外不匹配。"""
    ctx = ApiContext(canary=CanaryRegistry())
    before = len(ctx.canary)
    _status, body = handle_canary_issue(ctx, {}, {})
    retention = body["retention"]
    assert retention["max_tokens"] == ctx.canary.max_tokens
    assert retention["max_retired"] == ctx.canary.max_retired
    # 注册表构造时就自动签了一个，所以是「+1」而不是「= 1」
    assert retention["tokens_known"] == before + 1


def test_mask_token_is_the_single_masking_rule():
    """掩码规则只能有一份 —— 两处各写一份迟早漂成不同的泄露宽度。"""
    import inspect

    from prompt_ids.canary import tokens as mod

    source = inspect.getsource(mod.CanaryMatch.redacted_token)
    assert "mask_token" in source, "CanaryMatch 绕过了统一实现"
    assert mask_token("short") == "shor…"
    long = "pfx-0123456789abcdefghij-end"
    assert mask_token(long) == long[:8] + "…" + long[-4:]
    assert long not in mask_token(long)


# ------------------------------------------------------------ 指标
def test_metrics_show_issue_count_and_quota():
    ctx = ApiContext(canary=CanaryRegistry(), canary_issue_limit=30,
                     canary_issue_window_s=60.0)
    for _ in range(3):
        handle_canary_issue(ctx, {"label": "a"}, {})
    handle_canary_issue(ctx, {"label": "b"}, {})
    _status, body = handle_metrics(ctx, None, {})
    assert body["stats"]["canary_issues"] == 4
    assert body["stats"]["canary_issue:a"] == 3
    assert body["canary_issue_limit"] == {"limit": 30, "window_s": 60.0}
    assert body["canary"]["max_tokens"] > 0
