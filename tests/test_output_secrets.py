"""出站密钥扫描（prompt_ids/output/secrets.py）与代理接入的守护。

这一层是「输出侧检测」里 Canary 之外的那一半：Canary 只认自己埋的令牌，
而模型把 RAG 文档 / 代码上下文里的第三方凭据复述出来，Canary 一个都抓不到。
"""
from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from prompt_ids.core.pipeline import Pipeline
from prompt_ids.output import (
    MAX_HITS,
    SecretHit,
    redact,
    redact_bytes,
    scan_secrets,
    scan_text,
    summary,
)
from prompt_ids.proxy.server import ProxyConfig, create_server

AWS = "AKIAIOSFODNN7EXAMPLE"
SLACK = "xoxb-123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx"
JWT = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
       ".eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk")


# ---------------------------------------------------------------- 单元
@pytest.mark.parametrize("text,kind", [
    ("用的密钥是 AKIAIOSFODNN7EXAMPLE 谢谢", "aws_access_key"),
    ("sk-ant-api03-Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2RlZmdoamts", "anthropic_key"),
    ("sk-proj-T0pmaDEyMzQ1Njc4OTBhYmNkZWZnaGlqa2xtbm9wcXJz", "openai_key"),
    ("AIzaSyD-1234567890abcdefghijklmnopqrstu", "google_api_key"),
    (SLACK, "slack_token"),
    ("xapp-1-A012345678-1234567890123-abcdef", "slack_token"),
    ("ghp_1234567890abcdefghijklmnopqrstuvwxyzAB", "github_token"),
    ("glpat-ABCdef1234567890abcdef12", "gitlab_token"),
    ("-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----", "private_key"),
    (JWT, "jwt"),
    ("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9abcdefghijklmnop", "bearer_header"),
])
def test_structured_credentials_are_detected(text, kind):
    kinds = {h.kind for h in scan_secrets(text)}
    assert kind in kinds, f"{text[:30]!r} 未被判为 {kind}，实得 {kinds}"


def test_anthropic_key_wins_over_the_generic_openai_pattern():
    """`sk-ant-...` 同时满足 sk- 的宽模式，必须归到更具体的类别。"""
    hits = scan_secrets("sk-ant-api03-Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2RlZmdoamts")
    assert [h.kind for h in hits] == ["anthropic_key"]


@pytest.mark.parametrize("text", [
    "帮我写一段快速排序的 Python 代码",
    "AWS 访问密钥一般以 AKIA 开头，一共 20 个字符",
    "slack 机器人的 token 格式是 xoxb- 加一串字符",
    "我们的 JWT 用的是 HS256 算法",
    "-----BEGIN CERTIFICATE----- 不是私钥",
    "",
])
def test_ordinary_text_is_not_flagged(text):
    """描述凭据格式的话不该被当成凭据（否则文档问答会被大面积误杀）。"""
    assert scan_secrets(text) == []


def test_masked_never_reveals_the_secret():
    """审计与告警只用脱敏形态。"""
    hit = scan_secrets(f"key={AWS}")[0]
    masked = hit.masked()
    assert AWS not in masked
    assert len(masked) < len(AWS)
    assert masked.startswith("AKIA")


def test_redact_replaces_the_hit_with_a_kind_tag():
    text = f"这是 {AWS} 和 {SLACK}"
    hits = scan_secrets(text)
    out = redact(text, hits)
    assert AWS not in out and SLACK not in out
    assert "[REDACTED:aws_access_key]" in out
    assert "[REDACTED:slack_token]" in out


def test_redact_bytes_keeps_the_json_valid():
    """占位符必须能在响应体里就地替换，不能把 JSON 弄坏。"""
    payload = json.dumps({"choices": [{"message": {"content": f"key={AWS}"}}]}).encode()
    hits = scan_secrets(payload.decode())
    out = json.loads(redact_bytes(payload, hits).decode())
    assert AWS not in json.dumps(out)
    assert "[REDACTED:aws_access_key]" in out["choices"][0]["message"]["content"]


def test_redact_skips_a_hit_whose_offset_no_longer_applies():
    """文本被上层改过之后，旧的偏移量不能硬切（否则会削掉正常内容）。"""
    text = "12345 " + AWS
    hit = SecretHit("aws_access_key", 6, 6 + len(AWS), AWS)
    assert redact("12345 abcdefghij", [hit]) == "12345 abcdefghij"


def test_summary_counts_by_kind():
    assert summary(scan_secrets(f"{AWS} {AWS} {SLACK}")) == {
        "aws_access_key": 2, "slack_token": 1}


def test_hit_list_is_capped():
    text = " ".join(AWS + chr(65 + i) for i in range(40))
    assert len(scan_secrets(text, limit=5)) == 5


def test_hits_come_back_in_document_order():
    hits = scan_secrets(f"{SLACK} 然后是 {AWS}")
    assert [h.start for h in hits] == sorted(h.start for h in hits)


# ---------------------------------------------------------------- 代理接入
class LeakyUpstream(BaseHTTPRequestHandler):
    """假上游：把请求里最后一条用户消息原样当作模型输出吐回来。

    于是「模型把文档里的密钥复述出来」这件事可以用普通请求构造出来，
    不需要真的调 LLM。
    """

    protocol_version = "HTTP/1.1"

    def log_message(self, *args) -> None:
        pass

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        payload = json.loads(body.decode("utf-8"))
        echoed = ""
        tool_mode = False
        for message in payload.get("messages", []) or []:
            if isinstance(message, dict) and message.get("role") == "user":
                content = message.get("content")
                if isinstance(content, str):
                    echoed = content
                    tool_mode = content.startswith("__TOOLCALL__")
        if tool_mode:
            # 凭据出现在 tool_calls 的参数里，不在 message.content 里 ——
            # 「让 agent 把密钥写进配置文件」走的就是这条路。
            arguments = json.dumps({"path": "config.py", "body": f"KEY = {AWS}"})
            out = json.dumps({"choices": [{"message": {"role": "assistant", "content": None,
                                                       "tool_calls": [
                    {"function": {"name": "write_file", "arguments": arguments}}]}}]}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(out)))
            self.end_headers()
            self.wfile.write(out)
            return
        if payload.get("stream"):
            half = len(echoed) // 2
            chunks = [
                f'data: {{"choices":[{{"delta":{{"content":{json.dumps(echoed[:half])}}}}}]}}\n\n'.encode(),
                f'data: {{"choices":[{{"delta":{{"content":{json.dumps(echoed[half:])}}}}}]}}\n\n'.encode(),
                b"data: [DONE]\n\n",
            ]
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            for chunk in chunks:
                self.wfile.write(f"{len(chunk):X}\r\n".encode() + chunk + b"\r\n")
            self.wfile.write(b"0\r\n\r\n")
            self.wfile.flush()
            return
        out = json.dumps(
            {"choices": [{"message": {"role": "assistant", "content": echoed}}]}
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)


@pytest.fixture(scope="module")
def leaky_upstream():
    server = ThreadingHTTPServer(("127.0.0.1", 0), LeakyUpstream)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()
    server.server_close()


def _proxy_for(server, tmp_path_factory, name="secrets", **overrides):
    base = f"http://127.0.0.1:{server.server_address[1]}/v1"
    audit_path = tmp_path_factory.mktemp(name) / "proxy.jsonl"
    config = ProxyConfig(upstream=base, api_key="", port=0,
                         audit_path=str(audit_path), pipeline=Pipeline(), **overrides)
    httpd = create_server(config)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd, audit_path


def _post(port, payload):
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}/v1/chat/completions",
        data=json.dumps(payload).encode(), method="POST",
        headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def _events(audit_path):
    raw = audit_path.read_text(encoding="utf-8")
    return [json.loads(line) for line in raw.splitlines() if line.strip()]


def test_secret_in_output_is_redacted_before_it_reaches_the_client(leaky_upstream, tmp_path_factory):
    httpd, audit_path = _proxy_for(leaky_upstream, tmp_path_factory)
    try:
        content = f"根据文档，您的访问密钥是 {AWS}"
        status, body = _post(httpd.server_address[1], {
            "messages": [{"role": "system", "content": "你是助手"},
                         {"role": "user", "content": content}]})
        assert status == 200
        text = body.decode()
        assert AWS not in text, "凭据原样透给了客户端"
        assert "[REDACTED:aws_access_key]" in text
        # 响应其余部分必须保持原样，不能因为替换把 JSON 弄坏
        assert json.loads(text)["choices"][0]["message"]["content"].startswith("根据文档")
        events = _events(audit_path)
        secret_events = [e for e in events if e["extra"].get("decision") == "redact_secrets"]
        assert secret_events, "脱敏了却没落审计"
        assert secret_events[-1]["extra"]["secret_kinds"] == {"aws_access_key": 1}
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_secret_in_tool_call_arguments_is_also_redacted(leaky_upstream, tmp_path_factory):
    """凭据最常漏出去的地方是 tool_calls 参数（agent 写文件），不是 message.content。

    同时钉住一个实现细节：脱敏是按偏移就地替换，所以扫描的字符串必须与被切的
    字符串同源。早先版本扫的是 _response_text() 抽出来的 content，
    偏移对不上原始响应体，redact 的自我保护直接跳过了替换 —— 静默不生效。
    """
    httpd, audit_path = _proxy_for(leaky_upstream, tmp_path_factory, "tool")
    try:
        status, body = _post(httpd.server_address[1], {"messages": [
            {"role": "user", "content": "__TOOLCALL__ 把密钥写进配置文件"}]})
        assert status == 200
        text = body.decode()
        assert AWS not in text
        assert "[REDACTED:aws_access_key]" in text
        # 替换必须落在参数里，其余字段保持原样
        payload = json.loads(text)
        arguments = payload["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"]
        assert "[REDACTED:aws_access_key]" in arguments
        assert "config.py" in arguments
        events = _events(audit_path)
        assert [e for e in events if e["extra"].get("decision") == "redact_secrets"]
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_audit_never_contains_the_secret_itself(leaky_upstream, tmp_path_factory):
    """脱敏了响应还不够 —— 审计文件里出现密钥等于凭空多一个泄露面。"""
    httpd, audit_path = _proxy_for(leaky_upstream, tmp_path_factory, "audit")
    try:
        _post(httpd.server_address[1], {"messages": [
            {"role": "user", "content": f"key {AWS} {SLACK}"}]})
    finally:
        httpd.shutdown()
        httpd.server_close()
    raw = audit_path.read_text(encoding="utf-8")
    assert AWS not in raw and SLACK not in raw


def test_clean_output_is_forwarded_untouched(leaky_upstream, tmp_path_factory):
    httpd, audit_path = _proxy_for(leaky_upstream, tmp_path_factory, "clean")
    try:
        status, body = _post(httpd.server_address[1], {"messages": [
            {"role": "user", "content": "AWS 密钥以 AKIA 开头"}]})
        assert status == 200
        assert b"REDACTED" not in body
        events = _events(audit_path)
        assert not [e for e in events if e["extra"].get("secret_kinds")]
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_scan_can_be_turned_off(leaky_upstream, tmp_path_factory):
    httpd, _ = _proxy_for(leaky_upstream, tmp_path_factory, "off", scan_secrets=False)
    try:
        _, body = _post(httpd.server_address[1], {"messages": [
            {"role": "user", "content": f"key {AWS}"}]})
        assert AWS in body.decode()
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_env_switch_overrides_the_default(leaky_upstream, tmp_path_factory, monkeypatch):
    monkeypatch.setenv("PROMPT_IDS_PROXY_SCAN_SECRETS", "0")
    httpd, _ = _proxy_for(leaky_upstream, tmp_path_factory, "env")
    try:
        _, body = _post(httpd.server_address[1], {"messages": [
            {"role": "user", "content": f"key {AWS}"}]})
        assert AWS in body.decode(), "环境变量没能关掉出站密钥扫描"
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_default_is_on():
    assert ProxyConfig(upstream="http://x/v1", api_key="").scan_secrets is True


# ---------------------------------------------------------------- 三条正则纪律
def test_jwt_pattern_is_linear_on_repeated_prefix_input():
    """`[A-Za-z0-9_-]{n,}` 后接必需分隔符 = O(L²)。

    字符类含 `-`（不是 \\w），所以 `-eyJ` 重复串里**每个** `eyJ` 都是候选起点，
    每点回溯一遍整条 run。初版无界 `{8,}`：8KB 14ms / 64KB 867ms / 256KB 14.0 秒
    —— 而代理对**响应体**没有任何上限，且响应内容可被间接注入影响。
    改成有界 `{7,64}/{7,512}` 后同一输入 10.7ms（线性）。
    """
    import time

    for size in (16_000, 64_000):
        text = "-eyJ" * (size // 4)
        start = time.perf_counter()
        assert scan_secrets(text) == []
        elapsed_ms = (time.perf_counter() - start) * 1000
        # 线性 ⇒ 每翻一倍约 2 倍。留足余量仍能抓住平方级（那会是 4 倍）。
        budget = {16_000: 60.0, 64_000: 150.0}[size]
        assert elapsed_ms < budget, f"{size} 字符耗时 {elapsed_ms:.1f}ms，超过 {budget}ms"


def test_long_real_jwt_is_still_detected():
    """收窄段长不能让真 JWT 漏掉：RS256 签名段 base64 后 342 字符。"""
    token = ("eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLCJleHAiOjE3MDAwMDAwMDB9." + "A" * 342)
    assert "jwt" in {h.kind for h in scan_secrets(token)}


def test_every_pattern_is_scanned_even_after_the_report_cap_is_hit():
    """上报上限不能变成扫描上限。

    初版用 MAX_HITS 截断命中列表**并**提前 break 掉后续模式：
    「20 个 AWS key + 一份私钥」里私钥根本没被扫，审计却写「已脱敏」。
    """
    many = " ".join("AKIA" + chr(66 + i) * 16 for i in range(40))
    text = many + "\n-----BEGIN RSA PRIVATE KEY-----\nMIIEabc\n-----END RSA PRIVATE KEY-----"
    scan = scan_text(text)
    assert len(scan) > MAX_HITS, "构造的样本应当超过上报上限"
    assert "private_key" in scan.by_kind, "私钥模式根本没被跑到"
    assert "private_key" in {h.kind for h in scan.reported(MAX_HITS)}, "上报条数应被截到上限"
    out = redact(text, scan)
    assert "BEGIN RSA PRIVATE KEY" not in out


def test_private_key_body_is_redacted_too():
    """只吃 BEGIN 头 = 私钥正文原样透出（初版就是这样）。"""
    body = "\n".join("MIIE" + "A" * 60 for _ in range(12))
    key = f"-----BEGIN RSA PRIVATE KEY-----\n{body}\n-----END RSA PRIVATE KEY-----"
    out = redact(key, scan_text(key).hits)
    assert out == "[REDACTED:private_key]"
    assert "MIIE" not in out


def test_truncated_private_key_paste_is_still_caught():
    """被截断粘贴的密钥片段也要能识别（END 段可选）。"""
    partial = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA"
    assert "private_key" in {h.kind for h in scan_secrets(partial)}


def test_by_kind_counts_survive_the_report_cap():
    """by_kind 是全量计数，不受上报上限影响 —— 审计靠它记账。"""
    text = " ".join("AKIA" + "A" * 16 for _ in range(30))
    scan = scan_text(text)
    assert scan.by_kind["aws_access_key"] == 30
    assert len(scan.reported(MAX_HITS)) == MAX_HITS


def _run_cli(*args: str) -> tuple[int, str]:
    import subprocess
    import sys
    from pathlib import Path

    proc = subprocess.run(
        [sys.executable, "-m", "prompt_ids.cli", *args],
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120,
        cwd=str(Path(__file__).resolve().parent.parent),
    )
    return proc.returncode, proc.stdout


def test_cli_output_scan_exits_three_and_redacts():
    code, out = _run_cli("--scan-output", "--json", f"key {AWS}")
    assert code == 3, out
    body = json.loads(out)
    assert body["found"] == 1
    assert AWS not in out


def test_cli_output_scan_is_a_separate_mode_from_input_scanning():
    """同一个字符串当输入是良性的，当输出才判 —— 两侧覆盖面不同，别混。"""
    text = f"文档里的示例密钥 AKIAIOSFODNN7EXAMPLE 是公开的样例"
    code_out, out = _run_cli("--scan-output", "--quiet", text)
    assert code_out == 3
    code_in, _ = _run_cli(text)
    assert code_in == 0


def test_stream_can_only_be_warned_after_the_fact(leaky_upstream, tmp_path_factory):
    """流式里内容已经发出去了，撤不回来 —— 只能末尾补一条告警，不能假装拦住了。

    顺带钉住一件更容易漏的事：密钥被切成两个 delta 发出来，线上根本看不到
    连续的密钥串，只有把累积缓冲拼起来才认得出（真按分片扫就会漏）。
    """
    httpd, audit_path = _proxy_for(leaky_upstream, tmp_path_factory, "stream")
    try:
        status, body = _post(httpd.server_address[1], {
            "messages": [{"role": "user", "content": f"key {AWS}"}],
            "stream": True,
        })
        assert status == 200
        text = body.decode("utf-8", "replace")
        assert AWS not in text, "本例里密钥被拆成两个 delta，线上不该出现连续串"
        assert "AKIAIOSF" in text and "ODNN7EXAMPLE" in text
        assert "secret_scan" in text, "内容已发出去了，至少要补一条告警帧"
        events = _events(audit_path)
        warned = [e for e in events if e["extra"].get("decision") == "secret_leak"]
        assert warned and warned[-1]["extra"]["secret_kinds"] == {"aws_access_key": 1}
        assert "撤" in warned[-1]["note"], "审计要写明这一类无法撤回，否则会被误读成已拦住"
    finally:
        httpd.shutdown()
        httpd.server_close()
