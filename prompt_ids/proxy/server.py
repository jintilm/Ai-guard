"""OpenAI 兼容透明代理 —— 应用零改造接入。

应用侧只需把 base_url 指向本代理，其余代码一行不用动：

    openai.base_url = "http://127.0.0.1:8787/v1"

代理在请求发出前做入站检测；判定为阻断时直接返回 403，
请求根本不会到达上游，因此也不会产生 token 费用。

凭据一律从环境变量读取，不硬编码、不写进审计日志。
"""
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from prompt_ids.audit import AuditLogger, event_from_proxy
from prompt_ids.canary.tokens import CanaryRegistry
from prompt_ids.core.pipeline import Pipeline, PipelineConfig
from prompt_ids.core.types import Action
from prompt_ids.proxy.forward import UpstreamError, forward_headers, post_json, post_stream

DEFAULT_PORT = 8787
# 请求体上限。不设的话攻击者可以用超大 Content-Length 吃满内存与 CPU：
# 规则层耗时随长度线性增长（72KB 约 135ms），超大 body 足以拖垮代理
MAX_BODY_BYTES = 2 * 1024 * 1024
# 需要检测的路径；其余路径（如 /v1/models）直接透传
SCANNED_PATHS = ("/v1/chat/completions", "/v1/completions", "/chat/completions", "/completions")


def _first_env(*names: str, default: str = "") -> str:
    for name in names:
        value = os.environ.get(name, "").strip()
        if value:
            return value
    return default


class ProxyConfig:
    def __init__(
        self,
        upstream: str = "",
        api_key: str | None = None,
        port: int = DEFAULT_PORT,
        host: str = "127.0.0.1",
        audit_path: str | None = None,
        timeout_s: float = 60.0,
        # 判定为 sandbox 时是否仍然放行（False 表示也拦截）
        allow_sandbox: bool = True,
        pipeline: Pipeline | None = None,
        canary: CanaryRegistry | None = None,
        # 检出 Canary 泄漏时是否用告警替换响应（否则只记录审计）
        redact_leak: bool = True,
    ):
        self.upstream = (upstream or _first_env("PROMPT_IDS_UPSTREAM", "OPENAI_BASE_URL",
                                                default="https://api.openai.com/v1")).rstrip("/")
        self.api_key = api_key if api_key is not None else _first_env("PROMPT_IDS_UPSTREAM_KEY", "OPENAI_API_KEY")
        self.port = port
        self.host = host
        self.timeout_s = timeout_s
        self.allow_sandbox = allow_sandbox
        self.audit = AuditLogger(audit_path)
        self.pipeline = pipeline
        self.canary = canary
        self.redact_leak = redact_leak

    def leak_check(self, text: str):
        """出站检测：模型输出里是否出现了 Canary 令牌。"""
        if not self.canary or not text:
            return None
        return self.canary.check(text)

    @property
    def pipeline_instance(self) -> Pipeline:
        if self.pipeline is None:
            self.pipeline = Pipeline(config=PipelineConfig(enable_cache=True))
        return self.pipeline


def extract_prompt(payload: dict[str, Any]) -> str:
    """从 OpenAI 兼容请求体里取出待检测文本。

    messages 与 prompt 两种形态都支持；多轮只取用户输入，
    系统提示是应用自己的内容，不需要检测。
    """
    parts: list[str] = []
    messages = payload.get("messages")
    if isinstance(messages, list):
        for item in messages:
            if not isinstance(item, dict):
                continue
            role = str(item.get("role", "")).lower()
            content = item.get("content")
            if isinstance(content, list):  # 多模态：取出其中的文本段
                content = " ".join(
                    str(part.get("text", "")) for part in content if isinstance(part, dict)
                )
            if isinstance(content, str) and role in ("user", "human", "system", "developer", ""):
                parts.append(content)
    prompt = payload.get("prompt")
    if isinstance(prompt, str):
        parts.append(prompt)
    elif isinstance(prompt, list):
        parts.extend(str(p) for p in prompt)
    return "\n".join(parts).strip()


def decide(result, config: ProxyConfig) -> tuple[str, int, str]:
    """返回 (决策, HTTP 状态码, 说明)。"""
    if result.action is Action.BLOCK:
        return "block", 403, "请求被提示词注入防护拦截"
    if result.action is Action.SANDBOX and not config.allow_sandbox:
        return "sandbox", 403, "请求被判定为高风险，已隔离"
    if result.action is Action.SANDBOX:
        return "sandbox", 200, "高风险命中，已放行但记录审计"
    if result.action is Action.REVIEW:
        return "review", 200, "中等风险，已放行并记录"
    return "allow", 200, ""


class ProxyHandler(BaseHTTPRequestHandler):
    server_version = "prompt-ids-proxy/0.1"
    config: ProxyConfig  # 由 create_server 注入

    # ---------- 基础 ----------
    def log_message(self, fmt: str, *args) -> None:
        # 默认实现会往 stderr 打访问日志，代理场景交由审计模块负责
        pass

    def _send_json(self, status: int, obj: dict[str, Any]) -> None:
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _relay_response(self, status: int, headers: dict[str, str]) -> None:
        self.send_response(status)
        for key, value in headers.items():
            if key.lower() in ("transfer-encoding", "content-length", "connection"):
                continue
            self.send_header(key, value)
        self.end_headers()

    # ---------- 路由 ----------
    def do_GET(self) -> None:
        if self.path.rstrip("/") in ("/healthz", "/health"):
            self._send_json(200, {"status": "ok", "upstream": self.config.upstream})
            return
        self._passthrough("GET", b"")

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_BODY_BYTES:
            # 先把请求体读掉再拒绝：否则客户端还在发送时关闭连接会触发 RST，
            # 调用方（如 OpenAI SDK）看到的是 ConnectionResetError 而不是清晰的 413。
            # 分块丢弃，不把整个 body 装进内存。
            remaining = length
            while remaining > 0:
                chunk = self.rfile.read(min(remaining, 65536))
                if not chunk:
                    break
                remaining -= len(chunk)
            self._send_json(413, {"error": {
                "message": f"请求体过大（{length} 字节 > 上限 {MAX_BODY_BYTES}）",
                "type": "payload_too_large", "code": "payload_too_large"}})
            return
        body = self.rfile.read(length) if length else b""
        path = self.path.split("?")[0].rstrip("/")

        if path not in SCANNED_PATHS:
            self._passthrough("POST", body)
            return

        try:
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._send_json(400, {"error": "请求体不是合法 JSON"})
            return
        if not isinstance(payload, dict):
            self._send_json(400, {"error": "请求体必须是 JSON 对象"})
            return

        text = extract_prompt(payload)
        if not text:
            self._passthrough("POST", body)
            return

        pipeline = self.config.pipeline_instance
        started = time.perf_counter()
        result = pipeline.scan(text)
        detect_ms = (time.perf_counter() - started) * 1000
        decision, status, note = decide(result, self.config)

        if decision == "block":
            self.config.audit.log(
                event_from_proxy(
                    result, path=path, client=self.client_address[0], stream=False,
                    detect_ms=detect_ms, status=status, decision=decision, note=note, text=text,
                )
            )
            self._send_json(
                403,
                {
                    "error": {
                        "message": note,
                        "type": "prompt_injection_blocked",
                        "code": "injection_detected",
                    },
                    "prompt_ids": {
                        "score": result.score,
                        "level": result.level.value,
                        "action": result.action.value,
                        "findings": [f.pattern_id for f in result.findings][:10],
                        "explained": result.explained,
                    },
                },
            )
            return

        self._forward(path, body, payload, result, decision, detect_ms, text)

    # ---------- 转发 ----------
    def _build_headers(self) -> dict[str, str]:
        headers = forward_headers(self.headers)
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"
        headers["Content-Type"] = "application/json"
        return headers

    def _forward(
        self,
        path: str,
        body: bytes,
        payload: dict[str, Any],
        result,
        decision: str,
        detect_ms: float,
        text: str = "",
    ) -> None:
        url = f"{self.config.upstream}{path}"
        headers = self._build_headers()
        stream = bool(payload.get("stream"))
        started = time.perf_counter()
        try:
            if stream:
                status, resp_headers, chunks, _ = post_stream(url, body, headers, self.config.timeout_s)
                self._relay_response(status, resp_headers)
                # 流式无法撤回已发内容：边发边累积，末尾补一条告警事件并记审计
                buffered = bytearray()
                for chunk in chunks:
                    if not chunk:
                        continue
                    buffered.extend(chunk)
                    self.wfile.write(chunk)
                    self.wfile.flush()
                leak = self.config.leak_check(bytes(buffered).decode("utf-8", "replace"))
                if leak is not None:
                    self.wfile.write(_leak_event(leak))
                    self.wfile.flush()
            else:
                status, resp_headers, payload_bytes, _ = post_json(url, body, headers, self.config.timeout_s)
                leak = self.config.leak_check(_response_text(payload_bytes))
                if leak is not None and self.config.redact_leak:
                    # 令牌已经出现在输出里，原文不能再往前传，换成告警
                    self.config.audit.log(
                        event_from_proxy(result, path=path, client=self.client_address[0],
                                         stream=False, upstream_ms=(time.perf_counter() - started) * 1000,
                                         detect_ms=detect_ms, status=200, decision="leak",
                                         note=f"Canary 泄漏({leak.how})，响应已替换", text=text)
                    )
                    self._send_json(200, _leak_warning(leak))
                    return
                if leak is not None:
                    self._send_json(200, json.loads(payload_bytes.decode("utf-8", "replace")))
                    return
                self._relay_response(status, resp_headers)
                self.wfile.write(payload_bytes)
        except UpstreamError as exc:
            status = exc.status
            self._send_json(status, json.loads(exc.body.decode("utf-8")))
        except OSError:
            # 客户端提前断开，无能为力，记录即可
            status = 499
            return
        upstream_ms = (time.perf_counter() - started) * 1000

        self.config.audit.log(
            event_from_proxy(
                result, path=path, client=self.client_address[0], stream=stream,
                upstream_ms=upstream_ms, detect_ms=detect_ms, status=status,
                decision=decision, text=text,
            )
        )

    def _passthrough(self, method: str, body: bytes) -> None:
        """非检测路径（如 /v1/models）原样转发。"""
        url = f"{self.config.upstream}{self.path.split('?')[0].rstrip('/')}"
        headers = self._build_headers()
        request = urllib.request.Request(url, data=body or None, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=self.config.timeout_s) as response:
                data = response.read()
                self._relay_response(response.status, dict(response.headers))
                self.wfile.write(data)
        except urllib.error.HTTPError as exc:
            self._send_json(exc.code, {"error": f"上游返回 {exc.code}"})
        except (urllib.error.URLError, TimeoutError):
            self._send_json(502, {"error": "上游不可达"})


def _response_text(payload: bytes) -> str:
    """从 OpenAI 响应体里取出模型输出文本，用于出站 Canary 检测。"""
    try:
        obj = json.loads(payload.decode("utf-8", "replace"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return ""
    parts: list[str] = []
    for choice in obj.get("choices", []) or []:
        if not isinstance(choice, dict):
            continue
        message = choice.get("message") or {}
        if isinstance(message, dict):
            content = message.get("content")
            if isinstance(content, str):
                parts.append(content)
        if isinstance(choice.get("text"), str):
            parts.append(choice["text"])
        if isinstance(choice.get("delta"), dict):
            parts.append(str(choice["delta"].get("content", "")))
    return "\n".join(parts)


def _leak_warning(leak) -> dict[str, Any]:
    return {
        "error": {
            "message": "响应包含机密标识符，已被防护系统替换",
            "type": "canary_leak",
            "code": "system_prompt_leaked",
        },
        # public=True：对外只回显脱敏令牌，否则等于把令牌亲手交给攻击者
        "prompt_ids": {"leak": leak.as_dict(public=True)},
    }


def _leak_event(leak) -> bytes:
    return b"data: " + json.dumps(
        {"prompt_ids_warning": "canary_leak", "leak": leak.as_dict(public=True)}, ensure_ascii=False
    ).encode("utf-8") + b"\n\n"


def create_server(config: ProxyConfig) -> ThreadingHTTPServer:
    handler = type("BoundProxyHandler", (ProxyHandler,), {"config": config})
    return ThreadingHTTPServer((config.host, config.port), handler)


def serve(config: ProxyConfig) -> None:  # pragma: no cover - 阻塞调用
    server = create_server(config)
    print(f"透明代理已启动 http://{config.host}:{config.port} -> {config.upstream}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
