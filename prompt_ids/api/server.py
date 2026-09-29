"""REST API 服务：鉴权、限流、CORS、统一错误。

零第三方依赖，与 CLI / 透明代理 / 看板保持一致。
限流复用了 guard 模块里此前一直没被调用的 RateLimiter。
"""
from __future__ import annotations

import json
import os
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from prompt_ids.api.app import (
    ApiContext,
    ApiError,
    MAX_BATCH,
    resolve,
)
from prompt_ids.preprocess.guard import GuardConfig, RateLimiter

DEFAULT_PORT = 8790
MAX_BODY_BYTES = 2 * 1024 * 1024  # 2MB


def _first_env(*names: str, default: str = "") -> str:
    for name in names:
        value = os.environ.get(name, "").strip()
        if value:
            return value
    return default


class ApiServerConfig:
    def __init__(
        self,
        port: int = DEFAULT_PORT,
        host: str = "127.0.0.1",
        api_key: str | None = None,
        rate_limit: int = 0,
        rate_window_s: float = 60.0,
        cors: bool = True,
    ):
        self.port = port
        self.host = host
        # 未设置则不鉴权（本地开发），生产应显式设置
        self.api_key = api_key if api_key is not None else _first_env("PROMPT_IDS_API_KEY")
        self.cors = cors
        self.limiter = (
            RateLimiter(capacity=rate_limit, refill_s=rate_window_s)
            if rate_limit and rate_limit > 0
            else None
        )

    @property
    def auth_required(self) -> bool:
        return bool(self.api_key)


class ApiHandler(BaseHTTPRequestHandler):
    server_version = "prompt-ids-api/0.1"
    ctx: ApiContext
    config: ApiServerConfig

    # ---------- 基础 ----------
    def log_message(self, *args) -> None:
        pass  # 访问日志交给审计/指标，不打 stderr

    def _send(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        if self.config.cors:
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Headers", "Content-Type, X-API-Key, Authorization")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _error(self, status: int, code: str, message: str) -> None:
        self._send(status, {"error": {"code": code, "message": message}, "status": status})

    def _client_id(self) -> str:
        return self.headers.get("X-API-Key") or self.client_address[0]

    # ---------- 路由入口 ----------
    def _dispatch(self, method: str, read_body: bool) -> None:
        handler = resolve(method, self.path)
        if handler is None:
            self._error(404, "not_found", f"未知路由 {method} {self.path.split('?')[0]}")
            return

        # 鉴权：配置了 Key 就必须提供
        if self.config.auth_required and not self._authorized():
            self._error(401, "unauthorized", "缺少或错误的 API Key")
            return

        # 限流：按 Key 或来源 IP
        if self.config.limiter and not self.config.limiter.try_acquire(self._client_id()):
            self._error(429, "rate_limited", "请求过于频繁，请稍后再试")
            return

        payload: Any = {}
        if read_body:
            try:
                payload = self._read_json()
            except ApiError as exc:
                self._error(exc.status, exc.code, exc.message)
                return
        else:
            payload = self._query_dict()

        try:
            status, body = handler(self.ctx, payload, {})
        except ApiError as exc:
            self._error(exc.status, exc.code, exc.message)
            return
        except Exception as exc:  # 兜底：不让任何异常把服务打挂
            self._error(500, "internal_error", f"{type(exc).__name__}: {exc}")
            return
        self._send(status, body)

    def _authorized(self) -> bool:
        provided = self.headers.get("X-API-Key", "")
        auth = self.headers.get("Authorization", "")
        if auth.lower().startswith("bearer "):
            provided = provided or auth[7:].strip()
        return provided == self.config.api_key

    def _read_json(self) -> Any:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return {}
        if length > MAX_BODY_BYTES:
            raise ApiError(413, "payload_too_large", "请求体过大")
        raw = self.rfile.read(length)
        try:
            return json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ApiError(400, "bad_request", "请求体不是合法 JSON")

    def _query_dict(self) -> dict:
        query = urllib.parse.urlparse(self.path).query
        return {k: v[0] for k, v in urllib.parse.parse_qs(query).items()}

    # ---------- HTTP 方法 ----------
    def do_GET(self) -> None:
        self._dispatch("GET", read_body=False)

    def do_POST(self) -> None:
        self._dispatch("POST", read_body=True)

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        if self.config.cors:
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Headers", "Content-Type, X-API-Key, Authorization")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()


def create_api_server(ctx: ApiContext, config: ApiServerConfig) -> ThreadingHTTPServer:
    handler = type("BoundApiHandler", (ApiHandler,), {"ctx": ctx, "config": config})
    return ThreadingHTTPServer((config.host, config.port), handler)


def serve(ctx: ApiContext, config: ApiServerConfig) -> None:  # pragma: no cover
    server = create_api_server(ctx, config)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    print(f"REST API 已启动 http://{config.host}:{config.port}")
    print(f"鉴权: {'已启用' if config.auth_required else '未启用（设置 PROMPT_IDS_API_KEY 开启）'}")
    print(f"限流: {config.limiter.capacity if config.limiter else '关闭'} 次/窗口")
    print("端点: POST /v1/scan  POST /v1/scan/batch  GET /v1/rules  "
          "POST /v1/canary/issue  POST /v1/canary/check  GET /v1/metrics  GET /healthz")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
        server.server_close()
