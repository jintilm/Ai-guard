"""REST API 服务：鉴权、限流、CORS、统一错误。

零第三方依赖，与 CLI / 透明代理 / 看板保持一致。
限流复用了 guard 模块里此前一直没被调用的 RateLimiter。
"""
from __future__ import annotations

import json
import os
import threading
import time
import traceback
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from prompt_ids.api.app import (
    ApiContext,
    ApiError,
    resolve,
)
from prompt_ids.net import warn_if_exposed
from prompt_ids.preprocess.guard import RateLimiter

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
        canary_issue_limit: int = 30,
        canary_issue_window_s: float = 60.0,
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
        #: `POST /v1/canary/issue` 的**独立**配额。
        #:
        #: 为什么不用上面的通用限流：签发是特权操作（它明文返回完整令牌），
        #: 额度必须比「跑一次检测」紧得多；而共用一个桶的话，一次 issue 就要
        #: 占掉一次普通请求的额度，或者反过来把 issue 的额度放到几百 ——
        #: 两个都不是我们想要的语义。
        #:
        #: 默认**开着**（30/分钟·每身份），而不是像 `rate_limit` 那样默认关：
        #: 这个端点未鉴权部署时谁都能签走一个令牌，关掉配额等于没有防护。
        #: 确实需要高频轮换（自动化测试每次签一批）就显式调大或设 0 关闭。
        self.canary_issue_limit = int(
            _first_env("PROMPT_IDS_CANARY_ISSUE_LIMIT", default=str(canary_issue_limit))
            or canary_issue_limit
        )
        self.canary_issue_window_s = float(
            _first_env("PROMPT_IDS_CANARY_ISSUE_WINDOW_S",
                       default=str(canary_issue_window_s)) or canary_issue_window_s
        )
        self.canary_issue_limiter = (
            RateLimiter(capacity=self.canary_issue_limit,
                        refill_s=self.canary_issue_window_s)
            if self.canary_issue_limit and self.canary_issue_limit > 0
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
        """限流的分桶键。

        **不能用请求头里的 X-API-Key**：那等于「每次请求换一个 key 就是一个新桶」，
        令牌桶形同虚设。未鉴权时只按来源 IP；鉴权开启时用**已验证**的 Key
        （`_authorized()` 已通过），请求头里那个值只在没配 Key 时才作数。
        """
        if self.config.api_key:
            return "key:" + str(self.config.api_key)
        return "ip:" + str(self.client_address[0])

    # ---------- 路由入口 ----------
    def _dispatch(self, method: str, read_body: bool) -> None:
        handler = resolve(method, self.path)
        if handler is None:
            self._error(404, "not_found", f"未知路由 {method} {self.path.split('?')[0]}")
            return

        # 鉴权：配置了 Key 就必须提供
        # ⚠ **健康检查豁免**：编排探针（compose healthcheck / K8s liveness）
        #   不会带业务凭据，若 `/healthz` 也要求 Key，容器会被反复判死并重启 ——
        #   而服务其实好着。`handle_health` 只回 {status, detectors}，没有敏感信息。
        #   探针与业务端口分开暴露的部署仍可选择收紧（反代层按路径拦）。
        if (self.config.auth_required and not self._authorized()
                and self.path.split("?")[0] not in ("/healthz", "/health")):
            self._drain_body()
            self._error(401, "unauthorized", "缺少或错误的 API Key")
            return

        # 限流：按 Key 或来源 IP
        if self.config.limiter and not self.config.limiter.try_acquire(self._client_id()):
            self._drain_body()
            self._error(429, "rate_limited", "请求过于频繁，请稍后再试")
            return

        # 签发令牌是特权操作，**单独**一个桶（默认 30/分钟·每身份，默认开着）。
        # 不共用上面的通用限流：共用的话 issue 要么占掉一次普通请求额度、
        # 要么就得把整体额度放到几百，两者都不是这个端点该有的语义。
        if (self.path.split("?")[0] == "/v1/canary/issue"
                and self.config.canary_issue_limiter is not None
                and not self.config.canary_issue_limiter.try_acquire(self._client_id())):
            self._drain_body()
            retry = max(1, int(self.config.canary_issue_window_s))
            self._error(429, "canary_issue_rate_limited",
                        f"签发过于频繁（{self.config.canary_issue_limit} 次/{retry}s），"
                        f"请稍后再试；令牌轮换不需要这么频繁")
            return

        payload: Any = {}
        query = self._query_dict()
        if read_body:
            try:
                payload = self._read_json()
            except ApiError as exc:
                self._error(exc.status, exc.code, exc.message)
                return
        else:
            payload = query

        try:
            # 查询参数**也**作为 params 传进去：`/v1/events?limit=200` 过去是无效的
            # （params 恒为 {}），而现有守护用的断言在参数失效时同样成立，照不出来。
            status, body = handler(self.ctx, payload, query)
        except ApiError as exc:
            self._error(exc.status, exc.code, exc.message)
            return
        except Exception:  # noqa: BLE001
        # 兜底：不让任何异常把服务打挂。**刻意捕获全部异常** ——
        # 这一层是 HTTP 处理的最外圈，漏掉任何一类都会让连接直接断掉，
        # 而「服务进程死了」比「这一次请求 500」严重得多。
        # 具体异常已在上面的分支里各自处理过了。
            # **不回显异常文本**：FileNotFoundError 会带绝对路径，第三方 SDK 的异常
            # 可能带 base_url（内网网关地址，URL 里甚至可能内嵌凭据），而本服务默认不鉴权。
            # 完整栈写到服务端 stderr（否则就等于把异常静默吞了 —— 「详见日志」不能是空话），
            # 客户端只拿到错误码。
            traceback.print_exc()
            self._error(500, "internal_error", "内部错误，详见服务端日志")
            return
        self._send(status, body)

    def _authorized(self) -> bool:
        # 与 proxy / web 检测台共用 `prompt_ids.auth`（`hmac.compare_digest`
        # 而不是 `==`）。代理的 Authorization 头是透传给上游的，所以三个入口
        # 统一用 X-API-Key 承载「本服务的凭据」—— 见 auth 模块 docstring。
        from prompt_ids.auth import authorized

        return authorized(self.headers, self.config.api_key)

    def _content_length(self) -> int:
        """解析 Content-Length，非法值必须是 400 而不是 ValueError 冒泡。"""
        raw = (self.headers.get("Content-Length") or "").strip()
        if not raw:
            return 0
        try:
            value = int(raw)
        except ValueError:
            raise ApiError(400, "bad_request", "Content-Length 不是合法整数")
        if value < 0:
            # rfile.read(-1) 会一直读到连接关闭 —— 一个慢连接就能永久占住一个线程
            raise ApiError(400, "bad_request", "Content-Length 不能为负")
        return value

    def _drain_body(self) -> None:
        """把请求体读干净再响应。

        不排空的话，客户端还在发 body 时服务端写错误并关连接 → RST，
        调用方（OpenAI SDK 等）看到的是 ConnectionResetError 而不是清晰的 4xx。
        这个坑在 proxy 与 playground 各修过一次，REST 这侧漏了（回归）。
        """
        try:
            remaining = self._content_length()
        except ApiError:
            return
        while remaining > 0:
            chunk = self.rfile.read(min(remaining, 65536))
            if not chunk:
                break
            remaining -= len(chunk)

    def _drain_chunked(self, *, max_bytes: int = MAX_BODY_BYTES) -> tuple[bool, int]:
        """丢弃 chunked 请求体，返回 (是否读完, 字节数)。与超长 body 同一个理由：
        不读干净就回错误 ⇒ 客户端收到 RST 而不是 411。"""
        total = 0
        while True:
            line = self.rfile.readline(1024)
            if not line:
                return False, total
            try:
                size = int(line.split(b";", 1)[0].strip() or b"0", 16)
            except ValueError:
                return False, total
            if size == 0:
                while True:
                    trailer = self.rfile.readline(1024)
                    if not trailer or trailer in (b"\r\n", b"\n"):
                        break
                return True, total
            remaining = size
            total += size
            while remaining > 0:
                chunk = self.rfile.read(min(remaining, 65536))
                if not chunk:
                    return False, total
                remaining -= len(chunk)
            self.rfile.read(2)
            if total > max_bytes:
                return False, total

    def _read_json(self) -> Any:
        length = self._content_length()
        if self.headers.get("Transfer-Encoding", "").lower().strip() == "chunked":
            # 不支持分块：静默当空 body 会让调用方以为请求体被接收了。
            # 先读干净再回 411（与 413 同理，不排空就是 RST）。
            self._drain_chunked()
            raise ApiError(411, "length_required", "不支持 Transfer-Encoding: chunked，请带 Content-Length")
        if length <= 0:
            return {}
        if length > MAX_BODY_BYTES:
            self._drain_body()
            raise ApiError(413, "payload_too_large",
                           f"请求体过大（{length} 字节 > 上限 {MAX_BODY_BYTES}）")
        raw = self.rfile.read(length)
        try:
            return json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ApiError(400, "bad_request", "请求体不是合法 JSON")
        except RecursionError:
            # 深层嵌套 JSON 会让 json.loads 抛 RecursionError（不是 JSONDecodeError）
            raise ApiError(400, "bad_request", "请求体嵌套过深")

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
    # API 是三个入口里**唯一有客户端鉴权**的（PROMPT_IDS_API_KEY / --api-key）。
    # 所以只有「对外监听 + 没配 Key」这一种组合才需要告警。
    warn_if_exposed(config.host, service="REST API", authenticated=config.auth_required)
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
