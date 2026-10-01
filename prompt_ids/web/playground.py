"""交互式检测台 —— 静态看板 + 可动手试的在线检测。

为什么要有这个：同类项目（Vigil 的 Streamlit playground、Rebuff 的 Playground UI、
LLM Guard 的 playground）都把「能当场试一条」当标配，而本项目的看板此前只有
只读快照 —— 能看到实验数字，但没法亲手验证「这句话到底会不会被判成注入」。

设计上守两条线：

1. **不写第二套检测逻辑。** 前端打的就是既有的 REST 路由（`prompt_ids.api.app`），
   本模块只做「静态文件 + JSON 转发」。于是 `/v1/scan`、`/v1/rules`、`/v1/metrics`、
   `/v1/canary/*`、`/v1/memory/*` 全部自动可用，且 API 与检测台永远同源同行为。
   反面做法是在 web 里再实现一遍 scan —— 那两套逻辑迟早会漂移。

2. **静态模式不能被削弱。** 不加 `--serve` 时生成出来的仍是可双击打开、
   可当作业交的纯静态 HTML；检测台面板会自动显示为「未连接服务」并给出启动命令。
   这叫渐进增强：离线有离线的好，联网有联网的好。

安全边界（本地服务也要守）：
  * 只绑 127.0.0.1，不对外监听
  * 请求体上限 2MB，文本长度上限沿用 API 的校验
  * 服务端异常统一转成 JSON 错误，不把 traceback 吐给前端
"""
from __future__ import annotations

import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

from prompt_ids.api.app import ApiContext, ApiError, resolve

MAX_BODY_BYTES = 2 * 1024 * 1024


class PlaygroundState:
    """进程内共享状态：一个流水线、一个统计计数器。"""

    def __init__(self, ctx: ApiContext, dashboard_path: str, refresh_s: int = 0):
        self.ctx = ctx
        self.dashboard_path = dashboard_path
        self.refresh_s = refresh_s
        self._lock = threading.Lock()

    def scan(self, text: str, user: str = "playground", policy: str | None = None) -> dict[str, Any]:
        result = self.ctx.pipeline.scan(text, user=user, policy_name=policy)
        with self._lock:
            self.ctx.record(result)
            if self.ctx.audit is not None:
                self.ctx.audit.log_scan(result, text=text, user=user, source="playground")
        return result


class Handler(BaseHTTPRequestHandler):
    server_version = "prompt-ids-playground"
    state: PlaygroundState  # 由 attach() 注入

    # ---------------------------------------------------------- 基础工具
    def log_message(self, *args: Any) -> None:  # 静音，避免刷屏
        pass

    def _send_json(self, status: int, body: dict) -> None:
        payload = json.dumps(body, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(payload)

    def _send_html(self) -> None:
        try:
            with open(self.state.dashboard_path, "rb") as handle:
                body = handle.read()
        except OSError:
            self._send_json(500, {"error": "看板文件不存在，请先不带 --serve 跑一次生成它"})
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self) -> Any:
        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_BODY_BYTES:
            # 先把请求体读掉再拒绝：否则客户端还在发送时服务端关闭连接会触发 RST，
            # 前端看到的是 ConnectionResetError 而不是清晰的 413。
            # 分块丢弃，不把整个 body 装进内存（与 proxy/server.py 同一套做法）。
            remaining = length
            while remaining > 0:
                chunk = self.rfile.read(min(remaining, 65536))
                if not chunk:
                    break
                remaining -= len(chunk)
            raise ApiError(413, "payload_too_large", f"请求体超过 {MAX_BODY_BYTES // 1024 // 1024}MB")
        if length <= 0:
            return None
        raw = self.rfile.read(length)
        if not raw.strip():
            return None
        try:
            return json.loads(raw.decode("utf-8", errors="replace"))
        except json.JSONDecodeError as exc:
            raise ApiError(400, "bad_json", f"请求体不是合法 JSON：{exc}") from exc

    def _dispatch(self, method: str, payload: Any) -> None:
        parsed = urlparse(self.path)
        # 检测台的友好别名，内部落到同一批处理器上
        path = {"/api/scan": "/v1/scan", "/api/providers": "/v1/providers",
                "/api/rules": "/v1/rules", "/api/metrics": "/v1/metrics",
                "/api/events": "/v1/events"}.get(parsed.path, parsed.path)
        handler = resolve(method, path)
        if handler is None:
            self._send_json(404, {
                "error": f"未找到路由 {method} {parsed.path}",
                "hint": "可用：POST /v1/scan、GET /v1/rules、GET /v1/providers、GET /v1/metrics、GET /v1/events",
            })
            return
        params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        try:
            status, body = handler(self.state.ctx, payload, params)
        except ApiError as exc:
            self._send_json(exc.status, {"error": exc.code, "message": exc.message})
            return
        except Exception as exc:  # noqa: BLE001 - 前端只该看到结构化错误
            self._send_json(500, {"error": "internal", "message": f"{type(exc).__name__}: {exc}"[:200]})
            return
        self._send_json(status, body)

    # ---------------------------------------------------------- HTTP 动词
    def _is_dashboard_path(self, path: str) -> bool:
        """哪些路径返回看板 HTML。

        除了根路径与两个常规别名，还要认「实际输出文件名」——
        `--out reports/我的看板.html` 时 URL 里带的是那个名字，
        只认固定别名会让 serve() 打印出来的链接直接 404。
        """
        if path in ("/", "/index.html", "/dashboard.html"):
            return True
        return path == f"/{os.path.basename(self.state.dashboard_path)}"

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if self._is_dashboard_path(parsed.path):
            self._send_html()
            return
        if parsed.path.startswith(("/v1/", "/api/", "/healthz", "/health")):
            self._dispatch("GET", None)
            return
        self._send_json(404, {"error": "not_found", "path": parsed.path})

    def do_POST(self) -> None:  # noqa: N802
        try:
            payload = self._read_body()
        except ApiError as exc:
            self._send_json(exc.status, {"error": exc.code, "message": exc.message})
            return
        self._dispatch("POST", payload)


def attach(state: PlaygroundState):
    """把状态挂到一个新的 Handler 子类上（避免污染模块级类属性）。"""
    return type("BoundHandler", (Handler,), {"state": state})


def serve(
    ctx: ApiContext,
    dashboard_path: str,
    host: str = "127.0.0.1",
    port: int = 8765,
    refresh_s: int = 0,
    rebuild=None,
) -> ThreadingHTTPServer:
    """起服务并返回 server 对象（调用方决定何时 shutdown）。

    `rebuild` 给定时会起一个后台线程按 `refresh_s` 重新生成看板 ——
    这样「实验数字」和「在线检测」在同一个页面上都是最新的。
    """
    state = PlaygroundState(ctx, dashboard_path, refresh_s)
    server = ThreadingHTTPServer((host, port), attach(state))
    threading.Thread(target=server.serve_forever, daemon=True).start()

    if rebuild is not None and refresh_s > 0:
        def loop() -> None:
            while True:
                time.sleep(refresh_s)
                try:
                    rebuild()
                except Exception:  # noqa: BLE001 - 刷新失败不该拖垮服务
                    pass

        threading.Thread(target=loop, daemon=True).start()
    return server
