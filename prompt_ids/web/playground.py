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
  * **默认**只绑 127.0.0.1。这只是**默认值，不是保证** —— `--host` 是自由字符串，
    改了就对外监听，而本服务**没有任何客户端鉴权**（api 那套 `PROMPT_IDS_API_KEY`
    不在这里）。因此绑非回环地址时由 `prompt_ids.net.warn_if_exposed` 往 stderr
    打一段告警，说明暴露了什么、正确姿势是什么。
    ⚠ 别把这一行改写成「不对外监听」：那是把默认值说成保证，本模块正是为此存在。
  * 请求体上限 2MB，文本长度上限沿用 API 的校验
  * 服务端异常统一转成 JSON 错误，不把 traceback 吐给前端
"""
from __future__ import annotations

import collections
import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

from prompt_ids.api.app import ApiContext, ApiError, resolve
from prompt_ids.auth import authorized
from prompt_ids.net import warn_if_exposed

MAX_BODY_BYTES = 2 * 1024 * 1024

#: SSE 事件环保留多少条。重连时补发「错过的那些」，所以环不能太小 ——
#: 但也不能太大：每条都常驻内存，而环的消费者是浏览器标签页。
STREAM_RING = 50
#: SSE 心跳间隔秒。心跳不是装饰：反代与浏览器都会因空闲而掐断长连接，
#: 而**没有心跳的 SSE 看起来一切正常，直到某天开始静默停止推送**。
STREAM_HEARTBEAT_S = 15
#: 单条 SSE 连接的存活上限。到点后主动收尾，让前端自己重连 ——
#: 无限长连接在浏览器/反代/负载均衡三层各有一份超时策略，
#: 自己控制上限才能保证「重连」而不是「静默卡死」。
STREAM_MAX_S = 900


#: 「客户端已断开」的异常集合。
#:
#: ⚠ **必须包含 `ConnectionAbortedError`**（2026-10 在 Windows CI 上被抓到）：
#: 浏览器关标签页时，Windows 抛的是 `ConnectionAbortedError`
#: （WinError 10053 "An established connection was aborted by the software
#: in your host machine"），**不是** `ConnectionResetError`。
#:
#: 只捕 BrokenPipe/ConnectionReset 时，SSE 心跳那次 write 会把异常抛到
#: `socketserver.process_request_thread`，于是：
#:   ① 每个跑过 SSE 的测试 stderr 都多出一整段 traceback
#:      （CI 日志里刷屏的噪声）；
#:   ② 断言「stderr 为空」的守护随之失败 —— 而它报出来的位置是**别的文件**
#:      （`test_net_exposure.py`），完全指不到真正的原因。
#:      这正是本项目反复在修的那类「报错指不到真因」。
#:
#: 三个异常语义相同：对端没了 ⇒ SSE 连接该结束了，不是错误。
_CLIENT_GONE = (BrokenPipeError, ConnectionResetError, ConnectionAbortedError)


class PlaygroundState:
    """进程内共享状态：一个流水线、一个统计计数器。"""

    def __init__(self, ctx: ApiContext, dashboard_path: str, refresh_s: int = 0,
                 client_key: str = ""):
        self.ctx = ctx
        self.dashboard_path = dashboard_path
        self.refresh_s = refresh_s
        #: 客户端鉴权用的 Key（`PROMPT_IDS_WEB_CLIENT_KEY` / `--client-key`）。
        #: ⚠ 与 API 入口的 `PROMPT_IDS_API_KEY` **刻意不同名**：检测台暴露的是
        #: `/v1/scan`（让本机替别人跑检测）与 `/v1/canary/issue`（领令牌），
        #: 复用同一个变量名会让「我给 API 开了鉴权」被误读成检测台也开了。
        self.client_key = client_key
        # ⚠ **必须是 RLock**：SSE 的等待方在 `with self.changed:` 里调
        # `events_since()`，而 Condition 用的就是这把锁 ⇒ 普通 Lock 会在
        # 这里**自死锁**，表现是「hello 帧正常、之后一个事件都不推」，
        # **没有任何报错**（线程只是永远等下去）。
        # 踩过一次：事件环、`events_since`、`publish` 三处都用了普通 Lock。
        self._lock = threading.RLock()
        #: SSE 推送用的事件环（**只含判定与指纹，不含原文** —— 与审计同一条边界）。
        #: `seq` 单调递增，让前端能判断「这是新事件」还是「重连后补的历史」。
        self.recent: collections.deque[dict[str, Any]] = collections.deque(
            maxlen=STREAM_RING)
        self.seq = 0
        #: 新事件的通知器。用它而不是「定时轮询」——轮询的推送延迟等于轮询间隔，
        #: 拿心跳间隔当轮询间隔的话，一次检测最坏要等 15 秒才出现在面板上，
        #: 那不叫实时。实测：改成事件驱动后推送是即时的，而 15 秒只用于心跳。
        self.changed = threading.Condition(self._lock)

    def publish(self, event: dict[str, Any]) -> None:
        """把一次判定挂进事件环。**调用方必须已经做完脱敏**（这里不设防）。"""
        with self.changed:
            self.seq += 1
            self.recent.append({"seq": self.seq, **event})
            self.changed.notify_all()

    def events_since(self, last_seq: int) -> list[dict[str, Any]]:
        """`seq > last_seq` 的事件。

        ⚠ 调用方**可能已经持有** `self.changed`（SSE 等待方就是），
        所以 `_lock` 必须是 `RLock` —— 见 `__init__` 里的说明。
        """
        with self._lock:
            return [e for e in self.recent if e["seq"] > last_seq]

    def scan(self, text: str, user: str = "playground", policy: str | None = None) -> dict[str, Any]:
        result = self.ctx.pipeline.scan(text, user=user, policy_name=policy)
        with self._lock:
            self.ctx.record(result)
            if self.ctx.audit is not None:
                self.ctx.audit.log_scan(result, text=text, user=user, source="playground")
        # 推送出去的是**判定摘要**：level / score / action / pattern_id / 指纹 / 字数。
        # ⚠ 绝不含 `text` —— 那条边界在审计、遥测、看板三处都守着，
        #   SSE 是第四处；而 SSE 恰好是最容易被忘的一处（它是「顺手加的」功能）。
        self.publish({
            "ts": time.time(),
            "level": result.level.value,
            "action": result.action.value,
            "score": round(result.score, 1),
            "patterns": [f.pattern_id for f in result.findings][:8],
            "fingerprint": result.fingerprint,
            "chars": len(text),
            "detect_ms": round(float(result.latency_ms.get("total", 0.0)), 2),
            "cached": bool(result.cached),
            "skipped": list(result.skipped),
            "source": "playground",
        })
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

    def _drain(self, length: int) -> None:
        """把请求体分块读干净再响应（不装进内存）。

        401 也必须排空：客户端还在发 body 时服务端写错误并关连接 ⇒ RST，
        前端 `fetch` 看到的是 `ConnectionResetError` 而不是 401，
        于是「鉴权没配」会被读成「服务崩了」。与 413 / proxy 的 401 同一套做法。
        """
        remaining = max(0, length)
        while remaining > 0:
            chunk = self.rfile.read(min(remaining, 65536))
            if not chunk:
                break
            remaining -= len(chunk)

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
                "/api/events": "/v1/events",
                "/api/review": "/v1/review",
                "/api/review/queue": "/v1/review/queue"}.get(parsed.path, parsed.path)
        handler = resolve(method, path)
        if handler is None:
            self._send_json(404, {
                "error": f"未找到路由 {method} {parsed.path}",
                "hint": "可用：POST /v1/scan、GET /v1/rules、GET /v1/providers、GET /v1/metrics、GET /v1/events",
            })
            return

        # GET 路由的鉴权（POST 在 `do_POST` 里、**读 body 之前**判 ——
        # 见 `_reject_unauthorized` 的注释：读 body 之后再排空会对着空流阻塞）。
        if (self._needs_key(path)
                and not authorized(self.headers, self.state.client_key)):
            self._send_json(401, {
                "error": "缺少或错误的客户端 Key（X-API-Key）",
                "hint": "检测台的 JSON 路由需要鉴权；看板 HTML 本身不需要"})
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

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if self._is_dashboard_path(parsed.path):
            self._send_html()
            return
        if parsed.path in ("/v1/stream", "/api/stream"):
            # 鉴权与其它 /v1 路由同一套。⚠ 客户端**不能**用 `EventSource`：
            #   它无法自定义请求头，于是 Key 只能塞进 query 参数 —— 那会让凭据
            #   出现在 nginx 的 access log、浏览器历史与 Referer 里。
            #   前端因此必须用 `fetch` + `ReadableStream`（见 dashboard.py）。
            if self._needs_key(parsed.path) and not authorized(
                    self.headers, self.state.client_key):
                self._send_json(401, {"error": "缺少或错误的客户端 Key（X-API-Key）"})
                return
            self._stream_events(parsed)
            return
        if parsed.path.startswith(("/v1/", "/api/", "/healthz", "/health")):
            self._dispatch("GET", None)
            return
        self._send_json(404, {"error": "not_found", "path": parsed.path})

    def _stream_events(self, parsed) -> None:  # pragma: no cover - 长连接
        """SSE 推送：先补发错过的事件，再持续推新的。

        长连接用 `Connection: close` 收尾（而不是 keep-alive 复用）：
        `BaseHTTPRequestHandler` 的 keep-alive 与 SSE 共存时，
        第一个长连接会占住 `self.wfile` 直到超时，后续请求排队 ——
        现象是「面板打开了但整个服务卡住」。
        """
        try:
            last_seq = int(parse_qs(parsed.query).get("last_seq", ["0"])[0] or 0)
        except (TypeError, ValueError):
            last_seq = 0
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Accel-Buffering", "no")   # 别让反代缓冲住这条流
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            self._write_sse({"type": "hello", "seq": self.state.seq,
                             "ring": STREAM_RING,
                             "heartbeat_s": STREAM_HEARTBEAT_S})
            for event in self.state.events_since(last_seq):
                self._write_sse(event)
            sent = self.state.seq
            deadline = time.time() + STREAM_MAX_S
            while time.time() < deadline:
                # 事件驱动地等：有新事件立刻醒，没新事件到点发心跳。
                # ⚠ 用同一个 Condition（而不是另开一把锁）—— 否则会出现
                #   「事件已被记进环、但等待方没被唤醒」的窗口，
                #   现象是「偶尔漏推一条」，且只在负载高时出现。
                with self.state.changed:
                    if self.state.seq == sent:
                        self.state.changed.wait(timeout=STREAM_HEARTBEAT_S)
                    fresh = self.state.events_since(sent)
                    sent = self.state.seq
                for event in fresh:
                    self._write_sse(event)
                if not fresh:
                    self._write_sse({"type": "heartbeat", "seq": sent})
        except _CLIENT_GONE:
            pass          # 浏览器关掉标签页 —— 正常路径，不是错误
        finally:
            try:
                self.close_connection = True
            except Exception:  # noqa: BLE001
                pass

    def _write_sse(self, event: dict[str, Any]) -> None:
        payload = json.dumps(event, ensure_ascii=False)
        self.wfile.write(f"data: {payload}\n\n".encode("utf-8"))
        self.wfile.flush()

    def _needs_key(self, path: str) -> bool:
        """这个路径是否需要客户端鉴权。

        只挡 `/v1/*` 与 `/api/*`（JSON 路由）：看板 HTML 与静态文件**不挡** ——
        它们只含实验数字（可公开的那部分），挡了会让「拷走就能交」失效。
        """
        if not self.state.client_key:
            return False
        return path.startswith(("/v1/", "/api/"))

    def _reject_unauthorized(self) -> None:
        """401。

        ⚠ **必须在读 body 之前**调用：`_read_body` 会把 `Content-Length` 那些字节
        一次读走，之后再按同一个长度去「排空」就是**对着空流等数据** ——
        `rfile.read()` 会一直阻塞到连接关闭，于是每个未鉴权的请求都挂住一个线程，
        未鉴权的调用方反而成了 DoS 的触发器（实测：请求直接超时，线程不释放）。
        这也是 413 那条「先排空再响应」在**读 body 之前**判的同一个道理。
        """
        length = int(self.headers.get("Content-Length") or 0) or 0
        if length:
            self._drain(length)
        self._send_json(401, {
            "error": "缺少或错误的客户端 Key（X-API-Key）",
            "hint": "检测台的 JSON 路由需要鉴权；看板 HTML 本身不需要"})

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        if self._needs_key(parsed.path) and not authorized(self.headers, self.state.client_key):
            self._reject_unauthorized()
            return
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
    client_key: str = "",
) -> ThreadingHTTPServer:
    """起服务并返回 server 对象（调用方决定何时 shutdown）。

    `rebuild` 给定时会起一个后台线程按 `refresh_s` 重新生成看板 ——
    这样「实验数字」和「在线检测」在同一个页面上都是最新的。

    `client_key` 非空 ⇒ `/v1/*` 路由需要 `X-API-Key`。**看板 HTML 不鉴权**
    （它只含实验数字，鉴权会让「拷走就能交」失效）。
    """
    state = PlaygroundState(ctx, dashboard_path, refresh_s, client_key)
    # 暴露的是 /v1/scan（让本机替别人跑检测）、/v1/canary/issue（明文发令牌）
    # —— 配了 client_key 才算有门；绑非回环时 warn_if_exposed 会把缺门说出来。
    warn_if_exposed(host, service="检测台", authenticated=bool(client_key))
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
