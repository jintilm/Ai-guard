"""上游转发。

只做三件事：透传请求头中的必要字段、把上游响应原样搬回来、支持 SSE 流式。
不做任何改写 —— 代理的职责是检查，不是修改业务数据。
"""
from __future__ import annotations

import http.client
import json
import time
import urllib.error
import urllib.request
from collections.abc import Iterator

from prompt_ids.auth import HEADER as CLIENT_AUTH_HEADER

# 逐跳首部不能转发，否则客户端会解析错乱
_HOP_BY_HOP = frozenset({
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "transfer-encoding", "upgrade", "content-length",
    "host", "accept-encoding",
})

#: **本服务自己的**客户端凭据头，永不转发给上游。
#:
#: 客户端带 `X-API-Key` 是来证明「我有权调这个代理」的，与上游没有任何关系。
#: 转发出去的后果不只是「多一个无意义的头」：
#: - 不少网关看到不认识的 `X-API-Key` 会直接 401，症状看起来像**上游坏了**；
#: - 而它就是代理的鉴权口令 —— 一旦上游（或其日志、其错误回显）把它记下来，
#:   拿到它的人就能直接调用这个代理。凭据只该单向流动。
_NEVER_FORWARD = frozenset({CLIENT_AUTH_HEADER.lower()})


class UpstreamError(Exception):
    def __init__(self, status: int, body: str):
        super().__init__(f"上游返回 {status}")
        self.status = status
        self.body = body


def forward_headers(headers, client_key: str = "") -> dict[str, str]:
    """挑选可转发的请求头，并去掉逐跳字段与**本服务自己的**凭据。

    `client_key` 非空时，`Authorization` 若恰好等于它（`Bearer` 形式或裸值），
    也一并剥掉：`auth.authorized` 允许用 Bearer 承载客户端凭据，
    否则那条路径会把同一个口令透传给上游 —— 与 `X-API-Key` 同一个洞。
    只剥**完全相等**的值，所以真正的上游令牌不受影响。
    """
    out: dict[str, str] = {}
    for key, value in headers.items():
        lowered = key.lower()
        if lowered in _HOP_BY_HOP or lowered in _NEVER_FORWARD:
            continue
        if lowered.startswith("x-prompt-ids"):
            continue
        if client_key and lowered == "authorization" and _same_secret(value, client_key):
            continue
        out[key] = value
    out["accept-encoding"] = "identity"  # 避免拿到 gzip 后要额外解压
    return out


def _same_secret(value: str, client_key: str) -> bool:
    """`Authorization` 的值是不是本服务的客户端口令。"""
    text = (value or "").strip()
    if text.lower().startswith("bearer "):
        text = text[7:].strip()
    return bool(text) and text == client_key



def post_json(
    url: str,
    body: bytes,
    headers: dict[str, str],
    timeout_s: float = 60.0,
    max_bytes: int = 0,
) -> tuple[int, dict[str, str], bytes, float]:
    """非流式转发，返回 (状态码, 响应头, 响应体, 耗时ms)。

    `max_bytes` > 0 时给响应体一个**上限**：超限就只读那么多并返回。
    这是内存的硬边界 —— 上游说什么我们控制不了，而 `response.read()` 原本
    会把整个响应装进内存（一个上游故障或恶意的网关就能顶满代理进程）。
    超限时调用方拿到的 JSON 不完整，只能靠状态码/长度判断，不能当正常响应解析
    —— 所以宁可**报上游错误**也不静默给出半截响应。
    """
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    started = time.perf_counter()
    try:
        with urllib.request.urlopen(request, timeout=timeout_s) as response:
            if max_bytes:
                declared = response.headers.get("Content-Length")
                try:
                    if declared and int(declared) > max_bytes:
                        raise UpstreamError(
                            502,
                            json.dumps({"error": f"上游响应体过大（>{max_bytes} 字节），已拒收"},
                                       ensure_ascii=False).encode())
                except ValueError:
                    pass  # 头不可信，照常读，读超了再判
                payload = response.read(max_bytes + 1)
                if len(payload) > max_bytes:
                    raise UpstreamError(
                        502,
                        json.dumps({"error": f"上游响应体过大（>{max_bytes} 字节），已拒收"},
                                   ensure_ascii=False).encode())
            else:
                payload = response.read()
            return response.status, dict(response.headers), payload, (time.perf_counter() - started) * 1000
    except urllib.error.HTTPError as exc:
        payload = exc.read()
        return exc.code, dict(exc.headers or {}), payload, (time.perf_counter() - started) * 1000
    except (urllib.error.URLError, TimeoutError) as exc:
        raise UpstreamError(502, json.dumps({"error": f"上游不可达：{exc}"}, ensure_ascii=False).encode()) from exc
    except http.client.HTTPException as exc:
        # IncompleteRead / RemoteDisconnected 等**不是** OSError/URLError，
        # 不接住就是 traceback + 断连，而不是 502。
        raise UpstreamError(502, json.dumps({"error": f"上游响应不完整：{exc}"},
                                            ensure_ascii=False).encode()) from exc


def post_stream(
    url: str,
    body: bytes,
    headers: dict[str, str],
    timeout_s: float = 60.0,
):
    """流式转发：返回 (状态码, 响应头, chunk 迭代器, 耗时ms, 关连接的可调用对象)。

    第五个返回值是新增的：调用方负责在**任何**退出路径（正常结束、异常、客户端断开）
    上关掉上游连接。原来靠生成器的 `finally` 关，而 PEP 342 规定未启动的生成器
    `close()` 不执行任何代码 —— 于是「转发响应头就失败」这类路径上上游 socket 泄漏，
    只剩引用计数兜底。
    """
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    started = time.perf_counter()
    try:
        response = urllib.request.urlopen(request, timeout=timeout_s)
    except urllib.error.HTTPError as exc:
        payload = exc.read()
        exc.close()
        return exc.code, dict(exc.headers or {}), iter([payload]), \
            (time.perf_counter() - started) * 1000, (lambda: None)
    except (urllib.error.URLError, TimeoutError) as exc:
        raise UpstreamError(502, json.dumps({"error": f"上游不可达：{exc}"}, ensure_ascii=False).encode()) from exc
    return response.status, dict(response.headers), _iter_chunks(response), 0.0, response.close


def _iter_chunks(response) -> Iterator[bytes]:
    """分块读取并在结束时关闭上游连接，避免连接泄漏。"""
    try:
        while True:
            chunk = response.read1(4096)
            if not chunk:
                break
            yield chunk
    finally:
        response.close()
