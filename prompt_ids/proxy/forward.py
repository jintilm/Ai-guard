"""上游转发。

只做三件事：透传请求头中的必要字段、把上游响应原样搬回来、支持 SSE 流式。
不做任何改写 —— 代理的职责是检查，不是修改业务数据。
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from typing import Iterator

# 逐跳首部不能转发，否则客户端会解析错乱
_HOP_BY_HOP = frozenset({
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "transfer-encoding", "upgrade", "content-length",
    "host", "accept-encoding",
})


class UpstreamError(Exception):
    def __init__(self, status: int, body: str):
        super().__init__(f"上游返回 {status}")
        self.status = status
        self.body = body


def forward_headers(headers) -> dict[str, str]:
    """挑选可转发的请求头，并去掉逐跳字段。"""
    out: dict[str, str] = {}
    for key, value in headers.items():
        if key.lower() in _HOP_BY_HOP:
            continue
        if key.lower().startswith("x-") and key.lower().startswith("x-prompt-ids"):
            continue
        out[key] = value
    out["accept-encoding"] = "identity"  # 避免拿到 gzip 后要额外解压
    return out


def post_json(
    url: str,
    body: bytes,
    headers: dict[str, str],
    timeout_s: float = 60.0,
) -> tuple[int, dict[str, str], bytes, float]:
    """非流式转发，返回 (状态码, 响应头, 响应体, 耗时ms)。"""
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    started = time.perf_counter()
    try:
        with urllib.request.urlopen(request, timeout=timeout_s) as response:
            payload = response.read()
            return response.status, dict(response.headers), payload, (time.perf_counter() - started) * 1000
    except urllib.error.HTTPError as exc:
        payload = exc.read()
        return exc.code, dict(exc.headers or {}), payload, (time.perf_counter() - started) * 1000
    except (urllib.error.URLError, TimeoutError) as exc:
        raise UpstreamError(502, json.dumps({"error": f"上游不可达：{exc}"}, ensure_ascii=False).encode()) from exc


def post_stream(
    url: str,
    body: bytes,
    headers: dict[str, str],
    timeout_s: float = 60.0,
) -> tuple[int, dict[str, str], Iterator[bytes], float]:
    """流式转发：返回响应体的迭代句柄，调用方负责逐块写出。"""
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    started = time.perf_counter()
    try:
        response = urllib.request.urlopen(request, timeout=timeout_s)
    except urllib.error.HTTPError as exc:
        payload = exc.read()
        return exc.code, dict(exc.headers or {}), iter([payload]), (time.perf_counter() - started) * 1000
    except (urllib.error.URLError, TimeoutError) as exc:
        raise UpstreamError(502, json.dumps({"error": f"上游不可达：{exc}"}, ensure_ascii=False).encode()) from exc
    return response.status, dict(response.headers), _iter_chunks(response), 0.0


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
