"""遥测出口 —— OTLP/JSON 与 Langfuse，**零第三方依赖**。

## 为什么不引 OTel SDK

本项目的硬约束是「**看板与检测台运行时零外部依赖**」，而 OTel SDK 会把
protobuf + grpc + 若干传递依赖拖进来。为了「能导出 trace」而让「能不能跑」
取决于 pip 装得对不对，是本末倒置。所以这里手写 **OTLP/JSON**（OTLP 的官方
JSON 编码）用标准库 `urllib` 发出去：collector 侧不需要任何改动就能收。

Langfuse 走同一条路 —— 它 v3 的摄取端点本身就是 OTLP 兼容的
（`<host>/api/public/otel/v1/traces`，HTTP Basic 认证，public key 作用户名）。
所以「OTLP」和「Langfuse」在本实现里只是 **endpoint + 认证头不同**。

## 不可违背的一条：属性里绝不放原文

审计层只落指纹，是这个项目反复确认过的边界（`test_audit_never_writes_original_text`）。
遥测比审计层**走得更远** —— 它会被送到第三方 SaaS、会被长期留存、会被导出到
别人的 Grafana。所以这里用**白名单**而不是黑名单：

- 只有 :data:`ALLOWED_ATTRIBUTES` 里的键能出网，其余**静默丢弃**并在计数器里记账
- 值必须是数值/布尔/短字符串；超过 :data:`MAX_VALUE_CHARS` 的字符串一律丢弃
  （白名单里唯一的长文本是 pattern_id 列表，仍然受长度限制）
- 唯一与内容相关的标识是**指纹**（16 hex），它不可逆、不可检索

用白名单而不是「把明显像原文的键剔掉」的理由：黑名单永远漏一个
（`query` / `body` / `args` / `question` …），而白名单漏不掉 ——
新增属性必须先在这里登记，登记时就必须回答「这个值会不会携带原文」。

## 失败不许影响检测，也不许静默

导出失败（collector 挂了、网络超时、4xx）**绝不能**让扫描失败。
但按本项目纪律「宁可响亮失败也不静默降级」，所以：

- 失败计数 + `degraded` 标志进 `/v1/metrics` 的 `observability` 段
- 首次失败往 **stderr** 打一行（之后不再重复，避免刷屏）
- 读数里 `emitted` / `failed` / `dropped_attributes` 三个数必须与 trace 一起看

配置（全部走环境变量，`prompt_ids.env` 会在 import 期读 `.env`）::

    PROMPT_IDS_OBSERVABILITY=otlp|langfuse|off   # 默认 off
    PROMPT_IDS_OTEL_ENDPOINT=http://localhost:4318/v1/traces
    PROMPT_IDS_OTEL_SERVICE=prompt-ids
    PROMPT_IDS_OBSERVABILITY_TIMEOUT_S=2.0
    # Langfuse 专用（选 langfuse 时才需要）
    PROMPT_IDS_LANGFUSE_HOST=https://cloud.langfuse.com
    PROMPT_IDS_LANGFUSE_PUBLIC_KEY=...
    PROMPT_IDS_LANGFUSE_SECRET_KEY=...
"""
from __future__ import annotations

import base64
import json
import os
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass, field
from typing import Any

#: 唯一允许出网的属性键。**新增键必须先回答「这个值会不会携带原文」。**
ALLOWED_ATTRIBUTES: frozenset[str] = frozenset({
    # 判定
    "score", "level", "action", "policy", "tiers",
    # 证据（只有 id 与类别，没有 evidence 原文）
    "pattern_ids", "pattern_categories", "findings_count",
    # 执行
    "semantic_backend", "semantic_model", "semantic_calls", "semantic_abstained",
    "semantic_failed_share", "semantic_degraded", "memory_used", "cache_hit",
    "skipped_layers", "truncated", "rejected_reason",
    # 耗时
    "latency_ms_total", "latency_ms_preprocess", "latency_ms_rule",
    "latency_ms_heuristic", "latency_ms_semantic", "latency_ms_memory",
    "cold_start_ms",
    # 请求形态（不含内容）
    "text_chars", "user", "route", "decision", "outbound", "secret_kinds",
    # 标识
    "fingerprint", "trace_id",
})

#: 单个属性值的字符上限。超了直接丢，不做截断 —— 截断后的片段仍可能是原文。
MAX_VALUE_CHARS = 200

#: 一批多少条 span 落一次盘/发一次。1 = 逐条发（延迟最低，失败不影响别人）。
BATCH_SIZE = 1


def _env(name: str, default: str = "") -> str:
    return (os.environ.get(name, default) or "").strip()


def _env_float(name: str, default: float) -> float:
    try:
        return float(_env(name) or default)
    except (TypeError, ValueError):
        return default


@dataclass(slots=True)
class Span:
    """一条最小 span。字段名按 OTLP 语义命名，便于直接序列化。"""

    name: str
    trace_id: str
    span_id: str
    start_unix_nano: int
    end_unix_nano: int
    attributes: dict[str, Any] = field(default_factory=dict)
    status_code: int = 1          # 1=OK  2=ERROR
    status_message: str = ""

    def to_otlp(self) -> dict[str, Any]:
        return {
            "traceId": self.trace_id,
            "spanId": self.span_id,
            "name": self.name,
            "kind": 1,                       # SPAN_KIND_INTERNAL
            "startTimeUnixNano": str(self.start_unix_nano),
            "endTimeUnixNano": str(self.end_unix_nano),
            "attributes": [
                {"key": key, "value": _otlp_value(value)}
                for key, value in self.attributes.items()
            ],
            "status": {"code": self.status_code},
        }


def _otlp_value(value: Any) -> dict[str, Any]:
    if isinstance(value, bool):
        return {"boolValue": value}
    if isinstance(value, int):
        return {"intValue": str(value)}
    if isinstance(value, float):
        return {"doubleValue": value}
    if isinstance(value, (list, tuple)):
        return {"arrayValue": {"values": [_otlp_value(v) for v in value]}}
    return {"stringValue": str(value)}


def sanitize(attributes: dict[str, Any]) -> tuple[dict[str, Any], int]:
    """按白名单 + 长度上限过滤属性，返回 (可发送的, 被丢弃的键数)。

    这是本模块唯一的内容安全边界，所以做成**纯函数**便于直接断言。
    """
    kept: dict[str, Any] = {}
    dropped = 0
    for key, value in attributes.items():
        if key not in ALLOWED_ATTRIBUTES:
            dropped += 1
            continue
        if value is None:
            continue
        if isinstance(value, str) and len(value) > MAX_VALUE_CHARS:
            dropped += 1
            continue
        if isinstance(value, (list, tuple)):
            # 列表里的每一项也要过长度上限 —— 有人可能把原文塞进 pattern_ids
            if any(isinstance(v, str) and len(v) > MAX_VALUE_CHARS for v in value):
                dropped += 1
                continue
            kept[key] = list(value)
            continue
        kept[key] = value
    return kept, dropped


@dataclass(slots=True)
class _Counters:
    emitted: int = 0
    failed: int = 0
    dropped_attributes: int = 0
    last_error: str = ""
    degraded: bool = False
    warned: bool = False


class Exporter:
    """基类**同时就是「关闭」实现**（`_endpoint()` 返回空串 ⇒ `enabled()` 为 False）。

    刻意不用 `NotImplementedError`：关掉遥测是这个模块的默认路径，
    让默认路径去抛异常只会在每次 `Pipeline()` 构造时炸一次。
    真要加新协议就继承并覆盖 `_endpoint()` / `_headers()`，
    `kind` 决定 `/v1/metrics` 里显示成什么。
    """

    kind = "off"

    def __init__(self) -> None:
        self.counters = _Counters()
        self._lock = threading.Lock()

    # -- 子类覆盖 -------------------------------------------------
    def _endpoint(self) -> str:
        return ""

    def _headers(self) -> dict[str, str]:
        return {"Content-Type": "application/json"}

    # -- 公共 ----------------------------------------------------
    def enabled(self) -> bool:
        return bool(self._endpoint())

    def export(self, spans: list[Span]) -> None:
        """发一批 span。**任何失败都不许抛给调用方**（不能让检测因遥测失败）。"""
        if not spans or not self.enabled():
            return
        payload = {
            "resourceSpans": [{
                "resource": {"attributes": [
                    {"key": "service.name",
                     "value": {"stringValue": _env("PROMPT_IDS_OTEL_SERVICE", "prompt-ids")}},
                    {"key": "telemetry.sdk.name", "value": {"stringValue": "prompt-ids-otlp-json"}},
                ]},
                "scopeSpans": [{"scope": {"name": "prompt_ids.observability"},
                                "spans": [span.to_otlp() for span in spans]}],
            }],
        }
        body = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            self._endpoint(), data=body, method="POST", headers=self._headers())
        try:
            with urllib.request.urlopen(request, timeout=self._timeout()) as response:
                ok = 200 <= response.status < 300
                detail = "" if ok else f"HTTP {response.status}"
        except urllib.error.HTTPError as exc:
            ok, detail = False, f"HTTP {exc.code}"
        except Exception as exc:  # noqa: BLE001 - 遥测失败不许影响检测
            ok, detail = False, f"{type(exc).__name__}: {exc}"
        with self._lock:
            if ok:
                self.counters.emitted += len(spans)
                # 一次成功就恢复「健康」：否则 degraded 会永久粘住
                self.counters.degraded = False
            else:
                self.counters.failed += len(spans)
                self.counters.last_error = detail
                self.counters.degraded = True
                if not self.counters.warned:
                    self.counters.warned = True
                    print(f"[observability] 遥测导出失败（{detail}）→ "
                          f"http://{self._masked_endpoint()}；检测本身不受影响，"
                          f"失败计数见 /v1/metrics 的 observability 段",
                          file=sys.stderr)

    def _timeout(self) -> float:
        return _env_float("PROMPT_IDS_OBSERVABILITY_TIMEOUT_S", 2.0)

    def _masked_endpoint(self) -> str:
        """端点可能内嵌凭据（某些网关把 token 放 query），打印时抹掉 userinfo 与 query。"""
        endpoint = self._endpoint()
        head, sep, _query = endpoint.partition("?")
        scheme, _, rest = head.partition("://")
        if "@" in rest:
            rest = "***@" + rest.split("@", 1)[1]
        return scheme + "://" + rest + (sep and "?<redacted>")

    def stats(self) -> dict[str, Any]:
        with self._lock:
            return {
                "kind": self.kind,
                "enabled": self.enabled(),
                "emitted": self.counters.emitted,
                "failed": self.counters.failed,
                "dropped_attributes": self.counters.dropped_attributes,
                "degraded": self.counters.degraded,
                "last_error": self.counters.last_error,
                "allowed_attributes": len(ALLOWED_ATTRIBUTES),
            }


class OtlpExporter(Exporter):
    kind = "otlp"

    def _endpoint(self) -> str:
        return _env("PROMPT_IDS_OTEL_ENDPOINT")


class LangfuseExporter(Exporter):
    """Langfuse 的摄取端点本身就是 OTLP 兼容的，只是路径与认证不同。"""

    kind = "langfuse"

    def _endpoint(self) -> str:
        host = _env("PROMPT_IDS_LANGFUSE_HOST")
        if not host:
            return ""
        return host.rstrip("/") + "/api/public/otel/v1/traces"

    def _headers(self) -> dict[str, str]:
        public = _env("PROMPT_IDS_LANGFUSE_PUBLIC_KEY")
        secret = _env("PROMPT_IDS_LANGFUSE_SECRET_KEY")
        headers = {"Content-Type": "application/json"}
        if public and secret:
            token = base64.b64encode(f"{public}:{secret}".encode()).decode()
            headers["Authorization"] = f"Basic {token}"
        return headers


def _build_exporter() -> Exporter:
    kind = (_env("PROMPT_IDS_OBSERVABILITY") or "off").lower()
    if kind == "otlp":
        return OtlpExporter()
    if kind == "langfuse":
        return LangfuseExporter()
    return Exporter()


#: 进程级单例。构造一次（env 定），并发安全（内部锁）。
_EXPORTER: Exporter | None = None
_EXPORTER_LOCK = threading.Lock()


def exporter() -> Exporter:
    global _EXPORTER
    if _EXPORTER is None:
        with _EXPORTER_LOCK:
            if _EXPORTER is None:
                _EXPORTER = _build_exporter()
    return _EXPORTER


def reset_exporter() -> None:
    """只给测试与「运行中改 env」用：丢掉单例，下次调用重新按 env 建。"""
    global _EXPORTER
    with _EXPORTER_LOCK:
        _EXPORTER = None


def new_trace_id() -> str:
    return uuid.uuid4().hex


def emit_scan(*, result: Any, user: str = "default", policy: str = "",
              text_chars: int = 0, trace_id: str | None = None,
              route: str = "", cold_start_ms: float = 0.0,
              semantic: dict[str, Any] | None = None) -> str | None:
    """把一次扫描发成一个 span。**未启用时立即返回，代价≈0。**

    `result` 是 `ScanResult`（鸭子类型，避免在此处 import core 以免循环依赖）。
    `semantic` 是语义层 `stats()` 的子集，用来让「L3 弃权」在 trace 里可见 ——
    否则 trace 上只看到判定，看不到这一分可能是「L3 挂了退回规则层」的产物。
    """
    out = exporter()
    if not out.enabled():
        return None
    now = time.time_ns()
    latency = dict(getattr(result, "latency_ms", {}) or {})
    attributes: dict[str, Any] = {
        "score": round(float(getattr(result, "score", 0.0)), 2),
        "level": getattr(getattr(result, "level", None), "value", ""),
        "action": getattr(getattr(result, "action", None), "value", ""),
        "policy": policy or "",
        "findings_count": len(getattr(result, "findings", []) or []),
        "fingerprint": getattr(result, "fingerprint", "") or "",
        "text_chars": text_chars,
        "user": user,
        "route": route,
        "cache_hit": bool(getattr(result, "cached", False)),
        "truncated": bool(getattr(result, "truncated", False)),
        "cold_start_ms": round(cold_start_ms, 2),
        "latency_ms_total": round(float(latency.get("total", 0.0)), 2),
    }
    for key in ("preprocess", "rule", "heuristic", "semantic", "memory"):
        if key in latency:
            attributes[f"latency_ms_{key}"] = round(float(latency[key]), 2)
    findings = getattr(result, "findings", []) or []
    if findings:
        attributes["pattern_ids"] = [f.pattern_id for f in findings]
        attributes["pattern_categories"] = sorted({f.category for f in findings})
    skipped = getattr(result, "skipped", ()) or ()
    if skipped:
        attributes["skipped_layers"] = list(skipped)
    if getattr(result, "rejected", ""):
        attributes["rejected_reason"] = "length"
    if semantic:
        attributes["semantic_backend"] = str(semantic.get("backend", ""))
        attributes["semantic_model"] = str(semantic.get("model", ""))
        attributes["semantic_calls"] = int(semantic.get("calls", 0) or 0)
        attributes["semantic_abstained"] = int(semantic.get("abstained", 0) or 0)
        attributes["semantic_failed_share"] = float(semantic.get("failed_share", 0.0) or 0.0)
        attributes["semantic_degraded"] = bool(semantic.get("degraded"))

    kept, dropped = sanitize(attributes)
    with out._lock:
        out.counters.dropped_attributes += dropped
    trace = trace_id or new_trace_id()
    kept["trace_id"] = trace
    span = Span(
        name="prompt_ids.scan",
        trace_id=trace,
        span_id=uuid.uuid4().hex[:16],
        start_unix_nano=now - int(float(latency.get("total", 0.0)) * 1_000_000),
        end_unix_nano=now,
        attributes=kept,
    )
    out.export([span])
    return trace


def emit_decision(*, decision: str, extra: dict[str, Any] | None = None,
                  trace_id: str | None = None, route: str = "") -> str | None:
    """把代理/服务侧的**处置结论**发成一个 span（不含原文）。

    单独一个 span 而不是塞进 scan span 的原因：一次请求可能扫多段
    （`system#-1`、`tool#2`…），每段一个 scan span，而「这条请求最终怎么处理」
    是它们的上层结论 —— 混在一起会让人误以为一个 span 对应一次请求。
    """
    out = exporter()
    if not out.enabled():
        return None
    payload = {"decision": decision, "route": route, **(extra or {})}
    kept, dropped = sanitize(payload)
    with out._lock:
        out.counters.dropped_attributes += dropped
    trace = trace_id or new_trace_id()
    now = time.time_ns()
    out.export([Span(
        name="prompt_ids.decision",
        trace_id=trace,
        span_id=uuid.uuid4().hex[:16],
        start_unix_nano=now,
        end_unix_nano=now,
        attributes={**kept, "trace_id": trace},
    )])
    return trace


def stats() -> dict[str, Any]:
    """进 `/v1/metrics` 的读数。`kind == "off"` 时也要给出，让用户知道有这条路。"""
    return exporter().stats()
