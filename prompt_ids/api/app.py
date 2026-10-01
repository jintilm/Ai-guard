"""REST API 路由与处理逻辑。

设计约定（答辩时容易被问）：
- 检测服务用 **200 返回检出结果**。攻击与否是业务语义，不是 HTTP 错误；
  只有参数错误、鉴权失败、限流才用 4xx/5xx。
- 所有响应都是 JSON，错误也带结构化 body，便于客户端统一处理。
"""
from __future__ import annotations

import threading
import time
from typing import Any, Callable

from prompt_ids.audit.logger import AuditLogger
from prompt_ids.canary.tokens import CanaryRegistry
from prompt_ids.core.pipeline import Pipeline, PipelineConfig, create_pipeline
from prompt_ids.memory.detector import MemoryDetector

MAX_TEXT_CHARS = 50_000
MAX_BATCH = 200


class ApiError(Exception):
    def __init__(self, status: int, code: str, message: str):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


class ApiContext:
    """服务端共享状态：流水线、Canary 注册表、运行统计。"""

    def __init__(
        self,
        pipeline: Pipeline | None = None,
        canary: CanaryRegistry | None = None,
        semantic: bool = False,
        semantic_mode: str = "fallback",
        memory: bool = False,
        memory_encoder: str = "auto",
        memory_threshold: float = 0.86,
        memory_dir: str = "",
        audit: AuditLogger | None = None,
        audit_path: str = "",
    ):
        self.pipeline = pipeline or create_pipeline(
            config=PipelineConfig(
                semantic_enabled=semantic,
                semantic_mode=semantic_mode,
                memory_enabled=memory,
                memory_encoder=memory_encoder,
                memory_threshold=memory_threshold,
                memory_dir=memory_dir,
            )
        )
        self.canary = canary
        self.audit = audit or (AuditLogger(audit_path) if audit_path else None)
        self.started_at = time.time()
        self._lock = threading.Lock()
        self.stats: dict[str, Any] = {
            "scans": 0,
            "by_level": {},
            "by_action": {},
            "blocked": 0,
            "canary_checks": 0,
            "canary_leaks": 0,
        }

    def record(self, result) -> None:
        with self._lock:
            self.stats["scans"] += 1
            level = result.level.value
            action = result.action.value
            self.stats["by_level"][level] = self.stats["by_level"].get(level, 0) + 1
            self.stats["by_action"][action] = self.stats["by_action"].get(action, 0) + 1
            if result.is_blocked:
                self.stats["blocked"] += 1

    def record_canary(self, leaked: bool) -> None:
        with self._lock:
            self.stats["canary_checks"] += 1
            if leaked:
                self.stats["canary_leaks"] += 1

    @property
    def rule_detector(self):
        return self.pipeline.registry.get("rule")

    @property
    def memory(self):
        return self.pipeline.memory_detector


# ---------------------------------------------------------------- 参数校验
def _require_text(payload: Any) -> str:
    if not isinstance(payload, dict):
        raise ApiError(400, "bad_request", "请求体必须是 JSON 对象")
    text = payload.get("text")
    if not isinstance(text, str) or not text.strip():
        raise ApiError(400, "bad_request", "缺少 text 字段或为空")
    if len(text) > MAX_TEXT_CHARS:
        raise ApiError(413, "payload_too_large", f"text 超过 {MAX_TEXT_CHARS} 字符上限")
    return text


def _optional_key(payload: Any, name: str, default=None):
    return payload.get(name, default) if isinstance(payload, dict) else default


# ---------------------------------------------------------------- 处理器
def handle_scan(ctx: ApiContext, payload: Any, params: dict) -> tuple[int, dict]:
    text = _require_text(payload)
    user = str(_optional_key(payload, "user", "api") or "api")
    policy = _optional_key(payload, "policy", None)
    result = ctx.pipeline.scan(text, user=user, policy_name=policy)
    ctx.record(result)
    if ctx.audit is not None:
        ctx.audit.log_scan(result, text=text, user=user, source="api")
    body = result.to_dict()
    body["user"] = user
    return 200, body


def handle_scan_batch(ctx: ApiContext, payload: Any, params: dict) -> tuple[int, dict]:
    if not isinstance(payload, dict):
        raise ApiError(400, "bad_request", "请求体必须是 JSON 对象")
    texts = payload.get("texts")
    if not isinstance(texts, list) or not texts:
        raise ApiError(400, "bad_request", "texts 必须是非空数组")
    if len(texts) > MAX_BATCH:
        raise ApiError(413, "payload_too_large", f"批量上限 {MAX_BATCH} 条")
    cleaned: list[str] = []
    for item in texts:
        if not isinstance(item, str):
            raise ApiError(400, "bad_request", "texts 中每一项都必须是字符串")
        if len(item) > MAX_TEXT_CHARS:
            raise ApiError(413, "payload_too_large", "存在超长文本")
        cleaned.append(item)

    user = str(_optional_key(payload, "user", "api") or "api")
    results = [ctx.pipeline.scan(t, user=user) for t in cleaned]
    for r, t in zip(results, cleaned):
        ctx.record(r)
        if ctx.audit is not None:
            ctx.audit.log_scan(r, text=t, user=user, source="api:batch")
    blocked = sum(1 for r in results if r.is_blocked)
    return 200, {
        "count": len(results),
        "blocked": blocked,
        "results": [r.to_dict() for r in results],
    }


def handle_rules(ctx: ApiContext, payload: Any, params: dict) -> tuple[int, dict]:
    det = ctx.rule_detector
    if det is None:
        raise ApiError(503, "not_ready", "规则层未加载")
    book = det.rulebook if hasattr(det, "rulebook") else None
    stats = book.stats() if book else {}
    tier = _optional_key(payload, "tier", None)
    rules = [
        {
            "id": r.id,
            "category": r.category,
            "tier": r.tier,
            "weight": r.weight,
            "confidence": r.confidence,
            "description": r.description,
        }
        for r in det.active_rules
    ]
    if tier:
        rules = [r for r in rules if r["tier"] == tier]
    return 200, {"stats": stats, "count": len(rules), "rules": rules}


def handle_canary_issue(ctx: ApiContext, payload: Any, params: dict) -> tuple[int, dict]:
    if ctx.canary is None:
        raise ApiError(404, "not_enabled", "Canary 未启用，启动时加 --canary")
    label = str(_optional_key(payload, "label", "api") or "api")
    token = ctx.canary.issue(label)
    return 200, {
        "token": token.value,          # 服务端签发，需要把完整值交回调用方
        "label": token.label,
        "guard_instruction": token.guard_instruction(),
    }


def handle_canary_check(ctx: ApiContext, payload: Any, params: dict) -> tuple[int, dict]:
    if ctx.canary is None:
        raise ApiError(404, "not_enabled", "Canary 未启用，启动时加 --canary")
    text = _require_text(payload)
    match = ctx.canary.check(text)
    ctx.record_canary(match is not None)
    if ctx.audit is not None and match is not None:
        ctx.audit.log_leak(match, source="api")
    return 200, {
        "leaked": match is not None,
        "match": match.as_dict(public=True) if match else None,
        "tokens_known": len(ctx.canary),
    }


def _require_memory(ctx: ApiContext):
    if ctx.memory is None or not ctx.memory.enabled:
        raise ApiError(404, "not_enabled", "向量记忆库未启用，启动时加 --memory")
    return ctx.memory


def handle_memory_add(ctx: ApiContext, payload: Any, params: dict) -> tuple[int, dict]:
    """灌入已知攻击/误报样本，label 默认 1（攻击）。"""
    mem = _require_memory(ctx)
    if not isinstance(payload, dict):
        raise ApiError(400, "bad_request", "请求体必须是 JSON 对象")
    texts = payload.get("texts") or ([payload["text"]] if "text" in payload else None)
    if not isinstance(texts, list) or not texts:
        raise ApiError(400, "bad_request", "需要 text 或 texts 字段")
    if len(texts) > MAX_BATCH:
        raise ApiError(413, "payload_too_large", f"批量上限 {MAX_BATCH} 条")
    label = int(payload.get("label", 1))
    source = str(payload.get("source", "api"))
    added = mem.learn_many([str(t) for t in texts], label=label, source=source)
    return 200, {"requested": len(texts), "added": added, "total": len(mem.store)}


def handle_memory_search(ctx: ApiContext, payload: Any, params: dict) -> tuple[int, dict]:
    mem = _require_memory(ctx)
    text = _require_text(payload)
    k = int(payload.get("k", 5)) if isinstance(payload, dict) else 5
    vector = mem.encoder.encode_one(text)
    hits = mem.store.search(vector, k=min(k, 20))
    return 200, {
        "count": len(hits),
        "hits": [
            {"similarity": round(h.similarity, 4), "fp": h.item.fp[:12],
             "label": h.item.label, "source": h.item.source}
            for h in hits
        ],
    }


def handle_memory_stats(ctx: ApiContext, payload: Any, params: dict) -> tuple[int, dict]:
    mem = _require_memory(ctx)
    return 200, mem.stats()


def handle_memory_feedback(ctx: ApiContext, payload: Any, params: dict) -> tuple[int, dict]:
    """人工反馈：误报标记会写成负向记忆，下次把分数压下去。"""
    mem = _require_memory(ctx)
    text = _require_text(payload)
    is_attack = bool(payload.get("is_attack", True))
    ok = mem.feedback(text, is_attack=is_attack, note="api feedback")
    return 200, {
        "recorded": ok,
        "label": 1 if is_attack else 0,
        "total": len(mem.store),
    }


def handle_events(ctx: ApiContext, payload: Any, params: dict) -> tuple[int, dict]:
    """最近审计事件（只含指纹，不含原文），供实时看板滚动展示。

    读的是审计文件尾部，不额外维护一份内存缓冲 —— 与命令行 `tail -f`、
    离线分析看到的完全是同一份数据，不会出现「页面显示的和服务记录的不一致」。
    """
    try:
        limit = max(1, min(200, int(params.get("limit", 50))))
    except (TypeError, ValueError):
        limit = 50
    logger = ctx.audit
    if logger is None or not logger.enabled or logger.path is None:
        return 200, {"enabled": False, "count": 0, "events": []}
    logger.flush()  # 缓冲写模式下先把待写事件落盘，保证读到的是最新
    from prompt_ids.audit.logger import tail_events

    events = tail_events(logger.path, limit=limit)
    return 200, {
        "enabled": True,
        "count": len(events),
        "path": str(logger.path),
        "events": [e.to_dict() for e in events],
    }


def handle_metrics(ctx: ApiContext, payload: Any, params: dict) -> tuple[int, dict]:
    det = ctx.rule_detector
    book = det.rulebook if det and hasattr(det, "rulebook") else None
    uptime = time.time() - ctx.started_at
    return 200, {
        "uptime_s": round(uptime, 1),
        "rules": book.stats() if book else {},
        "stats": dict(ctx.stats),
        "detectors": ctx.pipeline.registry.names(),
        "semantic": {
            "enabled": bool(ctx.pipeline.semantic_detector and ctx.pipeline.semantic_detector.enabled),
            "info": ctx.pipeline.semantic_detector.stats() if ctx.pipeline.semantic_detector else {},
        },
        "canary": ctx.canary.stats() if ctx.canary else None,
    }


def handle_health(ctx: ApiContext, payload: Any, params: dict) -> tuple[int, dict]:
    return 200, {
        "status": "ok",
        "uptime_s": round(time.time() - ctx.started_at, 1),
        "rules": len(ctx.rule_detector.active_rules) if ctx.rule_detector else 0,
    }


def handle_providers(ctx: ApiContext, payload: Any, params: dict) -> tuple[int, dict]:
    """当前的语义后端 + LLM 提供商可用性清单。

    给前端（看板/检测台）和运维用：一眼看清「现在实际在用哪一家」，
    避免出现「以为在用 DeepSeek、其实静默降级到轻量模型」这种错觉。
    """
    from prompt_ids.detectors.semantic.factory import provider_table

    detector = ctx.pipeline.semantic_detector
    backend = getattr(detector, "backend", None) if detector else None
    active = backend.info() if backend is not None else {}
    active.pop("providers", None)  # 21 家清单已在下面单独给，避免重复
    return 200, {
        "active": {
            "semantic_enabled": bool(detector and detector.enabled),
            "mode": getattr(detector, "mode", ""),
            "backend": getattr(backend, "name", "null"),
            **active,
        },
        "providers": provider_table(),
    }


def handle_openapi(ctx: ApiContext, payload: Any, params: dict) -> tuple[int, dict]:
    return 200, OPENAPI


# ---------------------------------------------------------------- 路由表
Handler = Callable[[ApiContext, Any, dict], tuple[int, dict]]

ROUTES: list[tuple[str, str, Handler]] = [
    ("POST", "/v1/scan", handle_scan),
    ("POST", "/v1/scan/batch", handle_scan_batch),
    ("GET", "/v1/rules", handle_rules),
    ("POST", "/v1/canary/issue", handle_canary_issue),
    ("POST", "/v1/canary/check", handle_canary_check),
    ("POST", "/v1/memory/add", handle_memory_add),
    ("POST", "/v1/memory/search", handle_memory_search),
    ("POST", "/v1/memory/feedback", handle_memory_feedback),
    ("GET", "/v1/memory/stats", handle_memory_stats),
    ("GET", "/v1/providers", handle_providers),
    ("GET", "/v1/metrics", handle_metrics),
    ("GET", "/v1/events", handle_events),
    ("GET", "/v1/openapi.json", handle_openapi),
    ("GET", "/healthz", handle_health),
    ("GET", "/health", handle_health),
]

OPENAPI = {
    "openapi": "3.0.3",
    "info": {
        "title": "prompt-ids REST API",
        "version": "0.1.0",
        "description": "提示词注入检测服务：文本检测、规则库查询、Canary 令牌、运行指标。",
    },
    "paths": {},
}


def resolve(method: str, path: str) -> Handler | None:
    """精确匹配路由（路径参数当前不需要，保持简单）。"""
    clean = path.split("?")[0].rstrip("/") or "/"
    for verb, route, handler in ROUTES:
        if verb == method and route.rstrip("/") == clean:
            return handler
    return None
