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
from prompt_ids.output import MAX_HITS, redact, scan_text

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
        review_corpus: Any | None = None,
        review_corpus_path: str = "",
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
        if review_corpus is not None:
            self.review_corpus = review_corpus
        elif review_corpus_path:
            from prompt_ids.audit.review_corpus import ReviewCorpus

            self.review_corpus = ReviewCorpus(review_corpus_path)
        else:
            self.review_corpus = None
        self.started_at = time.time()
        self._lock = threading.Lock()
        self.stats: dict[str, Any] = {
            "scans": 0,
            "by_level": {},
            "by_action": {},
            "blocked": 0,
            "canary_checks": 0,
            "canary_leaks": 0,
            "output_checks": 0,
            "output_secret_hits": 0,
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

    def record_output_scan(self, hits: int) -> None:
        with self._lock:
            self.stats["output_checks"] += 1
            if hits:
                self.stats["output_secret_hits"] += int(hits)

    def record_review(self, is_attack: bool) -> None:
        with self._lock:
            self.stats["reviews"] = self.stats.get("reviews", 0) + 1
            key = "reviews_confirmed" if is_attack else "reviews_false_positive"
            self.stats[key] = self.stats.get(key, 0) + 1

    def review_stats(self) -> dict[str, Any]:
        """进程内的复核计数（与审计文件里的统计口径一致，数字不同是因为范围不同）。

        这里数的是**本次进程启动以来**的复核；`/v1/review/queue` 里的那份从
        审计文件读，能跨进程、含重启前的记录。
        """
        with self._lock:
            total = int(self.stats.get("reviews", 0))
            fp = int(self.stats.get("reviews_false_positive", 0))
            return {
                "reviews": total,
                "confirmed_attack": int(self.stats.get("reviews_confirmed", 0)),
                "false_positive": fp,
                "false_positive_rate_on_reviewed": round(fp / total, 4) if total else 0.0,
                "scope": "process",
            }

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


def _require_bool(payload: Any, name: str, default: bool) -> bool:
    """布尔字段必须是 JSON 布尔。

    `bool(payload["is_attack"])` 会把字符串 `"false"` 判成 **True** ——
    于是一条良性文本被当成「已确认攻击」写进记忆库与复核语料，
    之后所有相似请求都被判高危。`1`/`0` 也不接受：它们与 `"1"` 混用时，
    调用方自己都说不清写的是什么。
    """
    if not isinstance(payload, dict):
        return default
    value = payload.get(name, default)
    if not isinstance(value, bool):
        raise ApiError(400, "bad_request", f"{name} 必须是 JSON 布尔 true/false")
    return value


def _require_int(payload: Any, name: str, default: int, *, low: int | None = None,
                 high: int | None = None) -> int:
    """整数字段做类型 + 范围校验，让 ValueError 变成 400 而不是 500。"""
    if not isinstance(payload, dict):
        return default
    value = payload.get(name, default)
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise ApiError(400, "bad_request", f"{name} 必须是整数")
    try:
        number = int(value)
    except (TypeError, ValueError):
        raise ApiError(400, "bad_request", f"{name} 必须是整数")
    if low is not None and number < low:
        raise ApiError(400, "bad_request", f"{name} 不能小于 {low}")
    if high is not None and number > high:
        raise ApiError(400, "bad_request", f"{name} 不能大于 {high}")
    return number


def _require_str(payload: Any, name: str, default: str = "", *, choices=None) -> str:
    value = payload.get(name, default) if isinstance(payload, dict) else default
    if value is None:
        value = default
    if not isinstance(value, str):
        raise ApiError(400, "bad_request", f"{name} 必须是字符串")
    if choices and value not in choices:
        raise ApiError(400, "bad_request", f"{name} 只能是 {sorted(choices)}")
    return value


def _clamp_int(value: Any, *, default: int, low: int, high: int) -> int:
    """查询参数里的整数：解析不了就用默认值，**不因为一个 ?limit=abc 就 500**。

    这些是 GET 端点的分页参数，调用方拼错一个字符不该让整个请求失败；
    也不该让「解析失败」变成静默的默认值（那会让调用方以为 limit 生效了）。
    返回值同时用于响应里的回显。
    """
    if value is None or value == "":
        return default
    try:
        number = int(value)
    except (TypeError, ValueError):
        return default
    return max(low, min(high, number))


# ---------------------------------------------------------------- 处理器
def handle_scan(ctx: ApiContext, payload: Any, params: dict) -> tuple[int, dict]:
    text = _require_text(payload)
    user = _require_str(payload, "user", "api") or "api"
    # policy 原样透传给 PolicyEngine：`[]`/`{}` 会变成 `TypeError: unhashable` → 500。
    # 这里先做类型校验，未知策略名交给 PolicyEngine.resolve（它会响亮回退并可见）。
    policy = payload.get("policy") if isinstance(payload, dict) else None
    if policy is not None and not isinstance(policy, str):
        raise ApiError(400, "bad_request", "policy 必须是字符串（default/strict/permissive/log-only）")
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


def handle_output_scan(ctx: ApiContext, payload: Any, params: dict) -> tuple[int, dict]:
    """出站扫描：把模型输出交上来，看里面有没有第三方凭据。

    代理会在转发路径上自动做这件事（`ProxyConfig.scan_secrets`）；
    这个端点给**不经过代理**的调用方用 —— 自己接 LLM SDK 的应用、离线批处理、
    以及检测台里手贴一段输出试阈值。
    """
    text = _require_text(payload)
    scan = scan_text(text)
    ctx.record_output_scan(len(scan))
    reported = scan.reported(MAX_HITS)
    return 200, {
        "found": len(scan),
        "by_kind": scan.by_kind,
        # 上限只影响上报条数；脱敏走全量命中，所以「found > secrets 长度」是正常的
        "reported": len(reported),
        "truncated": len(reported) < len(scan),
        # 只回脱敏形态与类别：把完整凭据回吐给调用方等于凭空多一个泄露面
        "secrets": [h.as_dict() for h in reported],
        "redacted": redact(text, scan.hits),
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
    label = _require_int(payload, "label", 1, low=0, high=1)
    source = _require_str(payload, "source", "api")
    # 单条长度也要卡：不卡的话一条 2MB 文本就能吃掉编码器的 CPU 与 20000 条配额
    cleaned: list[str] = []
    for item in texts:
        if not isinstance(item, str):
            raise ApiError(400, "bad_request", "texts 里每一项都必须是字符串")
        if len(item) > MAX_TEXT_CHARS:
            raise ApiError(413, "payload_too_large",
                           f"单条文本超过上限 {MAX_TEXT_CHARS} 字符")
        cleaned.append(item)
    added = mem.learn_many(cleaned, label=label, source=source)
    return 200, {"requested": len(cleaned), "added": added, "total": len(mem.store)}


def handle_memory_search(ctx: ApiContext, payload: Any, params: dict) -> tuple[int, dict]:
    mem = _require_memory(ctx)
    text = _require_text(payload)
    k = _require_int(payload, "k", 5, low=1, high=20)
    try:
        vector = mem.encoder.encode_one(text)
    except Exception as exc:  # 编码器不可用（模型没下载/维度不对）不该变成 500
        raise ApiError(503, "encoder_unavailable", f"编码器不可用：{type(exc).__name__}")
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
    # 必须是真布尔：`bool("false")` 是 True，会把良性文本写成「已确认攻击」
    is_attack = _require_bool(payload, "is_attack", True)
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
    limit = _clamp_int(params.get("limit"), default=50, low=1, high=200)
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


def handle_review(ctx: ApiContext, payload: Any, params: dict) -> tuple[int, dict]:
    """提交人工复核结论：定性一条文本，并把结论喂回记忆层。

    为什么要有这个接口：检测层只能给建议，`medium` 这一档在生产里是
    「放行但记一笔」还是「进人工队列」由业务决定。同类系统（Lakera 的
    Detect/Enforce 两档、Calypso 的可解释检测）都把这条人工回路当标配 ——
    没有它，误报只能靠用户投诉发现，而投诉不会告诉你「哪条规则该改」。

    两处刻意的设计：
    - **原文由调用方提供**，服务端不试图从日志里还原（审计层压根不存原文）。
    - **审计只记指纹与结论**，与所有其他入口同一套字段，不新增日志格式。
    """
    if not isinstance(payload, dict):
        raise ApiError(400, "bad_request", "请求体必须是 JSON 对象")
    text = _require_text(payload)
    if "is_attack" not in payload:
        raise ApiError(400, "bad_request", "缺少 is_attack 字段（true=确认攻击，false=误报）")
    # 必须真布尔：`bool("false")` 是 True ⇒ 一条良性文本被当成「已确认攻击」
    # 写进记忆库与复核语料，规则迭代语料与后续判定一起被污染。
    is_attack = _require_bool(payload, "is_attack", True)
    reviewer = _require_str(payload, "reviewer", "api")
    note = _require_str(payload, "note", "")

    try:
        outcome = ctx.pipeline.review(text, is_attack=is_attack, reviewer=reviewer, note=note)
    except ValueError as exc:
        raise ApiError(400, "bad_request", str(exc)) from exc

    if ctx.audit is not None:
        ctx.audit.log_review(
            fp=outcome["fingerprint"], is_attack=is_attack, reviewer=reviewer,
            level=outcome["level"], score=outcome["score"],
            patterns=tuple(outcome.get("patterns") or ()),
            top_pattern=outcome.get("top_pattern", ""),
            note=note or outcome["verdict"], memory_absorbed=outcome["memory_absorbed"],
            source="api",
        )
    # 复核语料（含原文，刻意与审计层分开的第二个数据面）。
    # 显式配置了才写；写了要能看见写没写成 —— 静默失败会让「反哺」看起来是通的。
    corpus_written = None
    corpus_error = ""
    if ctx.review_corpus is not None:
        corpus_written = ctx.review_corpus.add(
            text=text, is_attack=is_attack, fp=outcome["fingerprint"],
            patterns=tuple(outcome.get("patterns") or ()),
            top_pattern=outcome.get("top_pattern", ""),
            level=outcome["level"], score=outcome["score"],
            reviewer=reviewer, note=note)
        errors = ctx.review_corpus.stats().get("errors") or []
        if errors and not corpus_written:
            corpus_error = errors[-1]
    ctx.record_review(is_attack)
    body = dict(outcome)
    body["reviewer"] = reviewer
    body["note"] = note
    body["reviews"] = ctx.review_stats()
    body["corpus"] = {
        "enabled": ctx.review_corpus is not None,
        "written": corpus_written,
        "error": corpus_error,
    }
    return 200, body


def handle_review_patterns(ctx: ApiContext, payload: Any, params: dict) -> tuple[int, dict]:
    """规则级复核台账：每条规则判对多少次、误报多少次，以及误报嫌疑榜。

    这是「反哺规则」的读数端 —— 有了它，「PV-C001 是不是在乱杀人」才有答案。
    只读，不改任何规则：候选只给建议，动作由人做（理由见 `query.rule_suspects`）。
    """
    logger = ctx.audit
    base: dict[str, Any] = {
        "corpus": ctx.review_corpus.stats() if ctx.review_corpus is not None
        else {"enabled": False},
    }
    if logger is None or not logger.enabled or logger.path is None:
        return 200, {**base, "enabled": False, "ledger": {}, "suspects": [],
                     "reason": "未配置审计日志，启动时加 --audit"}
    logger.flush()
    from prompt_ids.audit.logger import tail_events
    from prompt_ids.audit.query import rule_ledger, rule_suspects

    # limit 可调（此前写死 5000）：读尾成本与 limit 成正比（实测 9MB 审计文件
    # limit=50 是 0.8ms、limit=5000 是 42.9ms），而这个端点默认无鉴权、
    # 无默认限流，写死 5000 等于每次未认证 GET 都固定付 ~48ms。
    limit = _clamp_int(params.get("limit"), default=1000, low=1, high=20000)
    events = tail_events(logger.path, limit=limit)
    ledger = rule_ledger(events)
    suspects = rule_suspects(ledger)
    return 200, {
        **base,
        "enabled": True,
        "limit": limit,
        "scanned_events": len(events),
        "ledger": dict(sorted(ledger.items(), key=lambda kv: -kv[1]["total"])),
        "suspects": suspects,
        "note": "分母是人工复核过的样本；一条复核可归因多条规则，所以各行之和大于复核总数。"
                "候选只给建议 —— 系统不会自动改规则。"
                "统计范围是审计文件末尾的最近 N 条（?limit=，默认 1000，上限 20000）。",
    }


def handle_review_queue(ctx: ApiContext, payload: Any, params: dict) -> tuple[int, dict]:
    """待复核队列 + 复核统计（只含指纹，不含原文）。

    读的是审计文件尾部 —— 与 `tail -f`、离线报表看到的是同一份数据，
    不会出现「页面显示的和服务记录的不一致」。
    """
    logger = ctx.audit
    stats = ctx.review_stats()
    if logger is None or not logger.enabled or logger.path is None:
        return 200, {"enabled": False, "count": 0, "items": [], "stats": stats,
                     "reason": "未配置审计日志，启动时加 --audit"}
    limit = _clamp_int(params.get("limit"), default=20, low=1, high=200)
    logger.flush()  # 缓冲写模式下先落盘，保证读到的是最新
    from prompt_ids.audit.logger import tail_events
    from prompt_ids.audit.query import review_stats as _review_stats

    events = tail_events(logger.path, limit=max(limit * 20, 200))
    from prompt_ids.audit.query import pending_reviews, rule_ledger, rule_suspects

    pending = pending_reviews(events, limit=limit)
    ledger = rule_ledger(events)
    return 200, {
        "enabled": True,
        "count": len(pending),
        "path": str(logger.path),
        "stats": _review_stats(events),
        # 台账一起返回：复核页不用再发一次请求就能显示「哪条规则在乱杀人」
        "ledger": dict(sorted(ledger.items(), key=lambda kv: -kv[1]["total"])[:12]),
        "suspects": rule_suspects(ledger),
        "corpus": ctx.review_corpus.stats() if ctx.review_corpus is not None
        else {"enabled": False},
        "items": [
            {
                "fp": e.fp[:12],
                "ts": round(e.ts, 3),
                "level": e.level,
                "score": round(e.score, 2),
                "action": e.action,
                "findings": e.findings,
                "top_pattern": e.top_pattern,
                "source": e.source,
            }
            for e in pending
        ],
        "note": "队列只含指纹。原文需由调用方自行提供（审计层不存原文），"
                "拿到原文后 POST /v1/review 定性。",
    }


def handle_metrics(ctx: ApiContext, payload: Any, params: dict) -> tuple[int, dict]:
    det = ctx.rule_detector
    book = det.rulebook if det and hasattr(det, "rulebook") else None
    uptime = time.time() - ctx.started_at
    # stats 必须在锁内取**快照**：`dict(ctx.stats)` 只是浅拷贝，
    # by_level / by_action 还是同一批 dict 对象，随后被 json.dumps 遍历，
    # 而别的线程正在 record() 里插入 —— 序列化中途抛 RuntimeError 是真会发生的。
    with ctx._lock:
        stats = {k: (dict(v) if isinstance(v, dict) else v)
                 for k, v in ctx.stats.items()}
    return 200, {
        "uptime_s": round(uptime, 1),
        "rules": book.stats() if book else {},
        "stats": stats,
        "detectors": ctx.pipeline.registry.names(),
        "semantic": {
            "enabled": bool(ctx.pipeline.semantic_detector and ctx.pipeline.semantic_detector.enabled),
            "info": ctx.pipeline.semantic_detector.stats() if ctx.pipeline.semantic_detector else {},
        },
        "canary": ctx.canary.stats() if ctx.canary else None,
        "reviews": ctx.review_stats(),
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
    return 200, API_SPEC


# ---------------------------------------------------------------- 路由表
Handler = Callable[[ApiContext, Any, dict], tuple[int, dict]]

ROUTES: list[tuple[str, str, Handler]] = [
    ("POST", "/v1/scan", handle_scan),
    ("POST", "/v1/scan/batch", handle_scan_batch),
    ("POST", "/v1/scan/output", handle_output_scan),
    ("GET", "/v1/rules", handle_rules),
    ("POST", "/v1/canary/issue", handle_canary_issue),
    ("POST", "/v1/canary/check", handle_canary_check),
    ("POST", "/v1/memory/add", handle_memory_add),
    ("POST", "/v1/memory/search", handle_memory_search),
    ("POST", "/v1/memory/feedback", handle_memory_feedback),
    ("GET", "/v1/memory/stats", handle_memory_stats),
    ("POST", "/v1/review", handle_review),
    ("GET", "/v1/review/queue", handle_review_queue),
    ("GET", "/v1/review/patterns", handle_review_patterns),
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


def _build_openapi() -> dict[str, Any]:
    """从 ROUTES 生成 paths。

    `/v1/openapi.json` 原先返回的是空 paths —— 一个宣称自己是 OpenAPI 文档、
    却不列任何端点的接口，比没有这个接口更糟（客户端会当成「就这些」）。
    """
    spec = dict(OPENAPI)
    paths: dict[str, Any] = {}
    for verb, route, handler in ROUTES:
        if route == "/v1/openapi.json":
            continue
        operation = handler.__doc__ or ""
        summary = operation.strip().splitlines()[0] if operation.strip() else route
        paths.setdefault(route, {})[verb.lower()] = {
            "summary": summary,
            "responses": {"200": {"description": "成功"}},
        }
    spec["paths"] = paths
    return spec


API_SPEC = _build_openapi()


def resolve(method: str, path: str) -> Handler | None:
    """精确匹配路由（路径参数当前不需要，保持简单）。"""
    clean = path.split("?")[0].rstrip("/") or "/"
    for verb, route, handler in ROUTES:
        if verb == method and route.rstrip("/") == clean:
            return handler
    return None
