"""审计事件模型。

沿用代理审计验证过的约定：**审计日志只落指纹，不落原文**。
代理面对的是真实业务流量，里面有隐私和凭据；如果审计把原文照单全收，
防护系统自己就成了新的泄露面。需要原文时靠 fp 去别处关联。
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any

# 事件类型：检测 / Canary 泄漏 / 记忆写入 / API 请求 / 代理转发 / 人工复核 / 自定义
KIND_SCAN = "scan"
KIND_LEAK = "leak"
KIND_MEMORY = "memory"
KIND_API = "api"
KIND_PROXY = "proxy"
KIND_REVIEW = "review"
KIND_CUSTOM = "custom"

EVENT_KINDS = (KIND_SCAN, KIND_LEAK, KIND_MEMORY, KIND_API, KIND_PROXY, KIND_REVIEW, KIND_CUSTOM)

# 复核事件特有字段（收进 extra，与代理同款做法：不另起一套记录类型）
REVIEW_EXTRA_FIELDS = ("verdict", "reviewer", "memory_absorbed", "linked_level", "top_pattern")

#: 需要人工看一眼的等级。低于 medium 的（low / safe）不进复核队列 —— 否则队列
#: 会被大量「只有一个弱特征」的样本淹掉，真正需要判断的反而被埋掉。
REVIEW_LEVELS = frozenset({"medium", "high", "critical"})

MAX_PATTERNS = 5  # 只留前几个命中规则的 ID，够排查又不臃端

#: `note` 是**调用方自填的自由文本**，是原文唯一还能进审计文件的通道
#: （审计其余字段都由系统生成，都不含原文）。note 本该是一句备注，
#: 不是一段文档 —— 所以按长度截断，挡住「顺手把整段文本粘进备注」。
#: 注意这挡不住刻意粘贴：真要泄露，调用方有 1000 种办法。所以这只是
#: 缩小意外面，不是安全边界 —— 边界是「别往 note 里贴原文」。
MAX_NOTE_CHARS = 200


def _clip_note(note: str) -> str:
    text = " ".join(str(note or "").split())
    if len(text) <= MAX_NOTE_CHARS:
        return text
    return text[:MAX_NOTE_CHARS] + f"…[截断，原 {len(text)} 字符]"

# 代理特有字段：统一收入 AuditEvent.extra，不再另起一套记录类型。
# 通用字段（kind/level/action/score/fp/findings/patterns/detect_ms）与
# CLI / API / pipeline 三个入口**逐字段一致**，因此 `prompt-ids-audit summary`
# 不需要知道日志是哪个入口产生的。
PROXY_EXTRA_FIELDS = ("decision", "status", "client", "path", "stream", "upstream_ms",
                      "segments", "trigger", "truncated", "dropped", "scanned_chars")


@dataclass(frozen=True, slots=True)
class AuditEvent:
    ts: float
    kind: str
    level: str = ""
    action: str = ""
    score: float = 0.0
    fp: str = ""
    findings: int = 0
    patterns: tuple[str, ...] = ()
    top_pattern: str = ""
    detect_ms: float = 0.0
    user: str = ""
    source: str = ""      # cli / api / proxy / pipeline
    note: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "ts": round(self.ts, 3),
            "kind": self.kind,
            "level": self.level,
            "action": self.action,
            "score": round(self.score, 2),
            "fp": self.fp,
            "findings": self.findings,
            "patterns": list(self.patterns),
            "top_pattern": self.top_pattern,
            "detect_ms": round(self.detect_ms, 2),
            "user": self.user,
            "source": self.source,
            "note": self.note,
        }
        if self.extra:
            data["extra"] = self.extra
        return data

    def to_line(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AuditEvent":
        extra = data.get("extra")
        return cls(
            ts=float(data.get("ts", 0.0)),
            kind=str(data.get("kind", KIND_CUSTOM)),
            level=str(data.get("level", "")),
            action=str(data.get("action", "")),
            score=float(data.get("score", 0.0) or 0.0),
            fp=str(data.get("fp", "")),
            findings=int(data.get("findings", 0) or 0),
            patterns=tuple(data.get("patterns") or ()),
            top_pattern=str(data.get("top_pattern", "")),
            detect_ms=float(data.get("detect_ms", 0.0) or 0.0),
            user=str(data.get("user", "")),
            source=str(data.get("source", "")),
            note=str(data.get("note", "")),
            extra=dict(extra) if isinstance(extra, dict) else {},
        )

    @property
    def is_blocking(self) -> bool:
        return self.action == "block" or self.kind == KIND_LEAK


def event_from_scan(result, *, text: str = "", user: str = "",
                    source: str = "", note: str = "", **extra) -> AuditEvent:
    """从 ScanResult 组装审计事件。text 只用来算指纹。"""
    from prompt_ids.preprocess.guard import fingerprint

    findings = getattr(result, "findings", []) or []
    top = ""
    if findings:
        top = max(findings, key=lambda f: f.weight * f.confidence).pattern_id
    return AuditEvent(
        ts=time.time(),
        kind=KIND_SCAN,
        level=result.level.value,
        action=result.action.value,
        score=result.score,
        fp=fingerprint(text) if text else "",
        findings=len(findings),
        patterns=tuple(f.pattern_id for f in findings[:MAX_PATTERNS]),
        top_pattern=top,
        detect_ms=result.latency_ms.get("total", 0.0),
        user=user,
        source=source,
        note=_clip_note(note),
        extra=extra,
    )


def event_from_review(*, fp: str, is_attack: bool, reviewer: str = "",
                      level: str = "", score: float = 0.0, top_pattern: str = "",
                      patterns: tuple[str, ...] = (),
                      note: str = "", memory_absorbed: bool = False,
                      source: str = "review") -> AuditEvent:
    """人工复核结论 -> 统一 AuditEvent。

    为什么复核记录里**也没有原文**：审计层一旦存了原文，它就变成业务数据的副本，
    代理/网关场景下等于凭空多一个泄露面。复核队列只给「指纹 + 等级 + 命中规则」，
    判定与放行需要原文的场景（比如写入负向记忆）走独立接口，由调用方自己提供文本。

    `action` 刻意留空：人工结论不是检测层的动作，填进 action 会污染
    `by_action` 聚合，让「系统自己判了多少次阻断」这个数字失真。

    `patterns` 是**归因**：这条人工结论背后是哪些规则判的。反哺规则迭代全靠它 ——
    没有它，「PV-C001 的误报率是多少」根本无从回答，只能凭印象改规则。
    """
    return AuditEvent(
        ts=time.time(),
        kind=KIND_REVIEW,
        level=level,
        action="",
        score=score,
        fp=fp,
        findings=len(patterns),
        patterns=tuple(patterns[:MAX_PATTERNS]),
        top_pattern=top_pattern,
        user=reviewer,
        source=source,
        note=_clip_note(note or ("人工确认攻击" if is_attack else "人工标记误报")),
        extra={
            "verdict": "attack" if is_attack else "false_positive",
            "reviewer": reviewer,
            "memory_absorbed": bool(memory_absorbed),
            "linked_level": level,
            "top_pattern": top_pattern,
        },
    )


#: 出站处置：`decision` 说的是**这个请求怎么处理的**，
#: `outbound` 说的是**响应出去时发生了什么**。两个维度正交，混在一个字段里
#: 就出现过三个语义重叠的名字（leak / secret_leak / redact_secrets），
#: 而且为了记录出站结论要发**第二条**事件 ⇒ `by_decision` 把一次请求数成两次。
#:
#: - `none`     ：出站没有命中
#: - `redacted` ：非流式，命中片段已就地脱敏
#: - `replaced` ：整个响应被替换成告警（Canary 泄漏 + redact_leak）
#: - `warned`   ：流式，内容已发出，只能末尾补告警
#: - `rejected` ：上游响应形态无法保证检测（如 gzip），整条拒收
OUTBOUND_NONE = "none"
OUTBOUND_REDACTED = "redacted"
OUTBOUND_REPLACED = "replaced"
OUTBOUND_WARNED = "warned"
OUTBOUND_REJECTED = "rejected"
OUTBOUND_DISPOSITIONS = frozenset({
    OUTBOUND_NONE, OUTBOUND_REDACTED, OUTBOUND_REPLACED, OUTBOUND_WARNED, OUTBOUND_REJECTED,
})
#: 历史值：旧日志里的 leak / secret_leak / redact_secrets 仍要能聚合，
#: 但不再产生（新的单一事件把它们折成 outbound）。
LEGACY_OUTBOUND_DECISIONS = {
    "leak": OUTBOUND_REPLACED,
    "redact_secrets": OUTBOUND_REDACTED,
    "secret_leak": OUTBOUND_WARNED,
}


def event_from_proxy(result, *, decision: str = "allow", path: str = "",
                     client: str = "", stream: bool = False,
                     upstream_ms: float = 0.0, detect_ms: float = 0.0,
                     status: int = 200, note: str = "", text: str = "",
                     segments: int = 0, trigger: str = "",
                     truncated: int = 0, dropped: int = 0,
                     scanned_chars: int = 0, secret_kinds: dict | None = None,
                     secret_sampled: bool = False, secret_scanned_chars: int = 0,
                     secret_capped: bool = False,
                     outbound: str = OUTBOUND_NONE,
                     outbound_detail: str = "") -> AuditEvent:
    """代理转发事件 -> 统一 AuditEvent。

    代理侧历史上另有一套 AuditRecord。现在统一到同一个事件模型：
    通用字段与 scan 事件完全同构，代理特有的 decision/status/client/path/
    stream/upstream_ms 全部收进 extra（见 PROXY_EXTRA_FIELDS）。

    - `user` 取客户端地址：代理能拿到的使用者身份就是它，
      这样跨入口的 by_user 聚合在代理日志上同样可用。
    - `action` 仍是检测层给出的建议动作，代理自己的放行/拦截结论放 extra["decision"]。
    - text 只用来算指纹，绝不写入日志。
    """
    from prompt_ids.preprocess.guard import fingerprint

    findings = getattr(result, "findings", []) or []
    top = ""
    if findings:
        top = max(findings, key=lambda f: f.weight * f.confidence).pattern_id
    return AuditEvent(
        ts=time.time(),
        kind=KIND_PROXY,
        level=result.level.value,
        action=result.action.value,
        score=result.score,
        fp=fingerprint(text) if text else "",
        findings=len(findings),
        patterns=tuple(f.pattern_id for f in findings[:MAX_PATTERNS]),
        top_pattern=top,
        detect_ms=detect_ms,
        user=client,
        source="proxy",
        note=_clip_note(note),
        extra={
            "decision": decision,
            "status": status,
            "client": client,
            "path": path,
            "stream": bool(stream),
            "upstream_ms": round(upstream_ms, 2),
            # 分段检测的覆盖账：扫了几段、命中哪一段、取样了几段、丢了几段、扫了多少字符。
            # `truncated > 0` 或 `dropped > 0` 表示**这次检测没有覆盖全文** ——
            # 不记下来就等于让运维以为长文档被完整查过了。
            "segments": int(segments),
            "trigger": trigger,
            "truncated": int(truncated),
            "dropped": int(dropped),
            "scanned_chars": int(scanned_chars),
            # 出站密钥扫描命中的类别与计数：**只落类别，不落原文**。
            # 密钥的脱敏形态（首尾几个字符）只出现在给客户端的告警体里，不进审计文件。
            "secret_kinds": dict(secret_kinds or {}),
            # 出站扫描的**覆盖账**：响应侧同样要有预算，否则「扫了整个响应」这句话
            # 在 2MB 响应上意味着 258ms 的固定开销，而实测记忆体缓冲还能顶满内存。
            # sampled=True 表示超预算走了分层取样（不是全文扫过）。
            "secret_sampled": bool(secret_sampled),
            "secret_scanned_chars": int(secret_scanned_chars),
            # capped=True：累积缓冲撞到上限，尾部**没有**被扫过
            "secret_capped": bool(secret_capped),
            # 出站处置（与 decision 正交，见 OUTBOUND_* 常量）。
            # 一次请求只落**一条**事件，出站结论记在这里 —— 此前为记录出站结论
            # 额外发第二条事件，by_decision 因此把一次请求数成两次。
            "outbound": outbound,
            # 人读的说明（哪种凭据、哪种形态），例如
            # "canary:exact（响应已替换）" / "aws_access_key×1（已脱敏）"
            "outbound_detail": outbound_detail[:200],
        },
    )
