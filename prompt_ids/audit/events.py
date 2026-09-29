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

# 事件类型：检测 / Canary 泄漏 / 记忆写入 / API 请求 / 代理转发 / 自定义
KIND_SCAN = "scan"
KIND_LEAK = "leak"
KIND_MEMORY = "memory"
KIND_API = "api"
KIND_PROXY = "proxy"
KIND_CUSTOM = "custom"

EVENT_KINDS = (KIND_SCAN, KIND_LEAK, KIND_MEMORY, KIND_API, KIND_PROXY, KIND_CUSTOM)

MAX_PATTERNS = 5  # 只留前几个命中规则的 ID，够排查又不臃肿

# 代理特有字段：统一收入 AuditEvent.extra，不再另起一套记录类型。
# 通用字段（kind/level/action/score/fp/findings/patterns/detect_ms）与
# CLI / API / pipeline 三个入口**逐字段一致**，因此 `prompt-ids-audit summary`
# 不需要知道日志是哪个入口产生的。
PROXY_EXTRA_FIELDS = ("decision", "status", "client", "path", "stream", "upstream_ms")


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
        note=note,
        extra=extra,
    )


def event_from_proxy(result, *, decision: str = "allow", path: str = "",
                     client: str = "", stream: bool = False,
                     upstream_ms: float = 0.0, detect_ms: float = 0.0,
                     status: int = 200, note: str = "", text: str = "") -> AuditEvent:
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
        note=note,
        extra={
            "decision": decision,
            "status": status,
            "client": client,
            "path": path,
            "stream": bool(stream),
            "upstream_ms": round(upstream_ms, 2),
        },
    )
