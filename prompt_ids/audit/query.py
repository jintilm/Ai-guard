"""审计日志查询与分析。

读取统一事件模型（AuditEvent）。代理、CLI、API、pipeline 写入的是同一套字段，
代理特有信息（decision/status/client/...）在 extra 里，因此**同一份报表代码
可以直接分析任一入口产生的日志**。

读取器对字段缺失保持容错：历史上代理写过旧格式（顶层 decision 之类），
这类行仍能被读进来而不报错。
"""
from __future__ import annotations

import json
import time
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence

from prompt_ids.eval.metrics import markdown_table
from prompt_ids.audit.events import AuditEvent

BLOCK_ACTIONS = frozenset({"block", "sandbox"})


def decision_of(event: AuditEvent) -> str:
    """统一读取「放行 / 拦截」语义。

    代理入口把放行结论写在 extra["decision"]（allow/review/sandbox/block/leak），
    CLI / API / pipeline 没有这个字段，回退到 action。这样两套来源可以用同一段
    聚合逻辑分析，不需要调用方知道日志是哪个入口产生的。
    """
    extra = event.extra or {}
    value = extra.get("decision")
    return str(value) if value else event.action


def load(path: str | Path) -> list[AuditEvent]:
    file = Path(path)
    if not file.exists():
        return []
    events: list[AuditEvent] = []
    for line in file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            events.append(AuditEvent.from_dict(json.loads(line)))
        except (json.JSONDecodeError, TypeError, ValueError):
            continue
    return events


def within(events: Iterable[AuditEvent], since_s: float | None = None,
           until_s: float | None = None) -> list[AuditEvent]:
    out = []
    for event in events:
        if since_s is not None and event.ts < since_s:
            continue
        if until_s is not None and event.ts > until_s:
            continue
        out.append(event)
    return out


def last_hours(events: Iterable[AuditEvent], hours: float = 24) -> list[AuditEvent]:
    return within(events, since_s=time.time() - hours * 3600)


@dataclass(frozen=True, slots=True)
class AuditSummary:
    total: int = 0
    by_kind: dict[str, int] = None  # type: ignore[assignment]
    by_level: dict[str, int] = None  # type: ignore[assignment]
    by_action: dict[str, int] = None  # type: ignore[assignment]
    by_decision: dict[str, int] = None  # type: ignore[assignment]
    by_source: dict[str, int] = None  # type: ignore[assignment]
    blocked: int = 0
    avg_detect_ms: float = 0.0
    p95_detect_ms: float = 0.0
    span_s: float = 0.0

    def as_dict(self) -> dict:
        return {
            "total": self.total,
            "by_kind": dict(self.by_kind or {}),
            "by_level": dict(self.by_level or {}),
            "by_action": dict(self.by_action or {}),
            "by_decision": dict(self.by_decision or {}),
            "by_source": dict(self.by_source or {}),
            "blocked": self.blocked,
            "avg_detect_ms": round(self.avg_detect_ms, 2),
            "p95_detect_ms": round(self.p95_detect_ms, 2),
            "span_s": round(self.span_s, 1),
        }


def _tally(events: Sequence[AuditEvent], key) -> dict[str, int]:
    acc: Counter = Counter()
    for event in events:
        value = key(event)
        if value:
            acc[value] += 1
    return dict(sorted(acc.items(), key=lambda kv: -kv[1]))


def summarize(events: Sequence[AuditEvent]) -> AuditSummary:
    if not events:
        return AuditSummary()
    from prompt_ids.eval.metrics import percentile

    durations = [e.detect_ms for e in events if e.detect_ms > 0]
    timestamps = [e.ts for e in events if e.ts > 0]
    return AuditSummary(
        total=len(events),
        by_kind=_tally(events, lambda e: e.kind),
        by_level=_tally(events, lambda e: e.level),
        by_action=_tally(events, lambda e: e.action),
        by_decision=_tally(events, decision_of),
        by_source=_tally(events, lambda e: e.source),
        blocked=sum(
            1 for e in events if decision_of(e) in BLOCK_ACTIONS or e.kind == "leak"
        ),
        avg_detect_ms=sum(durations) / len(durations) if durations else 0.0,
        p95_detect_ms=percentile(durations, 0.95) if durations else 0.0,
        span_s=(max(timestamps) - min(timestamps)) if len(timestamps) > 1 else 0.0,
    )


def top_patterns(events: Sequence[AuditEvent], limit: int = 10) -> list[tuple[str, int]]:
    acc: Counter = Counter()
    for event in events:
        if event.patterns:
            # 每条事件的所有命中规则各计一次
            for pattern in event.patterns:
                acc[pattern] += 1
        elif event.top_pattern:
            acc[event.top_pattern] += 1
    return acc.most_common(limit)


def render_report(events: Sequence[AuditEvent], title: str = "审计摘要") -> str:
    summary = summarize(events)
    if not summary.total:
        return f"## {title}\n\n（无记录）"

    lines = [f"## {title}", ""]
    lines.append(f"- 事件总数：**{summary.total}**，其中阻断/泄漏 **{summary.blocked}**")
    lines.append(f"- 平均检测耗时 {summary.avg_detect_ms:.2f} ms，P95 {summary.p95_detect_ms:.2f} ms")
    if summary.span_s > 0:
        lines.append(f"- 时间跨度 {summary.span_s / 3600:.1f} 小时")
    lines.append("")

    if summary.by_kind:
        lines.append("按事件类型：")
        lines.append(markdown_table(
            ["类型", "次数"], [[k, v] for k, v in summary.by_kind.items()], aligns="lr"))
        lines.append("")
    if summary.by_level:
        lines.append("按风险等级：")
        lines.append(markdown_table(
            ["等级", "次数"], [[k, v] for k, v in summary.by_level.items()], aligns="lr"))
        lines.append("")
    if summary.by_decision:
        lines.append("按处置决策：")
        lines.append(markdown_table(
            ["决策", "次数"], [[k, v] for k, v in summary.by_decision.items()], aligns="lr"))
        lines.append("")
    if summary.by_source:
        lines.append("按来源：")
        lines.append(markdown_table(
            ["来源", "次数"], [[k, v] for k, v in summary.by_source.items()], aligns="lr"))
        lines.append("")

    patterns = top_patterns(events)
    if patterns:
        lines.append("命中最多的规则：")
        lines.append(markdown_table(
            ["规则", "次数"], [[p, c] for p, c in patterns], aligns="lr"))
    return "\n".join(lines)
