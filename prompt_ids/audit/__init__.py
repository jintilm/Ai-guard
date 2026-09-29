"""审计日志子包。

    from prompt_ids.audit import AuditLogger

    logger = AuditLogger("logs/audit.jsonl", buffer=20)
    result = pipeline.scan(text)
    logger.log_scan(result, text=text, user="u1", source="api")
    logger.flush()
"""
from prompt_ids.audit.events import (
    EVENT_KINDS,
    KIND_API,
    KIND_CUSTOM,
    KIND_LEAK,
    KIND_MEMORY,
    KIND_PROXY,
    KIND_SCAN,
    PROXY_EXTRA_FIELDS,
    AuditEvent,
    event_from_proxy,
    event_from_scan,
)
from prompt_ids.audit.logger import AuditLogger, disk_usage, file_size, tail_events
from prompt_ids.audit.query import (
    AuditSummary,
    decision_of,
    last_hours,
    load,
    render_report,
    summarize,
    top_patterns,
    within,
)

__all__ = [
    "EVENT_KINDS",
    "KIND_API",
    "KIND_CUSTOM",
    "KIND_LEAK",
    "KIND_MEMORY",
    "KIND_PROXY",
    "KIND_SCAN",
    "PROXY_EXTRA_FIELDS",
    "AuditEvent",
    "AuditLogger",
    "AuditSummary",
    "decision_of",
    "disk_usage",
    "event_from_proxy",
    "event_from_scan",
    "file_size",
    "last_hours",
    "load",
    "render_report",
    "summarize",
    "tail_events",
    "top_patterns",
    "within",
]
