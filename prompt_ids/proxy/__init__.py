"""透明代理子包。

    python -m prompt_ids.proxy --port 8787

审计已统一到 prompt_ids.audit：proxy.audit 只是兼容薄封装。
"""
from prompt_ids.proxy.audit import AuditLog, AuditRecord, build_event, build_record
from prompt_ids.proxy.server import (
    DEFAULT_PORT,
    ProxyConfig,
    ProxyHandler,
    create_server,
    decide,
    extract_prompt,
    serve,
)

__all__ = [
    "DEFAULT_PORT",
    "AuditLog",
    "AuditRecord",
    "ProxyConfig",
    "ProxyHandler",
    "build_event",
    "build_record",
    "create_server",
    "decide",
    "extract_prompt",
    "serve",
]
