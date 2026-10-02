"""REST API 子包。

    python -m prompt_ids.api --port 8790
"""
from prompt_ids.api.app import (
    API_SPEC,
    ApiContext,
    ApiError,
    OPENAPI,
    ROUTES,
    handle_canary_check,
    handle_canary_issue,
    handle_metrics,
    handle_output_scan,
    handle_rules,
    handle_scan,
    handle_scan_batch,
    resolve,
)
from prompt_ids.api.server import (
    DEFAULT_PORT,
    ApiHandler,
    ApiServerConfig,
    create_api_server,
    serve,
)

__all__ = [
    "API_SPEC",
    "DEFAULT_PORT",
    "OPENAPI",
    "ROUTES",
    "ApiContext",
    "ApiError",
    "ApiHandler",
    "ApiServerConfig",
    "create_api_server",
    "handle_canary_check",
    "handle_canary_issue",
    "handle_metrics",
    "handle_output_scan",
    "handle_rules",
    "handle_scan",
    "handle_scan_batch",
    "resolve",
    "serve",
]
