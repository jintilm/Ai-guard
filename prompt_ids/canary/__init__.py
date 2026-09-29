"""Canary 令牌子包。

    from prompt_ids.canary import CanaryRegistry, issue

    registry = CanaryRegistry()
    token = registry.issue("prod")
    system = token.wrap_system_prompt("你是一个客服助手")
    ...
    match = registry.check(model_output)   # 命中即证明提示已泄露
"""
from prompt_ids.canary.tokens import (
    CanaryMatch,
    CanaryRegistry,
    CanaryToken,
    CanaryError,
    DEFAULT_PREFIX,
    issue,
)

__all__ = [
    "DEFAULT_PREFIX",
    "CanaryError",
    "CanaryMatch",
    "CanaryRegistry",
    "CanaryToken",
    "issue",
]
