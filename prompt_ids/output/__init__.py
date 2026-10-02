"""出站密钥子包（模型输出侧的防护）。

- `secrets` : 模型输出里出现了第三方凭据 ⇒ 抹掉并记账（默认不开，见模块 docstring）

请求侧的分段检测在 `prompt_ids.proxy.server`，system prompt 埋令牌在 `prompt_ids.canary`。
"""
from prompt_ids.output.secrets import (
    MAX_HITS,
    PER_PATTERN_CAP,
    SecretHit,
    SecretScan,
    redact,
    redact_bytes,
    scan_secrets,
    scan_text,
    summary,
)

__all__ = [
    "MAX_HITS",
    "PER_PATTERN_CAP",
    "SecretHit",
    "SecretScan",
    "redact",
    "redact_bytes",
    "scan_secrets",
    "scan_text",
    "summary",
]
