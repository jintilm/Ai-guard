"""出站检测子包 —— 模型输出侧的防护。

目前两块，都作用在**响应**上（不是请求侧）：
- `secrets` : 模型输出里出现了第三方凭据 ⇒ 抹掉并记账（默认不开，见模块 docstring）

请求侧的分段检测在 `prompt_ids.proxy.server`，system prompt 埋令牌在 `prompt_ids.canary`。
"""
from prompt_ids.output.secrets import (
    MAX_HITS,
    SecretHit,
    redact,
    redact_bytes,
    scan_secrets,
    summary,
)

__all__ = [
    "MAX_HITS",
    "SecretHit",
    "redact",
    "redact_bytes",
    "scan_secrets",
    "summary",
]
