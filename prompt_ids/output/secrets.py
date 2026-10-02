"""出站密钥扫描 —— 模型输出里不该出现的第三方凭据。

与 Canary 的区别（两者都是出站检测，但语义完全不同，不能混成一个开关）：

- **Canary**：令牌是我们自己埋进 system prompt 的。输出里出现它 ⇒ 提示被吐出来了。
- **密钥扫描**：匹配的是**第三方**凭据（AWS / OpenAI / Slack / 私钥 / JWT）。
  输出里出现它几乎总是「模型把 RAG 文档、代码上下文、日志里的密钥复述出来了」。
  这是 Canary 覆盖不到的一类出站事故 —— Canary 只认自己的令牌。

**为什么默认不开**（`ProxyConfig.scan_secrets` 默认 False）：
密钥扫描的假阳性直接变成「把用户正常答案里的字符串抹掉」，代价是产品不可用。
所以口径与规则层一致 —— 只收高信号格式，宁可漏报不可错杀，并要求先量过良性语料的误报率
（`scripts/output_check.py` 留证据）再打开。

**绝不出站的东西**：命中证据在审计与告警里一律走 `masked()`，只保留首尾少量字符；
`redact()` 把命中片段替换成 `[REDACTED:<kind>]`，该占位符只含 ASCII 安全字符，
可以直接在 JSON 响应体里做字节级替换，不必重新序列化。
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable

# 命中 → (类别名, 模式)。全部是**结构化格式**，不含「api_key = xxx」这类自由文本形态：
# 后者在代码、文档、示例配置里太常见，扫它等于自造过防御。
_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b")),
    ("anthropic_key", re.compile(r"\bsk-ant-(?:api\d{2}-)?[A-Za-z0-9_-]{24,}")),
    ("openai_key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("slack_token", re.compile(r"\bx(?:ox[baprse]|app)-[A-Za-z0-9-]{10,}")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}")),
    ("gitlab_token", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}")),
    ("private_key", re.compile(
        r"-----BEGIN(?: [A-Z0-9]+)* PRIVATE KEY(?: BLOCK)?-----")),
    ("jwt", re.compile(
        r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")),
    ("bearer_header", re.compile(
        r"(?i)\bauthorization\s*[:=]\s*['\"]?bearer\s+[A-Za-z0-9._~+/-]{20,}")),
)

# 单条输出最多报多少命中：出站告警是给人看的，不是给人做数据挖掘的。
MAX_HITS = 20
# 脱敏后保留的头尾字符数（够定位是哪一把密钥，又不足以被复现）
_MASK_HEAD = 4
_MASK_TAIL = 2


@dataclass(frozen=True, slots=True)
class SecretHit:
    """一处密钥命中。`raw` 存在但**只应留在进程内**，落盘/回显一律走 masked()。"""

    kind: str
    start: int
    end: int
    raw: str = field(repr=False)

    def masked(self) -> str:
        value = self.raw
        if len(value) <= _MASK_HEAD + _MASK_TAIL + 1:
            return "…" + value[-1:]
        return f"{value[:_MASK_HEAD]}…{value[-_MASK_TAIL:]}"

    def placeholder(self) -> str:
        return f"[REDACTED:{self.kind}]"

    def as_dict(self) -> dict:
        return {"kind": self.kind, "masked": self.masked(), "at": self.start}


def scan_secrets(text: str, *, limit: int = MAX_HITS) -> list[SecretHit]:
    """扫描文本里的第三方凭据。命中按出现位置排序，重叠时先到先得。"""
    if not text:
        return []
    hits: list[SecretHit] = []
    claimed: set[tuple[int, int]] = set()
    for kind, pattern in _SECRET_PATTERNS:
        for m in pattern.finditer(text):
            span = m.span()
            if span in claimed:
                continue  # 已由更具体的类别认领（如 anthropic_key 先于 openai_key）
            claimed.add(span)
            hits.append(SecretHit(kind, span[0], span[1], m.group()))
            if len(hits) >= limit:
                break
        if len(hits) >= limit:
            break
    hits.sort(key=lambda h: h.start)
    return hits


def redact(text: str, hits: Iterable[SecretHit]) -> str:
    """把命中片段替换成占位符。位置是从后往前替换的，前面的偏移量才不会失效。"""
    ordered = sorted(hits, key=lambda h: h.start, reverse=True)
    out = text
    for hit in ordered:
        if out[hit.start:hit.end] != hit.raw:
            continue  # 文本已被上层改过，别按旧偏移硬切
        out = out[:hit.start] + hit.placeholder() + out[hit.end:]
    return out


def redact_bytes(payload: bytes, hits: Iterable[SecretHit]) -> bytes:
    """字节级替换：占位符只含 ASCII 字母数字方括号，可以直接在 JSON 里就地替换。"""
    return redact(payload.decode("utf-8", "replace"), hits).encode("utf-8", "replace")


def summary(hits: Iterable[SecretHit]) -> dict[str, int]:
    """按类别计数，供审计的 patterns 字段与指标聚合使用。"""
    counts: dict[str, int] = {}
    for hit in hits:
        counts[hit.kind] = counts.get(hit.kind, 0) + 1
    return counts
