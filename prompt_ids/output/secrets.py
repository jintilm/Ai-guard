r"""出站密钥扫描 —— 模型输出里不该出现的第三方凭据。

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

## 三条写正则时用血换来的纪律（2026-10，都是本模块自己踩出来的）

1. **`[A-Za-z0-9_-]{n,}` 后面跟必需的点号 ＝ O(L²)。** 字符类含 `-`（非 `\w`），
   于是 `-eyJ` 重复串里**每个** `eyJ` 都满足 `\b`，n 个候选位置各回溯一遍整条 run。
   实测 256KB 输入 **14.0 秒**（8KB→14ms、16KB→56ms、32KB→223ms、64KB→867ms，
   每翻一倍 4 倍时间）。改成**有界** `{7,64}/{7,512}` 后同一输入 **10.7ms**，
   且真实 JWT（HS256/RS256 342 字符签名）一个不漏。
   守护 `test_jwt_pattern_is_linear_on_repeated_prefix_input`。
2. **上报上限不能变成扫描上限。** 初版用 `MAX_HITS` 同时截断命中**列表**并提前
   `break` 掉后续模式，于是「20 个 AWS key + 一份私钥」里私钥**根本没被扫**，
   审计却写「已脱敏」。现在 `scan_text()` 永远扫完所有模式，
   `per_pattern_cap` 只是对象数兜底且会置 `capped`；上报上限只影响返回给调用方的条数。
   守护 `test_every_pattern_is_scanned_even_after_the_report_cap_is_hit`。
3. **只匹配 PEM 头 = 正文原样透出。** 初版 `private_key` 只吃 39 字符的 BEGIN 行，
   脱敏后客户端仍收到完整私钥材料。现在整块 `BEGIN…END` 一起脱敏
   （END 允许缺失 —— 被截断粘贴的密钥也要能识别）。
   守护 `test_private_key_body_is_redacted_too`。
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable

#: 命中 → (类别名, 模式)。全部是**结构化格式**，不含「api_key = xxx」这类自由文本形态：
#: 后者在代码、文档、示例配置里太常见，扫它等于自造过防御。
_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b")),
    ("anthropic_key", re.compile(r"\bsk-ant-(?:api\d{2}-)?[A-Za-z0-9_-]{24,}")),
    ("openai_key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("slack_token", re.compile(r"\bx(?:ox[baprse]|app)-[A-Za-z0-9-]{10,}")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}")),
    ("gitlab_token", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}")),
    # 整块 BEGIN…END。正文上限 20000 字符：RSA-4096 装甲私钥约 3–4KB，
    # 20000 已经很宽裕，同时防止一条畸形输入把整篇文档当私钥吞掉。
    # END 段可选：被截断粘贴的密钥片段也要能识别。
    ("private_key", re.compile(
        r"-----BEGIN(?: [A-Z0-9]+)* PRIVATE KEY(?: BLOCK)?-----"
        r"(?:[\s\S]{0,20000}?-----END(?: [A-Z0-9]+)* PRIVATE KEY(?: BLOCK)?-----)?")),
    # 三段都有界 —— 见模块 docstring 第 1 条纪律。
    ("jwt", re.compile(
        r"\beyJ[A-Za-z0-9_-]{7,64}\.[A-Za-z0-9_-]{7,512}\.[A-Za-z0-9_-]{7,512}")),
    ("bearer_header", re.compile(
        r"(?i)\bauthorization\s*[:=]\s*['\"]?bearer\s+[A-Za-z0-9._~+/-]{20,}")),
)

#: 上报给客户端 / 审计的条数上限。**不是扫描上限**（见模块 docstring 第 2 条）。
MAX_HITS = 20
#: 单个模式最多收集多少个命中对象：只防对象数无界（病态输入），
#: 触顶会置 `SecretScan.capped`，让审计能说清「这一类只收了前 N 处」。
PER_PATTERN_CAP = 500
#: 脱敏后保留的头尾字符数（够定位是哪一把密钥，又不足以被复现）
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


@dataclass(frozen=True, slots=True)
class SecretScan:
    """一次扫描的完整结果。

    `hits` 是**全部**命中（供脱敏用）；`by_kind` 是全量计数（不受上报上限影响）；
    `capped` 表示某一类撞到了 `per_pattern_cap`，那一类可能还有更多未脱敏。
    """

    hits: tuple[SecretHit, ...]
    by_kind: dict[str, int]
    capped: bool = False

    def __len__(self) -> int:
        return len(self.hits)

    def __iter__(self):
        return iter(self.hits)

    def reported(self, limit: int = MAX_HITS) -> list[SecretHit]:
        """给调用方（响应体 / 告警 / 审计）用的前 N 条。

        **按类别铺开再按位置补**：纯按位置取前 N 的话，「40 个 AWS key + 1 份私钥」
        会让上报里一条私钥都没有，而私钥显然是更严重的那类。
        脱敏不受本上限影响（走 `hits` 全量），这里只影响「给人看的清单」。
        """
        picked: list[SecretHit] = []
        seen: set[str] = set()
        for hit in self.hits:
            if hit.kind not in seen:
                seen.add(hit.kind)
                picked.append(hit)
            if len(picked) >= limit:
                return picked
        for hit in self.hits:
            if hit not in picked:
                picked.append(hit)
            if len(picked) >= limit:
                break
        return picked

    def summary(self) -> dict[str, int]:
        return dict(self.by_kind)


def scan_text(text: str, *, per_pattern_cap: int = PER_PATTERN_CAP) -> SecretScan:
    """扫描文本里的第三方凭据。

    **每一条模式都会被跑完** —— 上报上限不是扫描上限（模块 docstring 第 2 条）。
    命中按出现位置排序，同一区间只留给更靠前的（更具体的）类别。
    """
    if not text:
        return SecretScan((), {})
    hits: list[SecretHit] = []
    counts: dict[str, int] = {}
    claimed: set[tuple[int, int]] = set()
    capped = False
    for kind, pattern in _SECRET_PATTERNS:
        taken = 0
        for m in pattern.finditer(text):
            span = m.span()
            if span in claimed:
                continue  # 已由更具体的类别认领（如 anthropic_key 先于 openai_key）
            counts[kind] = counts.get(kind, 0) + 1
            if taken >= per_pattern_cap:
                capped = True
                break
            claimed.add(span)
            hits.append(SecretHit(kind, span[0], span[1], m.group()))
            taken += 1
    hits.sort(key=lambda h: h.start)
    return SecretScan(tuple(hits), counts, capped)


def scan_secrets(text: str, *, limit: int | None = None) -> list[SecretHit]:
    """兼容层：只要命中列表。`limit` **只截断返回条数**，扫描照旧跑完。"""
    return scan_text(text).reported(limit if limit is not None else len(text))


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
    """按类别计数（传入命中列表时的便捷函数）。"""
    counts: dict[str, int] = {}
    for hit in hits:
        counts[hit.kind] = counts.get(hit.kind, 0) + 1
    return counts
