"""解码展开 —— 生成变体集合。

规则必须跑在「原文 + 所有解码变体」上，只对原文匹配等于没做。
用 BFS 控制层数与总量，避免组合爆炸。
"""
from __future__ import annotations

import base64
import binascii
import codecs
import html
import re
from collections.abc import Callable
from typing import NamedTuple

from prompt_ids.core.types import Variant

# 判定解码产物是否为「可信文本」：可打印字符占比 + 有效字符下限
_MIN_PRINTABLE_RATIO = 0.92
_MIN_LEN = 4

_BASE64_RE = re.compile(r"[A-Za-z0-9+/=_%-]{16,}")
_HEX_RE = re.compile(r"(?:\\x[0-9a-fA-F]{2}|0x[0-9a-fA-F]{2}|[0-9a-fA-F]{2}){8,}")
_UNICODE_ESC_RE = re.compile(r"(?:\\u[0-9a-fA-F]{4}|\\U[0-9a-fA-F]{8}){2,}")
_PERCENT_RE = re.compile(r"%[0-9a-fA-F]{2}")
_HTML_ENTITY_RE = re.compile(r"&(?:#\d+|#x[0-9a-fA-F]+|[A-Za-z][A-Za-z0-9]{1,31});")


def _printable_ratio(text: str) -> float:
    if not text:
        return 0.0
    good = sum(1 for ch in text if ch.isprintable() or ch in "\n\t\r")
    return good / len(text)


def _plausible(text: str, source: str) -> bool:
    """过滤掉把随机串解成乱码的伪阳性变体。"""
    if len(text) < _MIN_LEN:
        return False
    if text == source:
        return False
    if _printable_ratio(text) < _MIN_PRINTABLE_RATIO:
        return False
    # 解码产物至少要含一位字母，纯符号串没有匹配价值
    return any(ch.isalpha() for ch in text)


def _decode_base64(text: str) -> str | None:
    cands = re.findall(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{16,}={0,2}(?![A-Za-z0-9+/])", text)
    if not cands:
        return None
    out = text
    changed = False
    for cand in cands:
        try:
            raw = base64.b64decode(cand + "=" * (-len(cand) % 4), validate=True)
            decoded = raw.decode("utf-8", errors="strict")
        except (binascii.Error, ValueError, UnicodeDecodeError):
            continue
        if not _plausible(decoded, cand):
            continue
        out = out.replace(cand, decoded)
        changed = True
    return out if changed else None


def _decode_percent(text: str) -> str | None:
    if not _PERCENT_RE.search(text) and "+" not in text:
        return None
    try:
        decoded = _PERCENT_RE.sub(
            lambda m: bytes.fromhex(m.group(0)[1:]).decode("utf-8", errors="replace"), text
        )
        if "+" in decoded:
            tmp = decoded.replace("+", " ")
            if tmp != decoded:
                decoded = tmp
    except Exception:  # noqa: BLE001
        return None
    return decoded if decoded != text else None


def _decode_hex(text: str) -> str | None:
    out = text
    changed = False
    for m in re.finditer(r"(?:\\[xX][0-9a-fA-F]{2}|0x[0-9a-fA-F]{2}){4,}", text):
        blob = m.group(0)
        hexes = re.findall(r"[0-9a-fA-F]{2}", blob.replace("\\x", "").replace("0x", ""))
        try:
            decoded = bytes(int(h, 16) for h in hexes).decode("utf-8", errors="strict")
        except (ValueError, UnicodeDecodeError):
            continue
        if not _plausible(decoded, blob):
            continue
        out = out.replace(blob, decoded)
        changed = True
    return out if changed else None


def _decode_unicode_escape(text: str) -> str | None:
    if not _UNICODE_ESC_RE.search(text):
        return None
    try:
        decoded = codecs.decode(text.encode("utf-8", "surrogateescape"), "unicode_escape", "replace")
        decoded = decoded.encode("utf-8", "surrogateescape").decode("utf-8", "replace")
    except Exception:  # noqa: BLE001
        return None
    return decoded if decoded != text else None


def _decode_html_entity(text: str) -> str | None:
    if not _HTML_ENTITY_RE.search(text):
        return None
    try:
        decoded = re.sub(
            _HTML_ENTITY_RE,
            lambda m: html.unescape(m.group(0)),
            text,
        )
    except Exception:  # noqa: BLE001
        return None
    return decoded if decoded != text else None


def _decode_rot13(text: str) -> str | None:
    decoded = codecs.encode(text, "rot_13")
    return decoded if decoded != text else None


class DecoderStep(NamedTuple):
    name: str
    fn: Callable[[str], str | None]
    # True 表示结果需满足 _plausible 才保留（防止乱码注入大量噪声变体）
    strict: bool = True


_DECODERS: tuple[DecoderStep, ...] = (
    DecoderStep("html_entity", _decode_html_entity),
    DecoderStep("unicode_escape", _decode_unicode_escape),
    DecoderStep("percent", _decode_percent),
    DecoderStep("base64", _decode_base64),
    DecoderStep("hex", _decode_hex),
    DecoderStep("rot13", _decode_rot13, strict=False),
)


class DecodeExpander:
    """BFS 展开解码变体。max_hops 控制层数，max_variants 控制总量。"""

    def __init__(
        self,
        max_hops: int = 2,
        max_variants: int = 24,
        enabled: tuple[str, ...] | None = None,
    ):
        self.max_hops = max_hops
        self.max_variants = max_variants
        names = set(enabled) if enabled is not None else None
        self.steps = [s for s in _DECODERS if names is None or s.name in names]

    def expand(self, text: str) -> list[Variant]:
        """返回去重后的变体集合，第一个恒为原文（kind=original）。"""
        root = Variant(kind="original", text=text, hops=0)
        seen: set[str] = {text}
        variants: list[Variant] = [root]
        frontier: list[Variant] = [root]

        for _ in range(self.max_hops):
            nxt: list[Variant] = []
            for node in frontier:
                for step in self.steps:
                    if len(variants) >= self.max_variants:
                        break
                    try:
                        produced = step.fn(node.text)
                    # 说明（抑制见下一行行尾的 noqa）：单个解码变体失败**不该让整个预处理放弃**
                    # 其余变体 —— 否则一个畸形输入就丢掉全部检出机会。
                    except Exception:  # noqa: BLE001
                        continue
                    if not produced or produced in seen:
                        continue
                    if step.strict and not _plausible(produced, node.text):
                        continue
                    seen.add(produced)
                    variant = Variant(kind=step.name, text=produced, hops=node.hops + 1)
                    variants.append(variant)
                    nxt.append(variant)
            if not nxt or len(variants) >= self.max_variants:
                break
            frontier = nxt
        return variants
