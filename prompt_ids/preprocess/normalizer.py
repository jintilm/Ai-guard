"""文本归一化 —— 决定了整个规则层的上限。

对抗四类最常见绕过：同形字替换、零宽/控制字符插入、全角字符、字符间插空格。
归一化不开，规则库再全也会被绕。
"""
from __future__ import annotations

import re
import unicodedata

# 西里尔 / 希腊同形字 -> 拉丁。只收真正形近的，避免误伤。
_HOMOGLYPHS = {
    # 西里尔小写
    "а": "a", "с": "c", "е": "e", "о": "o", "р": "p", "х": "x",
    "у": "y", "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "һ": "h",
    "ӏ": "l", "ԛ": "q", "ԝ": "w", "ғ": "f", "ә": "a", "п": "n",
    # 西里尔大写
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H",
    "О": "O", "Р": "P", "С": "C", "Т": "T", "У": "Y", "Х": "X", "І": "I", "Ј": "J",
    # 希腊小写
    "α": "a", "ο": "o", "ρ": "p", "ν": "v", "τ": "t", "ι": "i", "κ": "k", "ε": "e", "μ": "u",
    # 希腊大写
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K",
    "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X",
}
_HOMOGLYPH_TABLE = str.maketrans(_HOMOGLYPHS)

# 零宽 / 格式控制字符（含软连字符、BOM、双向控制、行分隔符）
_INVISIBLE = frozenset(
    "\u00ad\u061c\u180e\u200b\u200c\u200d\u200e\u200f"
    "\u2028\u2029\u202a\u202b\u202c\u202d\u202e\u2060"
    "\u2061\u2062\u2063\u2064\u2066\u2067\u2068\u2069\ufeff"
    "\U000e0001\U000e0020\U000e0100"
)

# 文段中用于断词的常见分隔符（插入在字符之间）
_SEPARATORS = " \t\u00a0\u3000\u2007\u202f._-*~`|'"


def strip_invisible(text: str) -> str:
    """移除不可见字符与组合附加符号（如 iǵnore 中的变音符）。"""
    out = []
    for ch in text:
        if ch in _INVISIBLE:
            continue
        if unicodedata.combining(ch):
            continue
        out.append(ch)
    return "".join(out)


def fold_spacing(text: str) -> str:
    """剥离字符间插入的空白<｜hy_place▁holder▁no▁813｜>分隔。用于生成「挤压」变体，不改动原文语义。"""
    return "".join(ch for ch in text if ch not in _SEPARATORS)


def reglue_spaced(text: str) -> str:
    """把被空白拆散的单字符重新拼接：i g n o r e -> ignore。

    这是「字符间插空格」绕过的正解：直接删空格会让规则里的空白匹配失效，
    必须先把词组还原出来。
    """
    buf: list[str] = []
    out: list[str] = []
    for token in text.split():
        if len(token) == 1 and token.isalnum():
            buf.append(token)
            continue
        if buf:
            out.append("".join(buf))
            buf.clear()
        out.append(token)
    if buf:
        out.append("".join(buf))
    return " ".join(out)


class Normalizer:
    def __init__(self, enable_homoglyph: bool = True, enable_spacing_fold: bool = True):
        self.enable_homoglyph = enable_homoglyph
        self.enable_spacing_fold = enable_spacing_fold

    def canonical(self, text: str) -> str:
        """产出用于匹配与缓存键的规范形式。"""
        if not text:
            return ""
        # NFKC 负责全角转半角、兼容字符折叠
        out = unicodedata.normalize("NFKC", text)
        if self.enable_homoglyph:
            out = out.translate(_HOMOGLYPH_TABLE)
        out = strip_invisible(out)
        # 折叠重复空白，避免 '\n\n\n' 造成规则写成不匹配
        out = re.sub(r"[ \t\u00a0]{2,}", " ", out)
        return out

    def variants(self, text: str) -> list[str]:
        """返回去重的候选文本列表：规范形式为首选，其后是挤压形式。"""
        base = self.canonical(text)
        cands = [base]
        glued = reglue_spaced(base)
        if glued != base:
            cands.append(glued)
        if self.enable_spacing_fold:
            squeezed = fold_spacing(base)
            if squeezed != base:
                cands.append(squeezed)
        seen: set[str] = set()
        uniq: list[str] = []
        for c in cands:
            if c and c not in seen:
                seen.add(c)
                uniq.append(c)
        return uniq
