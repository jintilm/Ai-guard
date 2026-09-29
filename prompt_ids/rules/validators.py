"""规则命中后的二次校验。

背景：有些规则要表达"必须同时满足多个字符类"，只能写成前瞻：

    (?=[A-Za-z0-9+/]*[0-9])(?=[A-Za-z0-9+/]*[a-z])... [A-Za-z0-9+/]{40,}

这种写法在**失败**时是 O(L²)：`search` 会在每个位置重扫一遍剩余全文。
实测一条"8000 字符纯字母"的文本，单条规则就要 596ms；32000 字符约 9.5s。
而"长英文文本且不含数字"恰好是最常见的输入形态 —— 经 `fold_spacing`
挤压掉空格后就是一条巨长的字母 run，任何请求都能把规则层拖死。

改法：正则只负责**线性地找到候选片段**，特征判定交给 Python 做一次：

    pattern: '[A-Za-z0-9+/]{40,}={0,2}'
    validate: base64_blob

等价性：校验函数对"区域内是否存在某个字符类"是单调的 ——
整段含数字则其任意子段也含数字，反之整段不含则子段也不含，
所以"贪心取到的整段不合格 ⇒ 它的任何子段都不合格"，
逐段 finditer 与原文前瞻写法结果完全一致，只是复杂度降到线性。
"""
from __future__ import annotations

from typing import Callable

_B64_ALPHABET = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
)


def base64_blob(text: str) -> bool:
    """极像 Base64 载荷：长度 >= 40，字母表合法，且大小写字母与数字齐备。

    只做字符构成判断，不做解码 —— 解码交给解码变体那条链路。

    刻意不提前返回：候选片段互不重叠（finditer 逐个吞掉），整段的扫描量
    仍是 O(L)，而"见到三类字符就返回"会让非法字符检查形同虚设。
    """
    body = text.rstrip("=")
    if len(body) < 40:
        return False
    has_digit = has_lower = has_upper = False
    for ch in body:
        if ch.isdigit():
            has_digit = True
        elif "a" <= ch <= "z":
            has_lower = True
        elif "A" <= ch <= "Z":
            has_upper = True
        elif ch not in _B64_ALPHABET:
            return False
    return has_digit and has_lower and has_upper


# 名字 -> 校验函数。YAML 里写 validate: <名字>
VALIDATORS: dict[str, Callable[[str], bool]] = {
    "base64_blob": base64_blob,
}


def get_validator(name: str) -> Callable[[str], bool]:
    """取校验器。名字写错必须报错而不能静默忽略 —— 静默忽略等于把这条
    规则的判据整个丢掉，规则看起来还在、实际只退化成"匹配 40 个字母数字"。"""
    clean = (name or "").strip()
    if clean not in VALIDATORS:
        raise KeyError(clean)
    return VALIDATORS[clean]


def names() -> list[str]:
    return sorted(VALIDATORS)
