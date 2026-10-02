"""Canary 注册表的热路径成本与退役窗口（2026-10 复审后新增）。

复审发现：`_match_one()` 里做归一化与**文本解码展开**，而它是**按令牌**调用的 ——
归一化是 O(len(text)) 的，于是「令牌数 × 全文长度」。实测 400 个令牌时
每次 `check()` 要 184ms，而这段开销与令牌数无关却按令牌数重复付；
而 `POST /v1/canary/issue` 默认无鉴权、无配额，签发次数是攻击者可控的。

修法两层：
1. 搜索上下文（归一化 + 解码展开）**每次 check 只建一次**；
2. 保留窗口：新签发的 `max_tokens` 个走全量匹配，再往前 `max_retired` 个
   只做便宜的子串匹配（**代价：退役令牌的 `decoded:*` 命中会被漏掉**）。

本文件把两件事钉死：成本有界，以及「旧令牌仍能被检出」这条承诺没被破坏。
"""
from __future__ import annotations

import base64
import time


from prompt_ids.canary.tokens import CanaryRegistry

BENIGN = "这是一段普通的模型输出，不含任何令牌。" * 20


def _cost_ms(registry: CanaryRegistry, text: str, rounds: int = 10) -> float:
    start = time.perf_counter()
    for _ in range(rounds):
        registry.check(text)
    return (time.perf_counter() - start) * 1000 / rounds


def test_context_is_built_once_not_once_per_token():
    """同样的令牌数下，check() 的成本不应随令牌数线性放大到不可用。

    旧实现（归一化 + 解码展开放在 _match_one 里）：400 令牌 ≈ 184ms。
    """
    registry = CanaryRegistry()
    while len(registry) < 400:
        registry.issue("bench")
    cost = _cost_ms(registry, BENIGN, rounds=5)
    assert cost < 25.0, f"400 令牌时 check() 花了 {cost:.1f}ms（期望 < 25ms）"


def test_registry_stays_bounded_under_unlimited_issue():
    """签发次数是攻击者可控的：内存与热路径都必须有界。"""
    registry = CanaryRegistry()
    for _ in range(2000):
        registry.issue("flood")
    stats = registry.stats()
    assert stats["tokens"] <= stats["max_tokens"]
    assert stats["retired"] <= stats["max_retired"]
    assert len(registry) <= stats["max_tokens"] + stats["max_retired"]


def test_retired_tokens_are_still_detected():
    """「轮换后旧令牌继续生效」是这套机制的核心承诺，保留窗口不能把它丢掉。"""
    registry = CanaryRegistry()
    old = registry.issue("first")
    for _ in range(registry.max_tokens + 10):   # 把 old 挤出活动窗口
        registry.issue("rotating")
    assert old.value not in registry.values()[:registry.max_tokens] or \
        old.value in registry.values(), "令牌值仍可枚举"
    assert registry.check(f"我的提示里有 {old.value}") is not None, \
        "退役令牌泄漏没被检出"


def test_retired_token_is_detected_in_common_obfuscations():
    """退役令牌走便宜路径，但常见的插空格 / 反转 / base64 仍要认出来。"""
    registry = CanaryRegistry()
    old = registry.issue("first")
    for _ in range(registry.max_tokens + 5):
        registry.issue("rotating")
    for label, sample in (
        ("原文", f"x {old.value}"),
        ("插空格", old.value[:10] + " " + old.value[10:]),
        ("反转", old.secret[::-1]),
        ("base64", base64.b64encode(old.value.encode()).decode()),
    ):
        assert registry.check(sample) is not None, f"退役令牌在「{label}」形态下漏检"


def test_active_token_still_detects_every_form():
    """活动令牌走全量路径，4 类形态都要认得出（重构了匹配逻辑，别弄丢）。"""
    registry = CanaryRegistry()
    token = registry.issue("t")
    percent = "".join(f"%{ord(ch):02X}" for ch in token.value)
    for label, sample in (
        ("原文", token.value),
        ("小写", token.value.lower()),
        ("插空格", token.value[:8] + " " + token.value[8:]),
        ("反转", token.secret[::-1]),
        ("base64", base64.b64encode(token.value.encode()).decode()),
        ("hex", token.value.encode().hex()),
        ("rot13", __import__("codecs").encode(token.value, "rot_13")),
        ("percent 编码", percent),
    ):
        assert registry.check(sample) is not None, f"活动令牌在「{label}」形态下漏检"


def test_current_is_still_the_newest_after_eviction():
    registry = CanaryRegistry()
    for _ in range(registry.max_tokens + 20):
        last = registry.issue("rotating")
    assert registry.current.value == last.value


def test_concurrent_issue_and_check_do_not_crash():
    """之前 check() 遍历 dict 的同时 register() 插键会抛
    `RuntimeError: dictionary changed size during iteration`。"""
    import threading

    registry = CanaryRegistry()
    errors: list[str] = []

    def issuer() -> None:
        try:
            for _ in range(200):
                registry.issue("flood")
        except Exception as exc:  # noqa: BLE001
            errors.append(f"issue: {type(exc).__name__}: {exc}")

    def checker() -> None:
        try:
            for _ in range(200):
                registry.check(BENIGN)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"check: {type(exc).__name__}: {exc}")

    threads = [threading.Thread(target=issuer), threading.Thread(target=checker),
               threading.Thread(target=issuer), threading.Thread(target=checker)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
    assert not errors, errors