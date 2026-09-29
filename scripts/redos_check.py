"""规则层 ReDoS 压力测试。

规则是按 YAML 手写的，正则回溯爆炸不会有任何报错，只会让某条请求突然
慢几十倍 —— 而慢的通常是"失败"的那条路径，也就是**正常输入**最容易踩到。

这个脚本把每条规则单独扔进几类对抗性 haystack 里，报出最坏耗时。
判定标准：单条规则单次匹配超过 --threshold（默认 50ms）就标红。

    python scripts/redos_check.py
    python scripts/redos_check.py --threshold 20 --size 32768
"""
from __future__ import annotations

import argparse
import string
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from prompt_ids.rules.loader import RuleBook  # noqa: E402


def haystacks(size: int) -> dict[str, str]:
    """构造"看起来正常但能让坏正则爆炸"的输入。"""
    letters = string.ascii_letters
    lower = string.ascii_lowercase
    digits = string.digits
    hexish = "0123456789abcdef"
    return {
        "纯字母": (letters * (size // len(letters) + 1))[:size],
        "纯小写": (lower * (size // len(lower) + 1))[:size],
        "纯大写": (letters.upper() * (size // len(letters) + 1))[:size],
        "纯数字": (digits * (size // len(digits) + 1))[:size],
        "十六进制": (hexish * (size // len(hexish) + 1))[:size],
        "字母+数字": (letters + digits) * (size // (len(letters) + len(digits)) + 1),
        "base64样": "aB3+/" * (size // 5 + 1),
        "纯空白": " " * size,
        "重复 a": "a" * size,
        "空格穿插": ("word " * (size // 5 + 1))[:size],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--threshold", type=float, default=50.0, help="单条规则单次匹配的告警阈值(ms)")
    parser.add_argument("--size", type=int, default=16_384, help="对抗输入长度")
    args = parser.parse_args()

    ruleset = RuleBook().ruleset
    hays = haystacks(args.size)
    print(f"规则 {len(ruleset)} 条 × 输入 {len(hays)} 类 × {args.size} 字符")
    print("-" * 74)

    offenders: list[tuple[float, str, str, str]] = []
    for rule in ruleset:
        for label, hay in hays.items():
            t0 = time.perf_counter()
            rule.match(hay)
            ms = (time.perf_counter() - t0) * 1000.0
            if ms >= args.threshold:
                offenders.append((ms, rule.id, label, rule.pattern))

    offenders.sort(reverse=True)
    if offenders:
        print(f"⚠️  超过 {args.threshold}ms 的规则：")
        for ms, rid, label, pattern in offenders:
            print(f"  {ms:9.1f} ms  {rid:<10} [{label}]  {pattern[:80]}")
    else:
        print(f"✅ 没有规则在 {args.threshold}ms 以上（含对抗性输入）")

    # 整体规则层在对抗输入上的耗时
    print("-" * 74)
    print("规则层整体最坏耗时：")
    worst = 0.0
    worst_label = ""
    for label, hay in hays.items():
        t0 = time.perf_counter()
        for rule in ruleset:
            rule.match(hay)
        ms = (time.perf_counter() - t0) * 1000.0
        if ms > worst:
            worst, worst_label = ms, label
        print(f"  {label:<10} {ms:9.1f} ms")
    print(f"→ 最坏 {worst:.1f} ms（{worst_label}）")

    return 1 if offenders else 0


if __name__ == "__main__":
    raise SystemExit(main())
