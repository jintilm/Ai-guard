"""正则引擎选择。

规则层是整条流水线里唯一随输入长度线性增长的部分，因为它要对
「每条规则 × 每个变体」各做一次全文搜索。实测（24KB 文本、70 条规则）：

    re     逐条搜索   中文为主 21.5ms / 英文为主 36.0ms
    regex  逐条搜索   中文为主  5.0ms / 英文为主 27.7ms   → 4.33× / 1.30×

差距来自 `regex` 对字面量前缀（ignore、vergiss、disregard…）会先做
一次快速定位再回溯，而 `re` 只能从每个位置逐字符尝试。

两个引擎在默认模式下语法兼容（`regex` 默认 VERSION0 即 `re` 语义），
所以这是一次**零召回损失**的纯加速。没装 `regex` 时自动退回标准库。

可用环境变量 `PROMPT_IDS_RULE_ENGINE=re|regex` 强制指定，
方便对照实验里跑 A/B。
"""
from __future__ import annotations

import os
from typing import Any

_RE_ERRORS: tuple[type[BaseException], ...]
try:  # 标准库引擎，永远兜底
    import re as _re

    _RE_ERRORS = (_re.error,)
except Exception:  # pragma: no cover - 不可能发生
    _RE_ERRORS = (Exception,)

_REGEX_MOD = None
try:
    import regex as _regex  # type: ignore[import-not-found]

    _REGEX_MOD = _regex
except Exception:  # pragma: no cover - 未安装时退回 re
    _REGEX_MOD = None


def _requested() -> str:
    return (os.environ.get("PROMPT_IDS_RULE_ENGINE") or "").strip().lower()


def engine_name() -> str:
    """当前实际使用的引擎名：regex / re。"""
    want = _requested()
    if want == "re":
        return "re"
    if _REGEX_MOD is not None:
        return "regex"
    return "re"


def regex_available() -> bool:
    return _REGEX_MOD is not None


def errors() -> tuple[type[BaseException], ...]:
    """编译/匹配可能抛出的异常类型，供上层统一兜底。"""
    if engine_name() == "regex" and _REGEX_MOD is not None:
        return (getattr(_REGEX_MOD, "error", Exception),) + _RE_ERRORS
    return _RE_ERRORS


def compile_pattern(pattern: str) -> Any:
    """编译一条规则正则。

    刻意不传任何 flags：规则里大小写敏感的写法（13 条中文规则没有 (?i)）
    必须原样保留，全局加 IGNORECASE 会悄悄改变语义。
    两个引擎的 search/match/group API 完全一致，上层无需区分。
    """
    if engine_name() == "regex" and _REGEX_MOD is not None:
        return _REGEX_MOD.compile(pattern)
    return _re.compile(pattern)


def info() -> dict[str, Any]:
    """供 rules/canary 等接口暴露引擎信息，避免"装了没有、用了没装"说不清。"""
    return {
        "rule_engine": engine_name(),
        "regex_available": regex_available(),
        "regex_version": getattr(_REGEX_MOD, "__version__", "") if _REGEX_MOD else "",
    }
