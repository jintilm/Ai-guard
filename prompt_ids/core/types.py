"""全局数据契约。

检测器、决策层、流水线、SDK/CLI 只依赖本模块，互不反向依赖。
"""
from __future__ import annotations

import copy
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from prompt_ids.core.execution import SemanticExecution

DETECTOR_RULE = "rule"
DETECTOR_HEURISTIC = "heuristic"
DETECTOR_SEMANTIC = "semantic"
DETECTOR_MEMORY = "memory"


class Level(str, Enum):
    """五级风险判定。"""

    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Action(str, Enum):
    """策略动作。"""

    PASS = "pass"
    LOG = "log"
    REVIEW = "review"
    SANDBOX = "sandbox"
    BLOCK = "block"


_LEVEL_RANK: dict[Level, int] = {
    Level.SAFE: 0,
    Level.LOW: 1,
    Level.MEDIUM: 2,
    Level.HIGH: 3,
    Level.CRITICAL: 4,
}


def level_rank(level: Level) -> int:
    return _LEVEL_RANK[level]


@dataclass(frozen=True, slots=True)
class Variant:
    """文本的一个解码变体。hops 为从原文出发的解码层数。"""

    kind: str
    text: str
    hops: int = 0


@dataclass(frozen=True, slots=True)
class Finding:
    """单条命中证据。

    evidence 必须截断，避免审计日志被超长 prompt 撑爆。
    """

    detector: str
    pattern_id: str
    category: str
    weight: float
    evidence: str
    confidence: float = 1.0
    variant: str = "original"
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "detector": self.detector,
            "pattern_id": self.pattern_id,
            "category": self.category,
            "weight": self.weight,
            "evidence": self.evidence,
            "confidence": round(self.confidence, 4),
            "variant": self.variant,
            "note": self.note,
        }


@dataclass(slots=True)
class ScanResult:
    score: float = 0.0
    level: Level = Level.SAFE
    action: Action = Action.PASS
    findings: list[Finding] = field(default_factory=list)
    latency_ms: dict[str, float] = field(default_factory=dict)
    explained: str = ""
    fingerprint: str = ""
    cached: bool = False
    truncated: bool = False
    rejected: str = ""
    # 因预算耗尽或短路而未执行的检测层 —— 静默跳过比报错更危险，必须可见
    skipped: tuple[str, ...] = ()
    semantic_coverage: TextCoverage | None = None
    semantic_ok: bool | None = None
    context_fingerprint: str = ""
    semantic_context_used: bool = False
    semantic_execution: SemanticExecution | None = None

    @property
    def is_blocked(self) -> bool:
        return self.action in (Action.BLOCK, Action.SANDBOX)

    def detached(self) -> ScanResult:
        """返回一个**不共享可变成员**的副本。

        缓存命中时必须用它。`copy.copy` 是浅拷贝：`findings` 与 `latency_ms`
        仍指向缓存里那一份，调用方随手 `result.findings.append(...)` 或
        `result.latency_ms["x"] = 1`，改的就是**缓存本身** —— 下一次命中会读到
        上次调用方留下的脏数据，而且没有任何报错。`Finding` 是 frozen 的，
        所以列表逐元素复制即可；`skipped` 是 tuple，天然不可变。
        """
        clone = copy.copy(self)
        clone.findings = list(self.findings)
        clone.latency_ms = dict(self.latency_ms)
        return clone

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": round(self.score, 2),
            "level": self.level.value,
            "action": self.action.value,
            "findings": [f.to_dict() for f in self.findings],
            "latency_ms": {k: round(v, 3) for k, v in self.latency_ms.items()},
            "explained": self.explained,
            "fingerprint": self.fingerprint,
            "cached": self.cached,
            "truncated": self.truncated,
            "rejected": self.rejected,
            "skipped": list(self.skipped),
            "semantic_coverage": self.semantic_coverage.to_dict() if self.semantic_coverage else None,
            "semantic_ok": self.semantic_ok,
            "context_fingerprint": self.context_fingerprint,
            "semantic_context_used": self.semantic_context_used,
            "semantic_execution": self.semantic_execution.to_dict() if self.semantic_execution else None,
        }

    def summary(self) -> str:
        lines = [
            f"判定: {self.level.value.upper():<8} 分数: {self.score:.1f}  动作: {self.action.value}",
            f"说明: {self.explained}",
        ]
        if self.semantic_execution:
            lines.append("语义执行: " + self.semantic_execution.summary())
        if self.context_fingerprint:
            lines.append("任务上下文: " + ("已用于有效判决" if self.semantic_context_used else "未用于有效判决"))
        if self.semantic_coverage:
            coverage = self.semantic_coverage
            lines.append(f"所选语义输入: {coverage.sampled_chars}/{coverage.input_chars} 字符"
                         f" · {len(coverage.ranges)} 个窗口 · {coverage.strategy}"
                         f" · {'取得判决' if self.semantic_ok else '未取得判决'}")
        if self.findings:
            lines.append(f"命中 {len(self.findings)} 项:")
            for f in self.findings[:10]:
                lines.append(
                    f"  [{f.detector}] {f.pattern_id} ({f.category}) "
                    f"w={f.weight} conf={f.confidence:.2f} via={f.variant}"
                )
                lines.append(f"     证据: {f.evidence}")
        if "total" in self.latency_ms:
            parts = " ".join(f"{k}={v:.2f}ms" for k, v in self.latency_ms.items() if k != "total")
            total = self.latency_ms["total"]
        else:
            parts = " ".join(f"{k}={v:.2f}ms" for k, v in self.latency_ms.items())
            total = sum(self.latency_ms.values())
        lines.append(f"耗时: {total:.2f}ms ({parts})")
        return "\n".join(lines)


@dataclass(frozen=True, slots=True)
class TextCoverage:
    """Character offsets in the backend input, without any original text."""

    strategy: str
    input_chars: int
    ranges: tuple[tuple[int, int], ...]

    def __post_init__(self):
        if self.strategy not in ("head", "stratified"):
            raise ValueError("Unknown text sampling strategy")
        if type(self.input_chars) is not int or self.input_chars < 0:
            raise ValueError("input_chars must be a nonnegative integer")
        if not isinstance(self.ranges, tuple) or len(self.ranges) > 8:
            raise ValueError("Coverage requires at most eight immutable ranges")
        previous = 0
        for span in self.ranges:
            if not isinstance(span, tuple) or len(span) != 2:
                raise ValueError("Invalid coverage range")
            start, end = span
            if type(start) is not int or type(end) is not int or not previous <= start < end <= self.input_chars:
                raise ValueError("Coverage ranges must be ordered, disjoint and inside the input")
            previous = end

    @property
    def sampled_chars(self) -> int:
        return sum(end - start for start, end in self.ranges)

    def to_dict(self) -> dict[str, Any]:
        return {
            "strategy": self.strategy,
            "input_basis": "backend_input",
            "input_chars": self.input_chars,
            "sampled_chars": self.sampled_chars,
            "coverage_ratio": round(self.sampled_chars / self.input_chars, 6) if self.input_chars else 0.0,
            "window_count": len(self.ranges),
            "ranges": [list(span) for span in self.ranges],
            "truncated": self.sampled_chars < self.input_chars,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TextCoverage:
        return cls(data["strategy"], data["input_chars"], tuple(tuple(span) for span in data["ranges"]))
