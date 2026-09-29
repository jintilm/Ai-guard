"""全局数据契约。

检测器、决策层、流水线、SDK/CLI 只依赖本模块，互不反向依赖。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

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

    @property
    def is_blocked(self) -> bool:
        return self.action in (Action.BLOCK, Action.SANDBOX)

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
        }

    def summary(self) -> str:
        lines = [
            f"判定: {self.level.value.upper():<8} 分数: {self.score:.1f}  动作: {self.action.value}",
            f"说明: {self.explained}",
        ]
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
