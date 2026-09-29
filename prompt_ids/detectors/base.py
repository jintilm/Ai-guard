"""检测器抽象基类与上下文。"""
from __future__ import annotations

import math
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from prompt_ids.core.types import Finding, Variant


@dataclass(slots=True)
class DetectorContext:
    """传给每个检测器的只读上下文。"""

    raw: str
    canonical: str
    variants: list[Variant]
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def variant_texts(self) -> list[str]:
        return [v.text for v in self.variants]

    def variant_kind(self, index: int) -> str:
        return self.variants[index].kind if 0 <= index < len(self.variants) else "unknown"


def saturate(accumulated: float, k: float = 4.0) -> float:
    """把累加权重压到 0-100。单条 CRITICAL 规则约 88 分，弱规则约 30-40 分。"""
    return 100.0 * (1.0 - math.exp(-max(accumulated, 0.0) / k))


class Detector(ABC):
    layer: int = 0
    name: str = "base"

    def __init__(self, enabled: bool = True):
        self.enabled = enabled

    @abstractmethod
    def detect(self, ctx: DetectorContext) -> list[Finding]:
        """返回命中列表，不去重（由引擎统一处理）。"""

    def subscore(self, findings: list[Finding]) -> float:
        """把本层命中折算成 0-100 子分，供决策层加权融合。"""
        weighted = sorted(
            (f.weight * f.confidence for f in findings),
            reverse=True,
        )
        accumulated = sum(w * (0.5**i) for i, w in enumerate(weighted[:8]))
        return round(saturate(accumulated), 2)

    def timed_detect(self, ctx: DetectorContext) -> tuple[list[Finding], float]:
        start = time.perf_counter()
        findings = self.detect(ctx) if self.enabled else []
        elapsed = (time.perf_counter() - start) * 1000.0
        return findings, elapsed

    def __repr__(self) -> str:  # pragma: no cover - 调试辅助
        return f"<{self.__class__.__name__} enabled={self.enabled}>"
