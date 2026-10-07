"""评测指标。

论文实验章节直接引用这里的定义：以 high/critical 为「判定攻击」的阈值，
因为生产上这两个等级才会触发 sandbox / block。
"""
from __future__ import annotations

import math
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

BLOCK_LEVELS = frozenset({"high", "critical"})


@dataclass(frozen=True, slots=True)
class Confusion:
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0

    @classmethod
    def from_pairs(cls, y_true: Iterable[int], y_pred: Iterable[int]) -> Confusion:
        tp = fp = tn = fn = 0
        for truth, pred in zip(y_true, y_pred):
            if truth == 1 and pred == 1:
                tp += 1
            elif truth == 0 and pred == 1:
                fp += 1
            elif truth == 0 and pred == 0:
                tn += 1
            else:
                fn += 1
        return cls(tp, fp, tn, fn)

    @property
    def total(self) -> int:
        return self.tp + self.fp + self.tn + self.fn

    def _div(self, num: int, den: int) -> float:
        return num / den if den else 0.0

    @property
    def precision(self) -> float:
        return self._div(self.tp, self.tp + self.fp)

    @property
    def recall(self) -> float:
        return self._div(self.tp, self.tp + self.fn)

    @property
    def specificity(self) -> float:
        return self._div(self.tn, self.tn + self.fp)

    @property
    def fpr(self) -> float:
        """误报率（把正常当攻击的比例）—— 答辩最容易被追问的一项。"""
        return self._div(self.fp, self.fp + self.tn)

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 0.0 if (p + r) == 0 else 2 * p * r / (p + r)

    @property
    def accuracy(self) -> float:
        return self._div(self.tp + self.tn, self.total)

    def as_row(self) -> dict[str, float]:
        return {
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "false_positive_rate": round(self.fpr, 4),
            "specificity": round(self.specificity, 4),
            "accuracy": round(self.accuracy, 4),
            "tp": self.tp,
            "fp": self.fp,
            "tn": self.tn,
            "fn": self.fn,
        }


def percentile(values: Sequence[float], q: float) -> float:
    """线性插值分位数。q ∈ [0,1]。"""
    if not values:
        return 0.0
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    pos = (len(ordered) - 1) * min(max(q, 0.0), 1.0)
    low = math.floor(pos)
    high = math.ceil(pos)
    if low == high:
        return ordered[low]
    return ordered[low] + (ordered[high] - ordered[low]) * (pos - low)


def latency_stats(values: Sequence[float]) -> dict[str, float]:
    if not values:
        return {"mean": 0.0, "p50": 0.0, "p95": 0.0, "p99": 0.0, "max": 0.0}
    return {
        "mean": round(sum(values) / len(values), 3),
        "p50": round(percentile(values, 0.50), 3),
        "p95": round(percentile(values, 0.95), 3),
        "p99": round(percentile(values, 0.99), 3),
        "max": round(max(values), 3),
    }


def markdown_table(headers: Sequence[str], rows: Sequence[Sequence[object]], aligns: str | None = None) -> str:
    """生成 markdown 表格，直接贴进论文。"""
    if aligns is None:
        aligns = "l" * len(headers)
    mapping = {"l": ":---", "c": ":---:", "r": "---:"}
    header_line = "| " + " | ".join(str(h) for h in headers) + " |"
    sep_line = "| " + " | ".join(mapping.get(a, ":---") for a in aligns) + " |"
    body = ["| " + " | ".join(str(c) for c in row) + " |" for row in rows]
    return "\n".join([header_line, sep_line, *body])
