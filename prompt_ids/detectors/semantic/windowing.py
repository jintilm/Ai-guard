"""Bounded input selection for LLM judges; offsets always refer to their input."""
from __future__ import annotations

from dataclasses import dataclass

from prompt_ids.core.types import TextCoverage

INPUT_STRATEGIES = ("head", "stratified")
INPUT_SAMPLING_VERSION = 1
GAP = "\n\n[... content omitted ...]\n\n"


@dataclass(frozen=True, slots=True)
class SampledText:
    text: str
    coverage: TextCoverage


def sample_text(text: str, *, budget: int = 3000, strategy: str = "head",
                max_windows: int = 3) -> SampledText:
    if strategy not in INPUT_STRATEGIES:
        raise ValueError(f"Unknown input strategy: {strategy!r}")
    if type(budget) is not int or budget < 1:
        raise ValueError("Input character budget must be a positive integer")
    if type(max_windows) is not int or not 1 <= max_windows <= 8:
        raise ValueError("max_windows must be an integer between 1 and 8")
    length = len(text)
    if not text:
        return SampledText("", TextCoverage(strategy, 0, ()))
    if length <= budget or strategy == "head":
        spans = ((0, min(length, budget)),)
    else:
        count = min(max_windows, (budget + len(GAP)) // (len(GAP) + 1))
        kept = budget - (count - 1) * len(GAP)
        width, remainder = divmod(kept, count)
        ranges = []
        for index in range(count):
            size = width + int(index < remainder)
            start = (length - size) * index // (count - 1) if count > 1 else 0
            ranges.append((start, start + size))
        spans = tuple(ranges)
    return SampledText(GAP.join(text[start:end] for start, end in spans),
                       TextCoverage(strategy, length, spans))
