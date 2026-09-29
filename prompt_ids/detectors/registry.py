"""检测器注册表：按层排序、级联调度。"""
from __future__ import annotations

from prompt_ids.detectors.base import Detector


class DetectorRegistry:
    def __init__(self, detectors: list[Detector] | None = None):
        self._detectors: list[Detector] = []
        for det in detectors or []:
            self.register(det)

    def register(self, detector: Detector) -> None:
        if not isinstance(detector, Detector):
            raise TypeError(f"必须是 Detector 子类：{type(detector).__name__}")
        if any(d.name == detector.name for d in self._detectors):
            raise ValueError(f"检测器重名：{detector.name}")
        self._detectors.append(detector)
        self._detectors.sort(key=lambda d: d.layer)

    def unregister(self, name: str) -> None:
        self._detectors = [d for d in self._detectors if d.name != name]

    def get(self, name: str) -> Detector | None:
        return next((d for d in self._detectors if d.name == name), None)

    def layer(self, n: int) -> list[Detector]:
        return [d for d in self._detectors if d.layer == n and d.enabled]

    def __iter__(self):
        return iter(self._detectors)

    def __len__(self) -> int:
        return len(self._detectors)

    def names(self) -> list[str]:
        return [d.name for d in self._detectors]
