"""L3 语义判定器。

分工：`SemanticDetector` 负责调度策略（预筛门禁）、超时兜底与统计，
具体的打分交给可插拔 backend（DeBERTa / LLM 裁判 / 轻量词袋）。
"""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from prompt_ids.core.types import DETECTOR_SEMANTIC, Finding
from prompt_ids.detectors.base import Detector, DetectorContext
from prompt_ids.detectors.semantic.base import NullBackend, Prediction, SemanticBackend
from prompt_ids.detectors.semantic.factory import build_backend

# fallback: 只在初判不确定的区间调用，省成本
# always:   全量调用，作为效果上限对照组
# hybrid:   初判有一点可疑就调用
# confirm:  只对初判 medium/high 复核，用于降误杀
MODES = ("fallback", "always", "hybrid", "confirm")

_EVIDENCE_LEN = 120


def _coerce(raw: Any, backend_name: str) -> Prediction:
    """兼容 Predicton 对象与 (prob, rationale) 元组两种返回。"""
    if isinstance(raw, Prediction):
        return raw
    if isinstance(raw, tuple) and len(raw) >= 2:
        return Prediction(float(raw[0]), str(raw[1]), backend_name)
    raise TypeError(f"不支持的预测返回类型：{type(raw).__name__}")


class SemanticDetector(Detector):
    layer = 3
    name = "semantic"

    def __init__(
        self,
        mode: str = "fallback",
        enabled: bool = False,
        model_name: str = "",
        backend: SemanticBackend | str | None = None,
        timeout_s: float | None = None,
    ):
        super().__init__(enabled=enabled)
        if mode not in MODES:
            raise ValueError(f"未知语义层模式 {mode}，可选：{MODES}")
        self.mode = mode
        self.model_name = model_name
        self.backend: SemanticBackend = self._resolve_backend(backend, model_name, enabled)
        self.timeout_s = self.backend.default_timeout_s if timeout_s is None else timeout_s

        self.calls = 0
        self.timeouts = 0
        self.errors = 0
        self.total_latency_ms = 0.0
        self.last_error: str | None = None
        self.last_prediction: Prediction | None = None
        self._executor: ThreadPoolExecutor | None = None

    # ---------- 构造 ----------
    def _resolve_backend(
        self, backend: SemanticBackend | str | None, model_name: str, enabled: bool
    ) -> SemanticBackend:
        if isinstance(backend, SemanticBackend):
            return backend
        if backend is not None:
            return build_backend(backend, model_name=model_name)
        if not enabled:
            return NullBackend()
        return build_backend("auto", model_name=model_name)

    @property
    def effective_model_name(self) -> str:
        return self.model_name or getattr(self.backend, "model_name", "") or self.backend.name

    # ---------- 生命周期 ----------
    def warmup(self) -> None:
        if self.enabled and self.backend.is_available():
            self.backend.warmup()

    def close(self) -> None:
        self.backend.close()
        if self._executor is not None:
            self._executor.shutdown(wait=False)
            self._executor = None

    # ---------- 预测（对外入口，带超时与异常兜底） ----------
    def predict(self, text: str) -> Prediction:
        started = time.perf_counter()
        try:
            raw = self._submit(lambda: self.predict_impl(text))
            prediction = _coerce(raw, self.backend.name)
        except TimeoutError:
            self.timeouts += 1
            self.last_error = f"语义后端超时（>{self.timeout_s}s）"
            prediction = Prediction(0.0, self.last_error, self.backend.name, self.timeout_s * 1000)
        except Exception as exc:
            self.errors += 1
            self.last_error = str(exc)[:200]
            prediction = Prediction(0.0, f"语义后端异常：{self.last_error}", self.backend.name)

        prediction = prediction.clamp()
        if prediction.latency_ms <= 0:
            prediction = Prediction(
                prediction.probability,
                prediction.rationale,
                prediction.backend,
                (time.perf_counter() - started) * 1000,
            )
        self.calls += 1
        self.total_latency_ms += prediction.latency_ms
        self.last_prediction = prediction
        return prediction

    def predict_impl(self, text: str) -> Prediction | tuple[float, str]:
        """扩展点：默认委托 backend，想自定义就重写本方法。"""
        return self.backend.predict(text)

    def _submit(self, task):
        if not self.timeout_s or self.timeout_s <= 0:
            return task()
        if self._executor is None:
            self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="semantic")
        return self._executor.submit(task).result(timeout=self.timeout_s)

    # ---------- Detector 接口 ----------
    def detect(self, ctx: DetectorContext) -> list[Finding]:
        if not self.enabled:
            return []
        text = (ctx.canonical or ctx.raw or "").strip()
        if not text:
            return []
        prediction = self.predict(text)
        # 低于阈值不产生 finding，但概率值仍由 last_prediction 供决策层降噪使用
        if prediction.probability <= 0.5:
            return []
        return [
            Finding(
                detector=DETECTOR_SEMANTIC,
                pattern_id="SE-001",
                category="semantic",
                weight=9.0,
                evidence=prediction.rationale[:_EVIDENCE_LEN],
                confidence=round(prediction.probability, 4),
                variant="semantic",
                note=f"[{prediction.backend}] {self.effective_model_name}",
            )
        ]

    def subscore(self, findings: list[Finding]) -> float:
        """语义层不需要堆叠衰减，直接用最高置信度映射 0-100。"""
        if not findings:
            return 0.0
        return round(min(100.0, max(f.confidence for f in findings) * 100.0), 2)

    def contribution(self) -> float | None:
        """本层对融合的贡献分。未调用过则返回 None。

        即使没产生 finding 也返回分数 —— 语义层同样能扮演"降噪"角色，
        把规则层误判的正常文本拉回安全区。
        """
        if not self.enabled or self.last_prediction is None:
            return None
        return round(self.last_prediction.probability * 100.0, 2)

    def should_invoke(self, preliminary_score: float, level: str) -> bool:
        """预筛门禁：正则层 0.5ms，语义层 50-200ms，这道门省掉约 80% 调用。"""
        if not self.enabled or not self.backend.is_available():
            return False
        if self.mode == "always":
            return True
        if self.mode == "confirm":
            return level in ("medium", "high")
        if self.mode == "hybrid":
            return preliminary_score >= 10.0
        return 20.0 <= preliminary_score <= 70.0

    def stats(self) -> dict[str, Any]:
        return {
            "backend": self.backend.name,
            "model": self.effective_model_name,
            "mode": self.mode,
            "available": self.backend.is_available(),
            "timeout_s": self.timeout_s,
            "calls": self.calls,
            "timeouts": self.timeouts,
            "errors": self.errors,
            "avg_latency_ms": round(self.total_latency_ms / self.calls, 2) if self.calls else 0.0,
            "last_error": self.last_error,
        }
