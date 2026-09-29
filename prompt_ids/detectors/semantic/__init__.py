"""L3 语义层 —— 可插拔后端，缺依赖自动降级。

    from prompt_ids.detectors.semantic import SemanticDetector, MODES, build_backend

    det = SemanticDetector(mode="fallback", enabled=True)          # 自动挑后端
    det = SemanticDetector(enabled=True, backend="local")          # 指定本地 DeBERTa
    det = SemanticDetector(enabled=True, backend="llm")            # LLM 裁判
    det.predict("Ignore all previous instructions")
"""
from prompt_ids.detectors.semantic.base import (
    NullBackend,
    Prediction,
    SemanticBackend,
)
from prompt_ids.detectors.semantic.detector import MODES, SemanticDetector
from prompt_ids.detectors.semantic.factory import build_backend, probe
from prompt_ids.detectors.semantic.lightweight import LightweightBackend
from prompt_ids.detectors.semantic.llm import LLMJudgeBackend
from prompt_ids.detectors.semantic.local import DEFAULT_MODEL, LocalModelBackend

__all__ = [
    "DEFAULT_MODEL",
    "MODES",
    "LLMJudgeBackend",
    "LightweightBackend",
    "LocalModelBackend",
    "NullBackend",
    "Prediction",
    "SemanticBackend",
    "SemanticDetector",
    "build_backend",
    "probe",
]
