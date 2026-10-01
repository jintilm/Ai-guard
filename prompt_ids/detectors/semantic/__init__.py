"""L3 语义层 —— 可插拔后端，缺依赖自动降级。

    from prompt_ids.detectors.semantic import SemanticDetector, MODES, build_backend

    det = SemanticDetector(mode="fallback", enabled=True)          # 自动挑后端
    det = SemanticDetector(enabled=True, backend="local")          # 指定本地 DeBERTa
    det = SemanticDetector(enabled=True, backend="llm")            # LLM 裁判（auto 选厂商）
    det = SemanticDetector(enabled=True, backend="ollama")         # 本地推理
    det = SemanticDetector(enabled=True, backend="groq/llama-3.3-70b-versatile")
    det.predict("Ignore all previous instructions")

21 家提供商与「一行写法」见 `prompt_ids.detectors.semantic.providers`。
"""
from prompt_ids.detectors.semantic.base import (
    NullBackend,
    Prediction,
    SemanticBackend,
)
from prompt_ids.detectors.semantic.detector import MODES, SemanticDetector
from prompt_ids.detectors.semantic.factory import (
    build_backend,
    probe,
    provider_table,
)
from prompt_ids.detectors.semantic.lightweight import LightweightBackend
from prompt_ids.detectors.semantic.llm import LLMBackend, LLMJudgeBackend, diagnose_llm
from prompt_ids.detectors.semantic.local import DEFAULT_MODEL, LocalModelBackend
from prompt_ids.detectors.semantic.providers import (
    PROVIDERS,
    Provider,
    list_models,
    provider_names,
    split_model_spec,
)

__all__ = [
    "DEFAULT_MODEL",
    "MODES",
    "PROVIDERS",
    "LLMBackend",
    "LLMJudgeBackend",
    "LightweightBackend",
    "LocalModelBackend",
    "NullBackend",
    "Prediction",
    "Provider",
    "SemanticBackend",
    "SemanticDetector",
    "build_backend",
    "diagnose_llm",
    "list_models",
    "probe",
    "provider_names",
    "provider_table",
    "split_model_spec",
]
