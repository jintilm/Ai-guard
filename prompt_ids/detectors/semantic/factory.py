"""后端工厂：按可用依赖自动选型，缺失时优雅降级。

选型优先级：本地模型 → LLM 裁判 → 轻量词袋 → Null。
任何一环装不上都不影响主链路，降级信息会写进 ScanResult，评测时能看到。
"""
from __future__ import annotations

from typing import Any

from prompt_ids.detectors.semantic.base import NullBackend, SemanticBackend
from prompt_ids.detectors.semantic.lightweight import LightweightBackend
from prompt_ids.detectors.semantic.llm import LLMJudgeBackend
from prompt_ids.detectors.semantic.local import DEFAULT_MODEL, LocalModelBackend

# spec 关键字 -> 构造器
_ALIASES: dict[str, tuple[str, dict[str, Any]]] = {}


def _register(name: str, factory, kwargs: dict[str, Any] | None = None) -> None:
    _ALIASES[name] = (factory, kwargs or {})


def build_backend(spec: str | SemanticBackend | None = "auto", **kwargs) -> SemanticBackend:
    """构造语义后端。

    spec 取值：
      auto        按依赖可用性自动挑选，全部不可用时返回 NullBackend
      local       transformers + torch 本地推理（DeBERTa）
      llm         OpenAI 兼容 LLM 裁判（按环境变量自动判定 provider）
      deepseek    DeepSeek 官方端点（api.deepseek.com，deepseek-chat）
      openai      OpenAI 官方端点
      lightweight sklearn TF-IDF + 逻辑回归（需先训练）
      null        显式关闭
      其他字符串   视为 HuggingFace repo id，用 local 后端加载
    """
    if isinstance(spec, SemanticBackend):
        return spec

    # 空串会让 LocalModelBackend 拿到 '' 当 repo id，必须在入口就过滤掉
    kwargs = {k: v for k, v in kwargs.items() if v not in (None, "")}
    key = (spec or "auto").strip().lower()

    if key in ("auto", ""):
        for candidate in ("local", "llm", "lightweight"):
            backend = build_backend(candidate, **kwargs)
            if backend.is_available():
                return backend
        return NullBackend()

    if key == "null":
        return NullBackend()
    if key == "local":
        return LocalModelBackend(model_name=kwargs.get("model_name", DEFAULT_MODEL), **_strip(kwargs, "model_name"))
    if key in ("llm", "deepseek", "openai"):
        provider = "auto" if key == "llm" else key
        return LLMJudgeBackend(
            provider=provider,
            **_pick(kwargs, "model_name", "base_url", "api_key", "max_retries"),
        )
    if key == "lightweight":
        return LightweightBackend(model_path=kwargs.get("model_path"))
    # 未识别的字符串当作 repo id
    return LocalModelBackend(model_name=spec or DEFAULT_MODEL)


def _strip(data: dict[str, Any], *names: str) -> dict[str, Any]:
    return {k: v for k, v in data.items() if k not in names}


def _pick(data: dict[str, Any], *names: str) -> dict[str, Any]:
    return {k: v for k, v in data.items() if k in names}


def probe() -> dict[str, dict[str, Any]]:
    """列出所有后端的可用性与原因，便于排查环境问题。"""
    candidates: dict[str, SemanticBackend] = {
        "local": LocalModelBackend(),
        "llm": LLMJudgeBackend(),
        "deepseek": LLMJudgeBackend(provider="deepseek"),
        "openai": LLMJudgeBackend(provider="openai"),
        "lightweight": LightweightBackend(),
    }
    report: dict[str, dict[str, Any]] = {}
    for name, backend in candidates.items():
        report[name] = backend.info()
        report[name]["reason" if not backend.is_available() else "note"] = _explain(name, backend)
    chosen = build_backend("auto")
    report["selected"] = {"backend": chosen.name, "info": chosen.info()}
    return report


def _explain(name: str, backend: SemanticBackend) -> str:
    if backend.is_available():
        return "可用"
    if name == "local":
        return "缺少 transformers/torch，或未连通模型镜像站"
    if name == "deepseek":
        return "未设置 DEEPSEEK_API_KEY（可写在项目根目录 .env，见 .env.example）"
    if name == "openai":
        return "未设置 OPENAI_API_KEY（可写在项目根目录 .env，见 .env.example）"
    if name == "llm":
        return "未设置 PROMPT_IDS_LLM_API_KEY / DEEPSEEK_API_KEY / OPENAI_API_KEY"
    return "未找到训练好的模型文件，请先运行 scripts/train_lightweight.py"
