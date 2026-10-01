"""后端工厂：按可用依赖自动选型，缺失时优雅降级。

选型优先级：本地模型 → LLM 裁判 → 轻量词袋 → Null。
任何一环装不上都不影响主链路，降级信息会写进 ScanResult，评测时能看到。

`spec` 接受三种写法，语义由「注册表里有没有这个名字」决定，不做无脑拆分：

    local / lightweight / null          ← 内置后端关键字
    deepseek / ollama / groq / ...      ← 任一注册表里的提供商（共 21 家）
    groq/llama-3.3-70b-versatile        ← LiteLLM 风格的「提供商/模型」一行写法
    protectai/deberta-v3-...            ← 左半边不是已知提供商，按 HF repo id 处理
"""
from __future__ import annotations

from typing import Any

from prompt_ids.detectors.semantic.base import NullBackend, SemanticBackend
from prompt_ids.detectors.semantic.lightweight import LightweightBackend
from prompt_ids.detectors.semantic.llm import LLMBackend, diagnose_llm
from prompt_ids.detectors.semantic.local import DEFAULT_MODEL, LocalModelBackend
from prompt_ids.detectors.semantic.providers import (
    PROVIDERS,
    get as get_provider,
    provider_names,
    resolve_provider,
    split_model_spec,
)

#: 非 LLM 的本地后端关键字
BUILTIN = ("local", "lightweight", "null")


def build_backend(spec: str | SemanticBackend | None = "auto", **kwargs) -> SemanticBackend:
    """构造语义后端。

    spec 取值：
      auto              按依赖可用性自动挑选，全部不可用时返回 NullBackend
      local             transformers + torch 本地推理（DeBERTa）
      lightweight       sklearn TF-IDF + 逻辑回归（需先训练）
      null              显式关闭
      llm               任一已配 Key 的提供商（auto 选型）
      <provider>        21 家之一：deepseek / openai / azure / qwen / zhipu / moonshot /
                        siliconflow / volces / qianfan / minimax / anthropic / groq /
                        mistral / together / openrouter / xai / perplexity /
                        ollama / vllm / lmstudio / custom
      <provider>/<模型>  LiteLLM 风格一行写法，如 groq/llama-3.3-70b-versatile
      其他字符串        视为 HuggingFace repo id，用 local 后端加载
    """
    if isinstance(spec, SemanticBackend):
        return spec

    # 空串会让 LocalModelBackend 拿到 '' 当 repo id，必须在入口就过滤掉
    kwargs = {k: v for k, v in kwargs.items() if v not in (None, "")}
    key = (spec or "auto").strip()

    if key.lower() in ("auto", ""):
        for candidate in ("local", "llm", "lightweight"):
            backend = build_backend(candidate, **kwargs)
            if backend.is_available():
                return backend
        return NullBackend()

    lowered = key.lower()
    if lowered == "null":
        return NullBackend()
    if lowered == "local":
        return LocalModelBackend(
            model_name=kwargs.get("model_name", DEFAULT_MODEL), **_strip(kwargs, "model_name")
        )
    if lowered == "lightweight":
        return LightweightBackend(model_path=kwargs.get("model_path"))
    if lowered == "llm":
        return _llm_backend(provider="auto", model_name=kwargs.get("model_name", ""), kwargs=kwargs)

    provider, model = split_model_spec(key)
    if provider:
        return _llm_backend(provider=provider, model_name=model, kwargs=kwargs)
    if lowered in PROVIDERS:
        return _llm_backend(provider=lowered, model_name=kwargs.get("model_name", ""), kwargs=kwargs)

    # 未识别的字符串当作 HF repo id，交给 local 后端
    return LocalModelBackend(model_name=spec or DEFAULT_MODEL)


def _llm_backend(provider: str, model_name: str, kwargs: dict[str, Any]) -> LLMBackend:
    picked = _pick(kwargs, "base_url", "api_key", "max_retries", "fallbacks", "allow_fallbacks")
    return LLMBackend(provider=provider, model_name=model_name, **picked)


def _strip(data: dict[str, Any], *names: str) -> dict[str, Any]:
    return {k: v for k, v in data.items() if k not in names}


def _pick(data: dict[str, Any], *names: str) -> dict[str, Any]:
    return {k: v for k, v in data.items() if k in names}


def probe() -> dict[str, dict[str, Any]]:
    """列出所有后端的可用性与原因，便于排查环境问题。

    键顺序即展示顺序：先是三个非 LLM 后端，再是全部 21 家提供商，最后 `selected`。
    `chosen=True` 标出 `auto` 实际会选中哪一家 —— 排查「以为在用 A 其实在用 B」时最关键。
    """
    report: dict[str, dict[str, Any]] = {}

    report["local"] = LocalModelBackend().info()
    report["lightweight"] = LightweightBackend().info()
    llm_auto = LLMBackend()
    report["llm"] = llm_auto.info()
    if not llm_auto.is_available():
        report["llm"]["reason"] = (
            "未配置任何 API Key。填 .env 即可（模板 .env.example），"
            "常用：DEEPSEEK_API_KEY / DASHSCOPE_API_KEY / OPENAI_API_KEY"
        )
    report["null"] = NullBackend().info()

    report.update(diagnose_llm())

    chosen = build_backend("auto")
    report["selected"] = {
        "backend": chosen.name,
        "provider": getattr(chosen, "provider", ""),
        "info": chosen.info(),
        "reason": _explain(chosen.name, chosen),
    }
    return report


def provider_table() -> list[dict[str, Any]]:
    """给 CLI / 看板用的扁平提供商清单（含可用性）。"""
    diagnosis = diagnose_llm()
    return [diagnosis[name] for name in provider_names()]


def _explain(name: str, backend: SemanticBackend) -> str:
    if backend.is_available():
        return "可用"
    if name == "local":
        return "缺少 transformers/torch，或未连通模型镜像站"
    if name == "llm_judge":
        return backend.unavailable_reason() if hasattr(backend, "unavailable_reason") else "未配置 API Key"
    if name == "lightweight":
        return "未找到训练好的模型文件，请先运行 scripts/train_lightweight.py"
    if name == "null":
        return "显式关闭语义层"
    return "不可用"


def provider_help() -> str:
    """一行行的提供商清单，给 CLI 帮助与错误提示复用。"""
    lines = []
    for name in provider_names():
        entry = get_provider(name)
        assert entry is not None
        key = " / ".join(entry.key_envs) or "（免 Key）"
        lines.append(f"  {name:<12} {entry.label:<24} {entry.default_model:<38} {key}")
    return "\n".join(lines)


__all__ = [
    "build_backend",
    "probe",
    "provider_table",
    "provider_help",
    "resolve_provider",
    "provider_names",
    "PROVIDERS",
    "BUILTIN",
]
