"""提示词注入检测系统 —— Python SDK。

    from prompt_ids import scan
    result = scan("Ignore all previous instructions")
    result.is_blocked  # True

API Key 等凭据写在项目根目录的 `.env`（模板见 `.env.example`），
导入本包时自动加载；已存在的真实环境变量优先，不会被文件覆盖。
"""
from __future__ import annotations

# 必须在其它子模块导入之前执行：规则引擎等在导入期就会读环境变量
from prompt_ids.env import load_env as _load_env

_load_env()

from prompt_ids.core.pipeline import Pipeline, PipelineConfig, create_pipeline  # noqa: E402
from prompt_ids.core.policy import Policy, PolicyEngine  # noqa: E402
from prompt_ids.core.types import Action, Finding, Level, ScanResult  # noqa: E402

__version__ = "0.1.0"

__all__ = [
    "Action",
    "Finding",
    "Guard",
    "Level",
    "Pipeline",
    "PipelineConfig",
    "Policy",
    "PolicyEngine",
    "ScanResult",
    "__version__",
    "create_pipeline",
    "get_pipeline",
    "load_env",
    "scan",
    "scan_batch",
]

load_env = _load_env

_pipeline: Pipeline | None = None


def get_pipeline(
    refresh: bool = False,
    config: PipelineConfig | None = None,
    **builder_kwargs,
) -> Pipeline:
    """进程内共享默认流水线，避免重复加载规则。

    传参或 refresh=True 时重建；无参调用复用已有实例。
    其余 kwargs 透传给 create_pipeline（tiers / rules_dir / guard / ...）。
    """
    global _pipeline
    if _pipeline is None or refresh or config is not None or builder_kwargs:
        _pipeline = create_pipeline(config=config, **builder_kwargs)
    return _pipeline


def scan(text: str, user: str = "default", policy: str | None = None) -> ScanResult:
    """扫描单条文本，返回 ScanResult。"""
    return get_pipeline().scan(text, user=user, policy_name=policy)


def scan_batch(texts: list[str], user: str = "default", policy: str | None = None) -> list[ScanResult]:
    """批量扫描。重复文本走缓存。"""
    return get_pipeline().scan_batch(texts, user=user, policy_name=policy)


class Guard:
    """带状态的门面：自带配置、策略与缓存，适合服务进程长期持有。"""

    def __init__(self, config: PipelineConfig | None = None, policy: Policy | None = None):
        policies = PolicyEngine()
        if policy is not None:
            policies.register(policy)
        self.pipeline = Pipeline(
            config=config or PipelineConfig(policy=policy.name if policy else "default"),
            policies=policies,
        )

    def scan(self, text: str, user: str = "default") -> ScanResult:
        return self.pipeline.scan(text, user=user)

    def score(self, text: str) -> float:
        return self.pipeline.scan(text).score

    def is_safe(self, text: str) -> bool:
        return not self.pipeline.scan(text).is_blocked

    def reload_rules(self) -> bool:
        return self.pipeline.reload_rules()

    def stats(self) -> dict[str, object]:
        det = self.pipeline.rule_detector
        return {
            "cache_hits": self.pipeline.guard.cache.hits,
            "cache_misses": self.pipeline.guard.cache.misses,
            "rules": det.rulebook.stats() if det and det.rulebook else {},
        }
