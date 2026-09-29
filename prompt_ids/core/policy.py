"""策略引擎：MVP 单租户，接口按多租户预留。"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from prompt_ids.core.types import Action, Level


@dataclass(frozen=True, slots=True)
class Policy:
    """动作映射 + 白名单。所有字段可配置，便于做策略对比实验。"""

    name: str = "default"
    actions: tuple[tuple[str, str], ...] = (
        ("safe", Action.PASS.value),
        ("low", Action.LOG.value),
        ("medium", Action.REVIEW.value),
        ("high", Action.SANDBOX.value),
        ("critical", Action.BLOCK.value),
    )
    # 指纹白名单：命中则直接放行（保留审计）
    allowlist: tuple[str, ...] = ()
    # 正则白名单：用于排除自家业务固定话术
    allow_patterns: tuple[str, ...] = ()
    # 是否把 medium 也升级为阻断（严格模式）
    strict: bool = False

    def action_for(self, level: Level) -> Action:
        mapping = {Level(k): Action(v) for k, v in self.actions}
        action = mapping.get(level, Action.PASS)
        if self.strict and level in (Level.MEDIUM, Level.HIGH):
            action = Action.BLOCK
        return action


# 预置策略。此前只有 default，调用方传 "strict" 会静默回退到 default，
# 安全配置形同虚设 —— 所以这里补齐常用档位。
BUILTIN_POLICIES: dict[str, Policy] = {
    "default": Policy(),
    # 严格：medium 与 high 一并阻断，适合对外开放的入口
    "strict": Policy(
        name="strict",
        actions=(
            ("safe", Action.PASS.value),
            ("low", Action.LOG.value),
            ("medium", Action.BLOCK.value),
            ("high", Action.BLOCK.value),
            ("critical", Action.BLOCK.value),
        ),
        strict=True,
    ),
    # 宽松：只阻断最高危，适合内部低风险场景，避免打扰业务
    "permissive": Policy(
        name="permissive",
        actions=(
            ("safe", Action.PASS.value),
            ("low", Action.PASS.value),
            ("medium", Action.LOG.value),
            ("high", Action.REVIEW.value),
            ("critical", Action.BLOCK.value),
        ),
    ),
    # 只观察不阻断：上线初期摸底用
    "log-only": Policy(
        name="log-only",
        actions=(
            ("safe", Action.PASS.value),
            ("low", Action.LOG.value),
            ("medium", Action.LOG.value),
            ("high", Action.LOG.value),
            ("critical", Action.LOG.value),
        ),
    ),
}


class PolicyEngine:
    def __init__(self, policies: dict[str, Policy] | None = None, default: str = "default"):
        merged = dict(BUILTIN_POLICIES)
        if policies:
            merged.update(policies)
        self._policies = merged
        if default not in self._policies:
            raise KeyError(f"默认策略 {default} 不存在")
        self.default_name = default

    def get(self, name: str | None = None) -> Policy:
        if name is None:
            return self._policies[self.default_name]
        return self._policies.get(name) or self._policies[self.default_name]

    def resolve(self, name: str | None = None) -> tuple[Policy, bool]:
        """返回 (策略, 是否回退)。未知名不再静默降级 —— 调用方应把回退暴露出来。"""
        if name is None:
            return self._policies[self.default_name], False
        policy = self._policies.get(name)
        if policy is not None:
            return policy, False
        return self._policies[self.default_name], True

    def register(self, policy: Policy) -> None:
        self._policies[policy.name] = policy

    def names(self) -> list[str]:
        return sorted(self._policies)


@dataclass(slots=True)
class Override:
    """按指纹/正则的例外，供低风险业务场景降噪。"""

    fingerprints: frozenset[str] = frozenset()
    patterns: tuple[str, ...] = field(default_factory=tuple)

    def is_allowed(self, fingerprint: str, text: str) -> bool:
        if fingerprint in self.fingerprints:
            return True
        return any(re.search(p, text) for p in self.patterns)
