"""决策层：加权融合 + 五级风险判定 + 可解释输出。"""
from __future__ import annotations

from dataclasses import dataclass

from prompt_ids.core.types import DETECTOR_MEMORY, DETECTOR_RULE, DETECTOR_SEMANTIC, Finding, Level

# 默认权重：规则层负责可解释，启发层负责补漏，语义层负责泛化
DEFAULT_WEIGHTS: dict[str, float] = {
    "rule": 0.3,
    "heuristic": 0.2,
    "semantic": 0.5,
    "memory": 0.4,
}

# 判别层：有独立意见、能加分也能减分（与"只做加法的证据层"相对）
DISCRIMINATORS = (DETECTOR_SEMANTIC, DETECTOR_MEMORY)

DEFAULT_THRESHOLDS: dict[str, float] = {
    "low": 20.0,
    "medium": 40.0,
    "high": 60.0,
    "critical": 85.0,
}

# evidence（默认）| weighted
# 两者都能跑，论文里可以直接做成融合策略的对比实验
STRATEGIES = ("evidence", "weighted")

# 命中这些类别直接拉到 high 以上，不等加权结果
STRONG_CATEGORIES = frozenset(
    {"role_tag_escape", "instruction_override", "tool_injection", "system_prompt_extraction"}
)


@dataclass(frozen=True, slots=True)
class FusionConfig:
    weights: tuple[tuple[str, float], ...] = tuple(DEFAULT_WEIGHTS.items())
    thresholds: tuple[tuple[str, float], ...] = tuple(DEFAULT_THRESHOLDS.items())
    critical_rule_weight: float = 8.0   # 达到即短路
    critical_rule_confidence: float = 0.85
    low_guard: float = 12.0             # 低于此分数个别中危规则不计入 strong
    # 融合策略：evidence=证据制（默认），weighted=加权平均
    strategy: str = "evidence"
    abstain_below: float = 15.0         # 证据层低于此分视为弃票，不稀释其他层
    secondary_weight: float = 0.5       # 次要证据层的抬升系数
    semantic_modifier: float = 0.5      # 语义层作为判别器的调节幅度（±25%）


def _clamp(value: float) -> float:
    return min(100.0, max(0.0, value))


def fuse(subscores: dict[str, float], config: FusionConfig = FusionConfig()) -> float:
    """把各层子分融合为 0-100 总分。

    evidence（默认）：证据层取最强的一票，其余层只做有限抬升；
    语义层是独立判别器，用乘性因子调节，既可以把规则层没抓到的攻击抬上去，
    也可以把规则层的偶尔误判压下来。这样避免了加权平均「弱信号稀释强证据」
    导致 L1+L2 召回反而不如 L1 单独工作的反常现象。

    weighted：朴素的权重归一化平均，保留作为策略对照组。
    """
    if not subscores:
        return 0.0
    if config.strategy == "weighted":
        return _weighted_fuse(subscores, config)
    return _evidence_fuse(subscores, config)


def _weighted_fuse(subscores: dict[str, float], config: FusionConfig) -> float:
    weights = dict(config.weights)
    active = {k: v for k, v in subscores.items() if v > 0 and k in weights}
    if not active:
        return 0.0
    total_weight = sum(weights[k] for k in active)
    if total_weight <= 0:
        return 0.0
    return round(_clamp(sum(subscores[k] * weights[k] for k in active) / total_weight), 2)


def _evidence_fuse(subscores: dict[str, float], config: FusionConfig) -> float:
    weights = dict(config.weights)
    scores = {k: max(0.0, v) for k, v in subscores.items() if k in weights}
    if not scores:
        return 0.0

    # 判别层单独处理 —— 它们有独立意见，能加分也能减分
    discriminators = [
        scores.pop(name) for name in DISCRIMINATORS if name in scores
    ]
    if not scores:
        # 只有判别层参与时，取它们的均值作为总分
        if not discriminators:
            return 0.0
        return round(_clamp(sum(discriminators) / len(discriminators)), 2)

    votes = {k: v for k, v in scores.items() if v >= config.abstain_below}
    if votes:
        primary_key = max(votes, key=lambda k: votes[k])
        primary = votes[primary_key]
        others = [k for k in votes if k != primary_key]
        if others:
            rest = sum(subscores[k] * weights[k] for k in others) / sum(weights[k] for k in others)
        else:
            rest = 0.0
        evidence = primary + (1.0 - primary / 100.0) * config.secondary_weight * rest
    else:
        # 没有层明确表态时保留最强的一票，而不是归零丢掉低风险信号
        evidence = max(scores.values())

    if not discriminators:
        return round(_clamp(evidence), 2)

    # 多个判别层取均值；p=1 → ×1.25，p=0 → ×0.75，p=0.5 → 不变
    pooled = sum(discriminators) / len(discriminators)
    adjusted = evidence * (1.0 + (pooled / 100.0 - 0.5) * config.semantic_modifier)
    # 判别层自身也可以作为独立证据来源（规则层完全没命中时靠它兜底）
    return round(_clamp(max(adjusted, max(discriminators))), 2)


def grade(score: float, config: FusionConfig = FusionConfig()) -> Level:
    th = dict(config.thresholds)
    if score >= th["critical"]:
        return Level.CRITICAL
    if score >= th["high"]:
        return Level.HIGH
    if score >= th["medium"]:
        return Level.MEDIUM
    if score >= th["low"]:
        return Level.LOW
    return Level.SAFE


def _strong_hit(findings: list[Finding], config: FusionConfig) -> Finding | None:
    for f in findings:
        if f.detector != DETECTOR_RULE:
            continue
        if f.weight >= config.critical_rule_weight and f.confidence >= config.critical_rule_confidence:
            return f
    return None


def decide(
    findings: list[Finding],
    subscores: dict[str, float],
    config: FusionConfig = FusionConfig(),
) -> tuple[float, Level, str]:
    score = fuse(subscores, config)
    hit = _strong_hit(findings, config)
    if hit is not None:
        # 高危规则命中给地板分，避免被大量无关层分数稀释到放行区间
        score = max(score, 88.0)
    level = grade(score, config)
    return score, level, (hit.pattern_id if hit else "")


def explain(findings: list[Finding], score: float, level: Level, short_circuit: str = "") -> str:
    if not findings:
        return "未命中任何规则或启发特征，判定为安全。"
    parts: list[str] = []
    if short_circuit:
        parts.append(f"命中高危规则 {short_circuit}，触发短路升档")
    by_detector: dict[str, list[Finding]] = {}
    for f in findings:
        by_detector.setdefault(f.detector, []).append(f)
    for detector, items in by_detector.items():
        top = sorted(items, key=lambda f: -f.weight * f.confidence)[:3]
        cats = sorted({i.category for i in items})
        parts.append(
            f"{detector} 层 {len(items)} 项（{'/'.join(cats)}），"
            f"最强 {top[0].pattern_id}: {top[0].note or top[0].evidence}"
        )
    return f"综合 {score:.1f} 分 → {level.value}。依据：" + "；".join(parts)
