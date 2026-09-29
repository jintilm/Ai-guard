"""L1 规则匹配引擎。

关键：规则跑在「原文 + 所有解码变体」上；去重按 pattern_id，不按命中文本。
"""
from __future__ import annotations

import re

from prompt_ids.core.types import DETECTOR_RULE, Finding, Variant
from prompt_ids.detectors.base import Detector, DetectorContext
from prompt_ids.rules import engine as _engine
from prompt_ids.rules.loader import Rule, RuleBook

_EVIDENCE_LEN = 120
_MATCH_ERRORS = _engine.errors()


def clip(text: str, limit: int = _EVIDENCE_LEN) -> str:
    """截取证据片段，避免审计日志被超长 prompt 撑爆。"""
    flat = re.sub(r"\s+", " ", text).strip()
    if len(flat) <= limit:
        return flat
    half = limit // 2
    return f"{flat[:half]}…{flat[-half:]}"


class RuleDetector(Detector):
    layer = 1
    name = "rule"

    def __init__(
        self,
        rules: RuleBook | list[Rule],
        tiers: tuple[str, ...] = ("critical", "high", "medium"),
        enabled: bool = True,
        max_variants: int = 24,
    ):
        super().__init__(enabled=enabled)
        self.rulebook = rules if isinstance(rules, RuleBook) else None
        self.fallback_rules: list[Rule] | None = None if self.rulebook else list(rules)
        self.tiers = tuple(tiers)
        self.max_variants = max_variants

    @property
    def active_rules(self) -> list[Rule]:
        if self.rulebook is not None:
            return self.rulebook.ruleset.for_tiers(self.tiers)
        assert self.fallback_rules is not None
        return [r for r in self.fallback_rules if r.tier in self.tiers]

    def detect(self, ctx: DetectorContext) -> list[Finding]:
        rules = self.active_rules
        variants: list[Variant] = list(ctx.variants[: self.max_variants]) or [
            Variant(kind="original", text=ctx.canonical)
        ]

        findings: list[Finding] = []
        seen_rules: dict[str, int] = {}

        for rule in rules:
            for variant in variants:
                try:
                    m = rule.match(variant.text)
                except _MATCH_ERRORS:
                    continue
                if m is None:
                    continue
                if rule.id in seen_rules:
                    # 同一规则命中多个变体只记一次，按变体优先级取首次命中
                    break
                # 解码/挤压变体上的命中可信度略低
                penalty = 1.0 if variant.kind.startswith("original") else 0.95
                seen_rules[rule.id] = len(findings)
                findings.append(
                    Finding(
                        detector=DETECTOR_RULE,
                        pattern_id=rule.id,
                        category=rule.category,
                        weight=rule.weight,
                        evidence=clip(m.group(0)),
                        confidence=round(min(rule.confidence * penalty, 1.0), 4),
                        variant=variant.kind,
                        note=rule.description,
                    )
                )
                break
        return findings
