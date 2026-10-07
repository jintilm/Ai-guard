import pytest

from prompt_ids.core.policy import Policy, PolicyEngine
from prompt_ids.core.types import DETECTOR_RULE, Action, Finding, Level
from prompt_ids.core.verdict import FusionConfig, decide, explain, fuse, grade


def _finding(pid: str, weight: float, confidence: float = 0.9, detector: str = DETECTOR_RULE):
    return Finding(
        detector=detector,
        pattern_id=pid,
        category="instruction_override",
        weight=weight,
        evidence="test",
        confidence=confidence,
    )


def test_fuse_all_layers_silent_falls_back_to_strongest():
    # 全部低于弃票线时保留最强的一票，而不是归零
    assert fuse({"rule": 8.0, "heuristic": 5.0}) == pytest.approx(8.0, abs=0.01)


def test_fuse_zero_subscores():
    assert fuse({}) == 0.0
    assert fuse({"rule": 0.0, "heuristic": 0.0}) == 0.0


def test_weighted_strategy_is_still_available():
    cfg = FusionConfig(strategy="weighted")
    expected = (0.3 * 60 + 0.2 * 40) / (0.3 + 0.2)
    assert fuse({"rule": 60.0, "heuristic": 40.0}, cfg) == pytest.approx(expected, abs=0.01)


def test_weighted_strategy_renormalizes_when_layer_missing():
    cfg = FusionConfig(strategy="weighted")
    assert fuse({"rule": 100.0, "heuristic": 0.0}, cfg) == pytest.approx(100.0, abs=1e-6)


def test_evidence_fuse_does_not_dilute_strong_evidence():
    """回归用例：加权平均会让 rule=65 被 heur=20 拉到 60 以下，
    导致 L1+L2 的召回反而低于 L1 单干。"""
    assert fuse({"rule": 65.0, "heuristic": 20.0}) >= 65.0


def test_evidence_fuse_semantic_can_lower_rule_false_positive():
    without = fuse({"rule": 65.0})
    with_sem = fuse({"rule": 65.0, "semantic": 2.0})
    assert with_sem < without


def test_evidence_fuse_semantic_can_lift_missed_attack():
    assert fuse({"rule": 0.0, "semantic": 95.0}) >= 90.0


def test_evidence_fuse_semantic_lifts_when_rule_already_high():
    assert fuse({"rule": 65.0, "semantic": 95.0}) >= fuse({"rule": 65.0})


@pytest.mark.parametrize(
    "score,expected",
    [(0.0, Level.SAFE), (25.0, Level.LOW), (50.0, Level.MEDIUM), (70.0, Level.HIGH), (95.0, Level.CRITICAL)],
)
def test_grade_thresholds(score, expected):
    assert grade(score) is expected


def test_decide_applies_critical_floor():
    findings = [_finding("PV-C001", 9.0, 0.95)]
    score, level, short = decide(findings, {"rule": 10.0})
    assert short == "PV-C001"
    assert score >= 88.0
    assert level is Level.CRITICAL


def test_decide_no_floor_for_weak_rules():
    findings = [_finding("PV-M001", 3.0, 0.6)]
    score, level, short = decide(findings, {"rule": 10.0})
    assert short == ""
    assert level in (Level.SAFE, Level.LOW, Level.MEDIUM)


def test_policy_action_mapping():
    policy = Policy()
    assert policy.action_for(Level.SAFE) is Action.PASS
    assert policy.action_for(Level.CRITICAL) is Action.BLOCK


def test_strict_policy_blocks_medium():
    engine = PolicyEngine()
    engine.register(Policy(name="strict", strict=True))
    assert engine.get("strict").action_for(Level.MEDIUM) is Action.BLOCK
    assert engine.get("default").action_for(Level.MEDIUM) is Action.REVIEW


def test_explain_mentions_detector_and_evidence():
    text = explain([_finding("PV-C001", 9.0)], 90.0, Level.CRITICAL, "PV-C001")
    assert "PV-C001" in text
    assert "短路" in text


def test_fusion_config_custom_thresholds():
    cfg = FusionConfig(thresholds=(("low", 5.0), ("medium", 10.0), ("high", 20.0), ("critical", 30.0)))
    assert grade(25.0, cfg) is Level.HIGH
