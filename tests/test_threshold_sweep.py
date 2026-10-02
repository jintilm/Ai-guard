"""阈值标定脚本（scripts/threshold_sweep.py）的守护。

守护三件事，其中第三件是**已经踩过**的坑：

1. 阈值曲线的基本计数别算错（tp/fp/tn/fn 与 P/R/F1/FPR 自洽）。
2. 「三个可操作读数」必须真的由曲线推出，且要说清 F1 最优点可能不可用。
3. **`sandbox` 不算拦截** —— 初版把 sandbox 计进 block 召回，
   在公开集上把 default 策略的 block 召回从 0.1694 虚报成 0.2159（+27% 相对误差）。
   原因：sandbox 的语义是「放行 + 记审计，HTTP 200」，只有 `--block-sandbox` 才真拦。
   脚本比文档更乐观是最危险的一类偏差。
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module")
def sweep():
    spec = importlib.util.spec_from_file_location(
        "threshold_sweep", ROOT / "scripts" / "threshold_sweep.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["threshold_sweep"] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


ROWS = [
    # score, label, level —— 一条 critical 攻击、两条 high 攻击、一条 high 良性、两条 low 良性
    {"score": 88.0, "label": 1, "level": "critical", "source": "x"},
    {"score": 70.0, "label": 1, "level": "high", "source": "x"},
    {"score": 72.0, "label": 1, "level": "high", "source": "x"},
    {"score": 71.0, "label": 0, "level": "high", "source": "x"},
    {"score": 26.6, "label": 0, "level": "medium", "source": "x"},
    {"score": 21.3, "label": 0, "level": "low", "source": "x"},
]


def test_threshold_curve_counts_match_the_definition(sweep):
    curve = {row["threshold"]: row for row in sweep.sweep_threshold(ROWS, [70.0])}
    row = curve[70.0]
    # score >= 70 → 3 条攻击（88/72/70）+ 1 条良性（71）
    assert (row["tp"], row["fp"], row["fn"], row["tn"]) == (3, 1, 0, 2)
    assert row["precision"] == pytest.approx(0.75)
    assert row["recall"] == pytest.approx(1.0)
    assert row["fpr"] == pytest.approx(1 / 3, abs=1e-4)  # 报告里的值取四位小数
    assert row["blocked_share"] == pytest.approx(4 / 6, abs=1e-4)


def test_threshold_is_inclusive(sweep):
    """>= 而不是 >：分数正好等于阈值的样本必须算命中，否则读数会漂。"""
    row = sweep.sweep_threshold(ROWS, [88.0])[0]
    assert row["tp"] == 1 and row["fn"] == 2


def test_thresholds_use_the_observed_scores_not_a_made_up_grid(sweep):
    """规则层大量命中给出同一个分数 —— 人造网格（0/10/20…）会漏掉整段台阶。"""
    thresholds = sorted({r["score"] for r in ROWS})
    assert thresholds == [21.3, 26.6, 70.0, 71.0, 72.0, 88.0]


def test_sandbox_is_not_counted_as_blocked(sweep):
    """default 策略把 high → sandbox，那是放行 + 审计，不算拦截。

    ROWS 里有三条 high（两条攻击 + 一条良性），它们都落到 sandbox；
    真正被 block 的只有 critical 那一条。
    """
    impact = sweep.policy_impact(ROWS)
    default = impact["default"]
    assert default["actions"]["sandbox"] == 3, "三条 high 都应落到 sandbox"
    assert default["blocked_attack"] == 1
    assert default["block_recall"] == pytest.approx(1 / 3, abs=1e-4)
    assert default["blocked_share"] == pytest.approx(1 / 6, abs=1e-4)
    assert default["sandbox_benign"] == 1


def test_sandbox_benign_is_tracked_separately(sweep):
    rows = [dict(row) for row in ROWS]
    rows.append({"score": 75.0, "label": 0, "level": "high", "source": "x"})
    impact = sweep.policy_impact(rows)
    default = impact["default"]
    assert default["sandbox_benign"] == 2
    assert default["block_fpr"] == 0.0, "sandbox 不该被算成误拦"


def test_strict_policy_trades_false_positives_for_recall(sweep):
    impact = sweep.policy_impact(ROWS)
    assert impact["strict"]["block_recall"] > impact["default"]["block_recall"]
    assert impact["strict"]["block_fpr"] > impact["default"]["block_fpr"]


def test_log_only_never_blocks(sweep):
    impact = sweep.policy_impact(ROWS)
    assert impact["log-only"]["block_recall"] == 0.0
    assert impact["log-only"]["blocked_share"] == 0.0


def test_knee_picks_the_operating_point_under_the_fpr_budget(sweep):
    curve = sweep.sweep_threshold(ROWS, sorted({r["score"] for r in ROWS}))
    knee = sweep.pick_knee(curve)
    # 零误报点 = T 72（把唯一的 high 良性排除掉）
    assert knee["max_recall_at_zero_fp"]["threshold"] == 72.0
    assert knee["max_recall_at_zero_fp"]["fp"] == 0
    assert knee["fpr_at_budget_0_01"]["fpr"] <= 0.01


def test_knee_reports_nothing_rather_than_inventing_a_point(sweep):
    """没有任何**可行**阈值时返回空 dict，不许返回一个看起来合规却无用武之地的点。

    构造：攻击分 10、良性分 50 —— 任何能抓到那条攻击的阈值都会一起抓走良性（FPR=1）。
    而「什么都不拦」（T=51）虽然 FPR=0，却抓不到任何攻击：这种平凡解必须被排除，
    否则「FPR ≤ 0.01 下召回最高」的答案是「召回 0 的点」，约束形同虚设。
    """
    rows = [
        {"score": 10.0, "label": 1, "level": "high", "source": "x"},
        {"score": 50.0, "label": 0, "level": "high", "source": "x"},
    ]
    curve = sweep.sweep_threshold(rows, [0.0, 10.0, 50.0, 51.0])
    knee = sweep.pick_knee(curve)
    assert knee["fpr_at_budget_0_01"] == {}
    assert knee["max_recall_at_zero_fp"] == {}
    # 退化点本身仍在曲线上（T=51 什么都不拦，误报 0 但召回 0），只是不会被当成推荐值
    flag_nothing = [r for r in curve if r["tp"] == 0 and r["fp"] == 0]
    assert flag_nothing and flag_nothing[0]["threshold"] == 51.0
