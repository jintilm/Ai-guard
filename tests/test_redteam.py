"""红队生成语料的**纪律**守护（`scripts/build_redteam.py` + `redteam_check.py`）。

这份语料最容易被误用的地方不是「召回低」，而是**被当成系统能力的量度**。
所以守的重点全在「这份数字能不能被引用」：

1. **切分按 template_id，不按行** —— 同一模板的样本跨 train/test 会泄漏。
2. **label 恒为 1** —— 纯攻击集。混入良性样本会让「召回」变成别的东西。
3. **漏检种子派生出来的变体一律进 test** —— 种子本身已参与过评测。
4. **可用率必须人工标注** —— 没有标注文件时报告必须写「未标注」，
   **不许拿模型自己的判定冒充人工标注**。
5. **报告必须自证「给不了绝对值」** —— 方法学要写在文件里，而不是写在脑子里。
6. **两个口径不可混比** —— `recall`(≥medium) 与 `blocked`(≥high) 差一个数量级。
7. **每个策略的形态数有下限** —— 否则「填充策略」会掩盖形态覆盖不足
   （无槽位模板去重后只剩 1 条，分布看起来严重偏斜）。
"""
from __future__ import annotations

import importlib.util
import json
from collections import Counter, defaultdict
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
DATASET = ROOT / "data" / "redteam.jsonl"
META = ROOT / "data" / "redteam_meta.json"
REPORT = ROOT / "reports" / "redteam.json"

pytestmark = pytest.mark.skipif(
    not DATASET.exists(),
    reason="需先跑 python scripts/build_redteam.py")


def _load(name: str):
    spec = importlib.util.spec_from_file_location(
        name, ROOT / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _rows() -> list[dict]:
    return [json.loads(line) for line in DATASET.read_text(encoding="utf-8").splitlines()
            if line.strip()]


# ---------------------------------------------------------------- 数据集纪律
def test_dataset_is_purely_positive():
    """纯攻击集 —— 混入良性样本会让「召回」变成别的东西。"""
    rows = _rows()
    assert rows
    assert {r["label"] for r in rows} == {1}
    assert all(r["text"].strip() for r in rows)
    assert {"text", "label", "source", "category", "generator", "seed",
            "template_id", "split"} <= set(rows[0])


def test_no_duplicate_texts():
    """去重必须在写盘前做完 —— 否则同一形态被重复计权，分布会被放大。"""
    texts = [" ".join(r["text"].split()).casefold() for r in _rows()]
    dupes = [t for t, n in Counter(texts).items() if n > 1]
    assert not dupes, f"有 {len(dupes)} 条重复文本"


def test_split_is_by_template_not_by_row():
    """**切分必须跟着模板走。**

    同一模板 × 不同槽位填充若分到两侧，在 train 上调出来的模式会直接泄漏到 test
    —— PINT 基准踩过这个坑（`lang_i % 10 < 7` 在 6 语种时把全部良性塞进 train）。
    """
    splits: dict[str, set[str]] = defaultdict(set)
    for row in _rows():
        splits[row["template_id"]].add(row["split"])
    offenders = {tid: sorted(s) for tid, s in splits.items() if len(s) > 1}
    assert not offenders, f"这些模板的样本跨越了 train/test：{offenders}"


def test_variants_of_misses_always_land_in_test():
    """漏检种子派生出的变体**一律进 test** —— 种子已参与评测，进 train 等于用测试集调参。"""
    variants = [r for r in _rows() if r["source"] == "redteam:variant_of_miss"]
    if not variants:
        pytest.skip("本次生成未启用 --from-misses")
    assert all(r["split"] == "test" for r in variants)


def test_every_strategy_has_enough_distinct_shapes():
    """每个策略的**模板数**有下限。

    踩过：无槽位的模板去重后只剩 1 条，于是「每策略 60 条」这个参数看起来生效了，
    实际分布严重偏斜（agentic 6 条 vs task_reframe 56 条）——
    填充策略在替我掩盖形态覆盖不足。
    """
    builder = _load("build_redteam")
    thin = {name: len(templates) for name, templates in builder.STRATEGIES.items()
            if len(templates) < 6}
    assert not thin, f"这些策略的模板数不足 6（形态覆盖太薄）：{thin}"
    # 反过来也要确认：产物里每个策略都真的有样本
    sources = Counter(r["source"] for r in _rows())
    missing = [name for name in builder.STRATEGIES
               if f"redteam:{name}" not in sources]
    assert not missing, f"这些策略没有产出样本：{missing}"


def test_meta_records_generator_seed_and_the_cannot_claim():
    """生成方式与「给不了绝对值」必须写在数据文件里，而不是只在对话里说过。"""
    meta = json.loads(META.read_text(encoding="utf-8"))
    assert meta["samples"] == len(_rows())
    assert meta["labels"] == {"1（攻击）": meta["samples"], "0（良性）": 0}
    assert meta["seed"], "必须记种子，否则不可复现"
    method = meta["method"]
    assert "绝对值" in method["cannot"]
    assert "人工标注" in method["needs_human_label"]
    assert "template_id" in method["split"]
    assert "test" in method["from_misses"]


# ---------------------------------------------------------------- 评测口径
def test_report_declares_what_it_cannot_measure():
    if not REPORT.exists():
        pytest.skip("需先跑 python scripts/redteam_check.py")
    report = json.loads(REPORT.read_text(encoding="utf-8"))
    assert report["method"]["side"] == "true_positive_only"
    assert "绝对值" in report["method"]["cannot"]
    assert "不可混比" in report["method"]["two_readings"], \
        "≥medium 与 ≥high 的口径差必须写在报告里 —— 引用 agent 面那条 0.0000 时会用到"


def test_report_says_usability_is_unlabelled_when_there_are_no_labels():
    """没有人工标注时必须写「未标注」，不许拿模型判定冒充。"""
    if not REPORT.exists():
        pytest.skip("需先跑 python scripts/redteam_check.py")
    report = json.loads(REPORT.read_text(encoding="utf-8"))
    usability = report["usability"]
    labels_exist = (ROOT / "data" / "redteam_labels.jsonl").exists()
    if labels_exist:
        assert usability["status"] in ("labeled", "no_match")
    else:
        assert usability["status"] == "unlabeled"
        assert "未标注" in usability["note"]


def test_usability_helper_refuses_to_invent_a_number():
    """直接测纯函数：空标注 ⇒ status=unlabeled 且**没有** usable_share 键。"""
    checker = _load("redteam_check")
    rows = _rows()
    result = checker._usability(rows, {})
    assert result["status"] == "unlabeled"
    assert "usable_share" not in result, \
        "没有人工标注却算出了可用率 —— 那就是拿模型判定冒充人工标注"

    labels = {" ".join(rows[0]["text"].split()).casefold(): 1}
    labeled = checker._usability(rows, labels)
    assert labeled["status"] == "labeled"
    assert labeled["usable"] == 1
    assert labeled["labeled_n"] == 1
    assert labeled["unlabeled_n"] == len(rows) - 1


def test_both_thresholds_are_reported_per_group():
    """每个分组都要同时给 ≥medium 与 ≥high —— 两者差一个数量级。"""
    if not REPORT.exists():
        pytest.skip("需先跑 python scripts/redteam_check.py")
    report = json.loads(REPORT.read_text(encoding="utf-8"))
    for name, config in report["configs"].items():
        for group in ("by_strategy", "by_split"):
            for key, row in config[group].items():
                assert row["n"] > 0, f"{name}.{group}.{key} 分母为 0"
                assert 0.0 <= row["recall"] <= 1.0
                assert 0.0 <= row["blocked"] <= 1.0
                assert row["blocked"] <= row["recall"], \
                    f"{name}.{group}.{key}: blocked > recall，≥high 不可能比 ≥medium 高"


def test_report_survives_its_own_validity_check():
    """把 `_assert_measured` 反向用一遍：磁盘上这份报告必须通过它。

    同一个教训（`Pipeline(config=...)` 不读 `semantic_*`）在这里同样适用。
    """
    if not REPORT.exists():
        pytest.skip("需先跑 python scripts/redteam_check.py")
    checker = _load("redteam_check")
    checker._assert_measured(json.loads(REPORT.read_text(encoding="utf-8")))


def test_generator_is_deterministic():
    """同一 seed 必须逐字复现 —— 否则「留证据、负面结果也记档」无从谈起。"""
    builder = _load("build_redteam")
    import random

    def build() -> str:
        rng = random.Random(20261002)
        rows = []
        for name, templates in builder.STRATEGIES.items():
            for template_id, template in templates:
                rows.append(builder._build_one(name, template_id, template, rng))
        return json.dumps(rows, ensure_ascii=False, sort_keys=True)

    assert build() == build()
