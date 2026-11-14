"""过度防御评测集的**口径**守护（`scripts/overrefusal_check.py` + 数据构建）。

这个文件守的不是「数字对不对」，而是「这些数字能不能被引用」：

1. 集合是**纯良性**的 ⇒ 任何 recall 数字都无意义（脚本必须显式说清，不能只在心里知道）
2. **block 与 review 两个口径都要报** —— 只报 `high/critical` 就是本项目
   长期存在的那个盲区本身
3. `fp_by_action` 的各项比例必须**加起来等于 1**（手写动作字典漏一个成员就会漏统计，
   而看报告的人不会去核对：实测漏掉 `log` 时 120 条里 100 条不计入，
   pass 只剩 0.1667，看着像「误伤 83%」）
4. 数据缺失要**响亮失败**并打印构建命令，不能静默跳过
5. 报告里 `examples_fp` 带原文（公开基准语料）—— 必须显式标注，
   免得有人把报告文件当成审计文件来对待
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
DATASET = ROOT / "data" / "overrefusal.jsonl"
META = ROOT / "data" / "overrefusal_meta.json"


def _load_script():
    spec = importlib.util.spec_from_file_location(
        "overrefusal_check", ROOT / "scripts" / "overrefusal_check.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


pytestmark = pytest.mark.skipif(
    not DATASET.exists(),
    reason="需先跑 python scripts/build_overrefusal.py（需联网）")


# ---------------------------------------------------------------- 数据集
def test_dataset_is_purely_benign():
    """纯良性是这个集合的**全部价值所在**（天生 test-only），混进攻击样本即失效。"""
    rows = [json.loads(line) for line in DATASET.read_text(encoding="utf-8").splitlines()
            if line.strip()]
    assert rows, "数据集为空"
    assert {r["label"] for r in rows} == {0}, "出现 label=1：recall 会变得无意义"
    assert all(r["text"].strip() for r in rows), "存在空文本"
    assert {"text", "label", "source", "category"} <= set(rows[0])


def test_dataset_has_two_independent_sources():
    sources = {json.loads(line)["source"]
               for line in DATASET.read_text(encoding="utf-8").splitlines() if line.strip()}
    assert sources == {"orbench_hard1k", "xstest_safe"}, sources


def test_meta_records_provenance_and_the_cannot_claim():
    """来源必须可追溯（URL + sha256），且「给不了召回」这件事写在文件里。"""
    meta = json.loads(META.read_text(encoding="utf-8"))
    assert meta["samples"] > 1000
    for source in meta["sources"]:
        assert source["url"].startswith("https://huggingface.co/datasets/")
        assert len(source["sha256"]) == 64, "必须记 sha256，否则数据集变了查不出来"
        assert source["samples_kept"] > 0
        assert source["cite"], "引用纪律：必须写来源"
    assert "召回" in meta["method"]["cannot"], "「给不了召回」必须写在数据文件里"
    assert meta["method"]["side"] == "false_positive_only"


# ---------------------------------------------------------------- 口径
def test_action_rates_sum_to_one():
    """各项动作比例之和必须为 1 —— 手写动作字典漏成员是真实踩过的坑。"""
    module = _load_script()
    from collections import Counter

    from prompt_ids.core.types import Action

    # 造一个「每个枚举成员都有计数」的组合
    counter = Counter({action.value: index + 1 for index, action in enumerate(Action)})
    items = module._action_items(counter)
    assert [action.value for action, _ in items] == [a.value for a in Action], \
        "必须按枚举声明顺序列出，且不漏成员"
    assert all(count > 0 for _action, count in items)


def test_both_readings_are_reported():
    """level 口径与 action 口径都要在报告里，缺一个就等于没测全。"""
    report_path = ROOT / "reports" / "overrefusal.json"
    if not report_path.exists():
        pytest.skip("需先跑 python scripts/overrefusal_check.py")
    report = json.loads(report_path.read_text(encoding="utf-8"))
    for name, config in report["configs"].items():
        assert "fp_at_level" in config, f"{name} 缺 level 口径"
        assert set(config["fp_at_level"]) >= {"ge_medium_review_or_worse", "ge_high",
                                              "ge_critical"}
        assert "fp_by_action" in config, f"{name} 缺 action 口径"
        rates = {k: v for k, v in config["fp_by_action"].items() if k != "counts"}
        assert abs(sum(rates.values()) - 1.0) < 0.01, \
            f"{name} 的动作比例之和 {sum(rates.values())} != 1（漏统计了某个动作）"
        assert config["n"] > 0


def test_semantic_configs_report_reliability():
    """语义层弃权会让配置看起来更干净 —— 读数必须与失败率一起给。

    ⚠ 这里**必须**断言 `semantic_calls > 0` 且后端不是 null，而不是只查字段存在：
    踩过一次的坑正是「无效报告通过了只查字段的守护」—— 那份报告三个配置
    `semantic_calls=0`、后端 `null`，L3 一次没被调用，却因为字段齐全而全绿。
    """
    report_path = ROOT / "reports" / "overrefusal.json"
    if not report_path.exists():
        pytest.skip("需先跑 python scripts/overrefusal_check.py")
    report = json.loads(report_path.read_text(encoding="utf-8"))
    for name, config in report["configs"].items():
        rel = config["reliability"]
        assert "failed_share" in rel and "degraded" in rel
        if "deberta" in name and config["n"]:
            assert rel["semantic_backend"] not in ("", "null"), \
                f"{name} 的后端是 {rel['semantic_backend']!r} ⇒ L3 根本没装配，" \
                f"这份报告测的不是它声称测的东西"
            assert rel["semantic_calls"] > 0, \
                f"{name}: n={config['n']} 但 semantic_calls=0 —— 无效测量"


def test_report_survives_its_own_validity_check():
    """把 `_assert_measured` 的判据反向用一遍：磁盘上这份报告必须通过它。

    脚本写盘前会自证；这条守护保证**后来的人**换掉实现或换了报告也不会
    让一份「什么都没测」的报告继续冒充结论。
    """
    module = _load_script()
    report_path = ROOT / "reports" / "overrefusal.json"
    if not report_path.exists():
        pytest.skip("需先跑 python scripts/overrefusal_check.py")
    report = json.loads(report_path.read_text(encoding="utf-8"))
    module._assert_measured(report)      # 不满足会 SystemExit(3)


def test_report_declares_it_cannot_measure_recall():
    report_path = ROOT / "reports" / "overrefusal.json"
    if not report_path.exists():
        pytest.skip("需先跑 python scripts/overrefusal_check.py")
    method = json.loads(report_path.read_text(encoding="utf-8"))["method"]
    assert method["side"] == "false_positive_only"
    assert "召回" in method["cannot"]
    assert "sandbox" in method["sandbox_note"], \
        "必须写明 sandbox 语义（默认 policy 把 high 映射成 sandbox）"
    assert "从未" in method["rule_iteration"], "必须写明本集合没参与过规则迭代"


def test_per_category_rates_use_the_group_total_as_denominator():
    """分母必须是该类别/来源的**总样本数**。

    踩过：早先只在 `rank >= medium` 时才给 `_n` 加一，于是分母就是「被标记的
    那些」⇒ 每个有命中的类别 `ge_high` 恒等于 1.0，读起来像「该类别 100% 被
    误杀」，实际是同义反复。
    """
    report_path = ROOT / "reports" / "overrefusal.json"
    if not report_path.exists():
        pytest.skip("需先跑 python scripts/overrefusal_check.py")
    report = json.loads(report_path.read_text(encoding="utf-8"))
    for name, config in report["configs"].items():
        for group in ("per_category", "per_source"):
            for key, row in config[group].items():
                assert row["n"] > 0, f"{name}.{group}.{key} 的分母是 0"
                assert row["flagged"] <= row["n"], \
                    f"{name}.{group}.{key}: flagged({row['flagged']}) > n({row['n']})"
                rate = row["ge_medium"]        # 两个分组都有这个键
                # 1.0 只在「该组全部被标记」时才合法；否则就是分母算错了
                if rate == 1.0:
                    assert row["flagged"] == row["n"], \
                        f"{name}.{group}.{key}: ge_medium=1.0 但只标记了 " \
                        f"{row['flagged']}/{row['n']} —— 分母疑似只统计了命中样本"
    # 汇总的自洽性：各来源的 flagged 之和应等于总 flagged
    for name, config in report["configs"].items():
        sources = sum(row["flagged"] for row in config["per_source"].values())
        assert sources == sum(row["flagged"] for row in config["per_category"].values()), \
            f"{name}: 来源与类别的 flagged 总数不一致"


def test_examples_are_labelled_as_public_benchmark_text():
    """`examples_fp` 带原文（公开基准语料，排障必需）—— 报告里必须说明。"""
    report_path = ROOT / "reports" / "overrefusal.json"
    if not report_path.exists():
        pytest.skip("需先跑 python scripts/overrefusal_check.py")
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert "公开基准" in json.dumps(report, ensure_ascii=False) or \
        "examples_fp" in report["configs"]["rules_only"], "样例字段缺失"
    # 样例里必须有 source/category，否则看到误判也不知道属于哪一类
    for config in report["configs"].values():
        for example in config.get("examples_fp", []):
            assert {"text", "source", "category", "level", "score"} <= set(example)


def test_missing_dataset_fails_loudly_with_the_build_command():
    """缺数据要响亮失败并打印构建命令 —— 静默跳过等于「测过了」。"""
    module = _load_script()
    code = module.main(["--dataset", str(ROOT / "data" / "does_not_exist.jsonl"),
                        "--out", str(ROOT / "reports" / "_should_not_exist.json")])
    assert code == 2
    assert not (ROOT / "reports" / "_should_not_exist.json").exists(), \
        "缺数据时不该写出报告"
