"""agent 面基准的守护测试。

这个基准的作用是「钉住一个不好看但真实的数字」：规则层在 agent 面 block 召回 0.0000。
这种数字最容易被后来的改动悄悄改善（或悄悄恶化）而没人发现，所以：
- 数据集必须真的来自 Agent-Dojo，不能是自造的；
- 抽出来的文本不能留占位符（`_ATTACKER_IBAN` 那类坑）；
- 报告里的口径声明不能被删掉 —— 它是「这不是 Agent-Dojo 分数」这句话的唯一载体。
"""
from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
BENCH = ROOT / "data" / "agent_bench.jsonl"
META = ROOT / "data" / "agent_bench.meta.json"
REPORT = ROOT / "reports" / "agent_check.json"

pytestmark = pytest.mark.skipif(
    not BENCH.exists(),
    reason="先跑 python -X utf8 scripts/build_agent_bench.py（需要联网下载 Agent-Dojo）",
)


def _rows() -> list[dict]:
    return [json.loads(l) for l in io.open(BENCH, encoding="utf-8") if l.strip()]


def test_bench_has_both_labels_and_real_size():
    rows = _rows()
    attacks = [r for r in rows if r["label"] == 1]
    benign = [r for r in rows if r["label"] == 0]
    assert len(attacks) >= 30, f"攻击样本太少：{len(attacks)}"
    assert len(benign) >= 60, f"良性样本太少：{len(benign)}"
    assert all(r["source"].startswith("agentdojo:") for r in rows)
    assert all(r["text"].strip() for r in rows)


def test_no_unresolved_placeholders_left_in_bench():
    """`_ATTACKER_IBAN` 定义在**类体里**而不是模块顶层 —— 只扫模块级会让
    大半攻击目标留着 `{_ATTACKER_IBAN}` 字面量，基准看起来建好了其实是半成品。"""
    bad = [r for r in _rows()
           if "_ATTACKER" in r["text"] or "{_" in r["text"] or "{self." in r["text"]]
    assert not bad, f"{len(bad)} 条仍含未解析占位符：{bad[0]['text'][:80]}"


def test_bench_contains_the_two_shapes_that_matter():
    """agent 面注入与单条提示注入是两种东西，少一类这个基准就没意义。"""
    categories = {r["category"] for r in _rows()}
    assert "attacker_goal" in categories, "缺攻击目标"
    assert "user_prompt" in categories, "缺真实用户任务（良性对照）"
    assert any(c.startswith("tool_default:") for c in categories), \
        "缺 agent 环境里的正常工具输出（良性对照）"


def test_meta_records_licence_and_caveat():
    meta = json.loads(META.read_text(encoding="utf-8"))
    assert "Agent-Dojo" in meta["source"]
    assert "攻击成功率" in meta["caveat"], "口径声明必须留着：这不是 Agent-Dojo 分数"


@pytest.mark.skipif(not REPORT.exists(), reason="先跑 python -X utf8 scripts/agent_check.py")
def test_report_keeps_the_not_agentdojo_score_caveat():
    """删掉口径声明 = 让人把这组数字当成 Agent-Dojo 的成绩单。"""
    report = json.loads(REPORT.read_text(encoding="utf-8"))
    assert "攻击成功率" in report["caveat"]
    assert "不可相减" in report["caveat"]


@pytest.mark.skipif(not REPORT.exists(), reason="先跑 python -X utf8 scripts/agent_check.py")
def test_report_has_separate_rules_and_semantic_runs():
    """规则层口径的数字必须来自**真的没开 L3** 的流水线。

    第一版只建了一条带语义层的流水线，然后给四组结果分别贴「规则层」「含 L3」的标签，
    数字全是同一条流水线的 —— 标签是假的。四组必须各自独立。
    """
    runs = json.loads(REPORT.read_text(encoding="utf-8"))["runs"]
    assert {"rules_tool", "rules_no_tool", "rules_user"} <= set(runs)
    assert any(k.startswith("semantic_") for k in runs), "缺含 L3 的对照"


@pytest.mark.skipif(not REPORT.exists(), reason="先跑 python -X utf8 scripts/agent_check.py")
def test_report_records_the_system_prompt_false_positive_probe():
    """「语义层会误杀 RAG 系统提示」这条结论的唯一载体就是这个探针。

    没有它，后人看 ablation.json 里 DeBERTa 的 FPR 0.010 会以为 agent 流量上也没问题。
    """
    probe = json.loads(REPORT.read_text(encoding="utf-8")).get("rag_system_prompt_probe", {})
    assert probe.get("available"), "探针没跑成"
    by_backend = probe["by_backend"]
    assert "local" in by_backend, "至少要量本地 DeBERTa"
    flagged = sum(row["flagged"] for row in by_backend.values())
    assert flagged > 0, "探针没抓到任何误杀 —— 那结论本身也要复核"


def test_report_keeps_both_sides_of_the_role_policy_tradeoff():
    """分角色策略必须同时留**收益侧与代价侧**。

    只报「误报 0.5278 → 0.0833」而不报「system 角色注入召回 0.4468 → 0.0638」，
    就是选择性披露 —— 而代价侧恰恰是这个决定的成立条件之一。
    """
    report = json.loads(REPORT.read_text(encoding="utf-8"))
    traffic = report.get("rag_traffic") or {}
    cost = report.get("system_role_attack_cost") or {}
    for key in ("system_rules_only", "system_through_l3"):
        assert key in traffic, f"收益侧缺 {key}"
        assert key in cost, f"代价侧缺 {key}"
        assert traffic[key]["block_rate"] is not None
        assert cost[key]["recall"] is not None
    # 收益：默认设置必须比旧行为误拦少
    assert traffic["system_rules_only"]["block_rate"] < traffic["system_through_l3"]["block_rate"], \
        "分角色策略没降低良性 RAG 请求的误拦率 —— 那这个策略就不成立"
    # 代价：也必须真的变差，否则说明代价侧数字是编的
    assert cost["system_rules_only"]["recall"] < cost["system_through_l3"]["recall"], \
        "代价侧没有变差？要么数字错，要么策略没真正生效（后者更糟）"


def test_report_keys_match_proxyconfig_semantics():
    """报告里的键名必须直接对应 ProxyConfig 的 `semantic_system`，不做二次解释。

    第一版把开关叫 `policy_on`，结果 `semantic_system=policy_on` 让「策略开」
    变成了「系统提示过 L3」，打印出来正好反了 —— 而这正是会进 README 的那张表。
    """
    report = json.loads(REPORT.read_text(encoding="utf-8"))
    for section in ("rag_traffic", "system_role_attack_cost"):
        rows = report.get(section) or {}
        for key, expect in (("system_rules_only", False), ("system_through_l3", True)):
            if key in rows:
                assert rows[key]["semantic_system"] is expect, (
                    f"{section}.{key} 的 semantic_system 应为 {expect}"
                )


def test_builder_does_not_exec_third_party_source():
    """解析 Agent-Dojo 源码必须走 ast 而不是 import/exec。

    注意 `ast.literal_eval` 是安全的（只求字面量），所以正则要排除它 ——
    用朴素子串匹配会把 `literal_eval(` 一起判成违规。
    """
    import re

    source = (ROOT / "scripts" / "build_agent_bench.py").read_text(encoding="utf-8")
    assert "ast.parse" in source
    assert "import agentdojo" not in source, "不能 import 第三方包来取语料"
    for pattern in (r"\bexec\(", r"(?<!literal_)\beval\("):
        hit = re.search(pattern, source)
        assert hit is None, f"基准构建脚本里不该出现 {hit.group() if hit else pattern}"
