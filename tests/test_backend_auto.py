"""`auto` 选型与诊断输出一致性（2026-10 修「以为在用 A 其实在用 B」）。

背景：用户问「配置的 api 和 key 是否可用」，实测发现三件事：
1. `--semantic`（不加 `--semantic-backend`）走的是**本地 DeBERTa**（219ms），
   配好的云端 key 一次都没被用 —— 而用户以为在用云端。
2. `--probe` 里 `llm_judge.chosen=true` 与 `selected.backend=local_model`
   互相矛盾，两个不同含义的「auto」都叫 chosen/selected，docstring 还把
   前者说成后者 ⇒ 照着它排查会得出**相反**结论。
3. `LLMBackend.is_available()` 只看 Key 配没配，**不看网关通不通** ⇒
   云端优先之后，配了 Key 但网关挂着时 L3 会持续弃权，而运行时**没有任何
   指标**能看出这件事（`ok=False` 不计入 timeouts/errors）。

本文件把这三条钉死。
"""
from __future__ import annotations

import pytest

from prompt_ids.detectors.semantic import (
    AUTO_PREFERENCE,
    DEGRADED_CALL_FAIL_SHARE,
    build_backend,
    diagnose_llm,
    probe,
)


# ------------------------------------------------------------ 坑 1：云端优先
def test_auto_prefers_llm_when_a_key_is_configured(monkeypatch):
    """云端优先：配了 Key 就该用 LLM 裁判，而不是被本地模型静默顶替。

    理由（数字）：agent 面规则层单干召回 0.0000，L3 语义层拉到 0.4469。
    用户既然配了 Key 要付这份钱，就该默认拿到泛化更强的那一层。
    """
    monkeypatch.setenv("PROMPT_IDS_LLM_API_KEY", "sk-test-not-real")
    monkeypatch.setenv("PROMPT_IDS_LLM_BASE_URL", "https://example.invalid/v1")
    backend = build_backend("auto")
    assert backend.name == "llm_judge", (
        f"配了 Key 却选了 {backend.name} —— auto 的顺序必须是云端优先")


def test_auto_falls_back_to_local_when_no_key(monkeypatch):
    """没有 Key 时必须安静地回落到本地，而不是空转或报错。"""
    for name in ("PROMPT_IDS_LLM_API_KEY", "PROMPT_IDS_LLM_BASE_URL",
                 "PROMPT_IDS_LLM_PROVIDER", "PROMPT_IDS_LLM_MODEL"):
        monkeypatch.delenv(name, raising=False)
    backend = build_backend("auto")
    assert backend.name in {"local_model", "lightweight", "null"}, backend.name


def test_auto_preference_is_llm_first_and_documented():
    """顺序是产品决定，不是实现细节：提成常量并写明代价。"""
    import inspect

    from prompt_ids.detectors.semantic import factory

    assert AUTO_PREFERENCE[0] == "llm", AUTO_PREFERENCE
    assert set(AUTO_PREFERENCE) == {"llm", "local", "lightweight"}
    # 代价必须与顺序写在同一处：改顺序的人第一眼就会看到
    # （LLM 裁判 ≈10s/条，本地 219ms）
    source = inspect.getsource(factory)
    assert "10s" in source and "219ms" in source, "改顺序的人必须先看到代价"


def test_local_is_still_reachable_by_name(monkeypatch):
    """云端优先不能变成「没法用本地」—— 离线/省钱场景要能显式回退。"""
    monkeypatch.setenv("PROMPT_IDS_LLM_API_KEY", "sk-test-not-real")
    monkeypatch.setenv("PROMPT_IDS_LLM_BASE_URL", "https://example.invalid/v1")
    assert build_backend("local").name == "local_model"


# ------------------------------------------------------------ 坑 2：诊断自洽
def test_probe_has_exactly_one_authoritative_answer():
    """`effective` 是唯一回答「不加 --semantic-backend 时实际跑哪个」的键。"""
    report = probe()
    assert "effective" in report, "缺少权威答案，调用方只能自己猜"
    assert report["effective"]["backend"] == report["selected"]["backend"], \
        "effective 与 selected 说法不一致"
    assert report["effective"]["preference"] == list(AUTO_PREFERENCE)
    assert "override_hint" in report["effective"]


def test_probe_loaded_false_is_explained():
    """探针进程不加载模型 ⇒ loaded 恒为 false。不解释就会被读成「模型不在」。"""
    report = probe()
    assert "note" in report["local"], "local 的 loaded=false 必须有说明"
    assert "未加载模型" in report["local"]["note"]


def test_llm_auto_pick_is_not_mislabelled_as_the_effective_one():
    """`llm_auto_pick` 回答的是「若走 LLM 会选哪家」，不能被当成实际生效的后端。

    旧字段名 `chosen` 就是这么被误读的：probe 里 llm_judge.chosen=true，
    而实际生效的是 local_model。
    """
    report = diagnose_llm()
    assert report, "没有任何提供商条目"
    for name, info in report.items():
        assert "chosen" not in info, f"{name} 还在用含义过载的旧字段 chosen"
        assert "llm_auto_pick" in info, f"{name} 缺 llm_auto_pick"
    picked = [n for n, i in report.items() if i["llm_auto_pick"]]
    assert len(picked) <= 1, f"llm_auto_pick 标了多家：{picked}"


def test_probe_report_does_not_claim_a_provider_is_in_use():
    """整个 probe 里不得再出现「某家提供商正在被使用」这种说法。

    因为 auto 现在云端优先，实际选中的**是后端**（llm_judge）而不是某家提供商；
    说「custom 被选中」会让人以为 key 一定被用上了。
    """
    import json

    blob = json.dumps(probe(), ensure_ascii=False)
    assert '"chosen"' not in blob, "旧的 chosen 字段还在输出里"


# ------------------------------------------------------------ 坑 3：降级可见
def test_abstained_calls_are_counted_and_flagged():
    """后端自己返回 ok=False 时 timeouts/errors 都是 0，必须单独计数。

    这是云端优先最危险的形态：配了 Key 但网关挂着 ⇒ 每次调用都弃权 ⇒
    L3 静默失效，而分数看起来仍然「正常」（只是回到规则层）。
    """
    from prompt_ids.detectors.semantic.base import Prediction, SemanticBackend
    from prompt_ids.detectors.semantic.detector import SemanticDetector

    class DeadGateway(SemanticBackend):
        name = "llm_judge"
        provider = "custom"
        default_timeout_s = 5.0        # 类属性，不是方法

        def is_available(self) -> bool:
            return True

        def predict(self, text: str) -> Prediction:
            # 网关 503 的真实形态：后端内部失败，不是抛异常
            return Prediction(0.0, "LLM 裁判调用失败：503", self.name, 12.0, ok=False)

    det = SemanticDetector(enabled=True, backend=DeadGateway(), mode="always")
    for _ in range(6):
        assert det.predict("随便一条").ok is False
    stats = det.stats()
    assert stats["calls"] == 6
    assert stats["timeouts"] == 0 and stats["errors"] == 0, \
        "这条路径不该记成超时/异常，正是它此前不可见的原因"
    assert stats["abstained"] == 6, f"弃权没被计数：{stats}"
    assert stats["failed_share"] == 1.0
    assert stats["degraded"] is True, "全灭还不标降级 = 静默失效"


def test_healthy_backend_is_not_flagged_degraded():
    from prompt_ids.detectors.semantic.base import Prediction, SemanticBackend
    from prompt_ids.detectors.semantic.detector import SemanticDetector

    class Fine(SemanticBackend):
        name = "llm_judge"
        provider = "custom"
        default_timeout_s = 5.0

        def is_available(self) -> bool:
            return True

        def predict(self, text: str) -> Prediction:
            return Prediction(0.1, "正常", self.name, 8.0)

    det = SemanticDetector(enabled=True, backend=Fine(), mode="always")
    for _ in range(5):
        det.predict("普通问题")
    stats = det.stats()
    assert stats["abstained"] == 0
    assert stats["degraded"] is False
    assert stats["failed_share"] == 0.0


def test_degraded_threshold_is_shared_with_the_offline_report():
    """运行时与离线评测必须用同一个阈值，否则两边口径会漂。

    之前 `scripts/eval_semantic.py` 里写死 0.20，运行时压根没有 degraded 判断 ——
    于是「离线把超时组标成不可用、线上却一切正常」这类不一致谁也发现不了。
    """
    import pathlib

    from prompt_ids.detectors.semantic import detector as detector_mod

    assert DEGRADED_CALL_FAIL_SHARE == 0.20
    script = (pathlib.Path(__file__).resolve().parents[1] /
              "scripts" / "eval_semantic.py").read_text(encoding="utf-8")
    assert "= 0.20" not in script, "脚本里又抄了一份阈值"
    assert detector_mod.DEGRADED_CALL_FAIL_SHARE == 0.20


def test_metrics_expose_the_effective_backend_and_guard_state():
    """/v1/metrics 必须能回答「现在跑的哪个后端」「降级了吗」「限流挡了多少」。"""
    from prompt_ids.api.app import ApiContext, handle_metrics
    from prompt_ids.core.pipeline import Pipeline, PipelineConfig

    pipeline = Pipeline(config=PipelineConfig())
    ctx = ApiContext(pipeline=pipeline)
    try:
        _status, body = handle_metrics(ctx, None, {})
        assert "guard" in body, "限流/缓存状态没有出口"
        assert "cache" in body["guard"] and "rate_limited" in body["guard"]
        assert "semantic" in body and "info" in body["semantic"]
        assert "backend" in body["semantic"]["info"], "看不出实际用的哪个后端"
    finally:
        pipeline.close()
