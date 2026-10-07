"""并发下「本次扫描的判决」不得串到别的请求上（2026-10 审查发现）。

背景：`SemanticDetector.last_prediction` 与 `MemoryDetector.last_hits` 原本是
**实例字段**，而它们承担的是「detect() 的结果要递给 contribution()」这条通道。
代理 / REST 都是 `ThreadingHTTPServer`，每请求一线程，于是：

- A 线程写完 `last_prediction`（p=0.99 的攻击），B 线程（良性）覆盖它，
  A 的 `contribution()` 读到 B 的 0.0 → **攻击被放行**；
- 反向同理：良性请求继承 0.99 被 block；
- 「`ok=False` 必须弃票」这条不变量也被破坏 —— 读到别人的 `ok`。

修法是把这两个字段改成线程局部（`threading.local` + property）。
本文件用**真实的并发**钉死它：构造两个语义后端，让一个「攻击」与一个「良性」
在两个线程里交错 predict，各自读到的 contribution 必须是自己那次的。
"""
from __future__ import annotations

import threading

from prompt_ids.detectors.semantic.base import Prediction, SemanticBackend
from prompt_ids.detectors.semantic.detector import SemanticDetector


class _FlakyBackend(SemanticBackend):
    """按文本内容返回固定概率的假后端；用 barrier 强制两个线程交错。"""

    name = "flaky"

    def __init__(self, barrier: threading.Barrier):
        self.barrier = barrier
        self.calls = 0

    def is_available(self) -> bool:
        return True

    def warmup(self) -> None:
        pass

    def predict(self, text: str):
        self.calls += 1
        # 两个线程都到这里之后才继续，确保 predict 的写与 contribution 的读交错
        self.barrier.wait(timeout=10)
        return Prediction(0.99, "attack-like", self.name, 1.0) if "ATTACK" in text \
            else Prediction(0.0, "benign-like", self.name, 1.0)

    def default_timeout_s(self) -> float:
        return 5.0

    def stats(self) -> dict:
        return {"calls": self.calls}


def test_contribution_is_scoped_to_the_current_scan():
    """两个线程交错跑，contribution() 必须各读各的预测。

    编排是关键：**两个线程都写完**之后才允许读（第二个 barrier）。
    实例字段的实现下，后写的那个值会被两个线程同时读到 ⇒
    必有一个断言失败（不是「可能失败」）。
    """
    written = threading.Barrier(2)
    detector = SemanticDetector(enabled=True, backend=_FlakyBackend(threading.Barrier(1)),
                                timeout_s=0.0)   # timeout=0 → 同步执行，便于编排

    results: dict[str, float | None] = {}
    errors: list[str] = []

    def work(tag: str, text: str) -> None:
        try:
            detector.predict(text)     # 写 last_prediction
            written.wait(timeout=10)    # 两个线程都写完
            results[tag] = detector.contribution()
        except Exception as exc:
            errors.append(f"{tag}: {type(exc).__name__}: {exc}")

    threads = [
        threading.Thread(target=work, args=("attack", "ATTACK payload")),
        threading.Thread(target=work, args=("benign", "hello, write me a poem")),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=15)

    assert not errors, errors
    assert results["attack"] == 99.0, "攻击线程读到的应是 0.99 → 99.0"
    assert results["benign"] == 0.0, "良性线程读到的应是 0.0"


def test_last_prediction_is_invisible_from_another_thread():
    detector = SemanticDetector(enabled=True, backend=_FlakyBackend(threading.Barrier(1)),
                                timeout_s=0.0)
    detector.last_prediction = Prediction(0.9, "x", "flaky", 1.0)
    seen: list[object] = []
    thread = threading.Thread(target=lambda: seen.append(detector.last_prediction))
    thread.start()
    thread.join(timeout=10)
    assert seen == [None], "别的线程读到了本线程的预测 —— 判定会张冠李戴"


def test_failed_call_still_abstains_after_the_change():
    """`ok=False` → contribution() 必须返回 None（弃票），不能变成 0.0。"""

    class _FailBackend(SemanticBackend):
        name = "failing"

        def is_available(self) -> bool:
            return True

        def warmup(self) -> None:
            pass

        def predict(self, text: str):
            return Prediction(0.0, "boom", self.name, 1.0, ok=False)

        def default_timeout_s(self) -> float:
            return 5.0

    detector = SemanticDetector(enabled=True, backend=_FailBackend(), timeout_s=0.0)
    detector.detect(_ctx("任意文本"))
    assert detector.contribution() is None


def _ctx(text: str):
    from prompt_ids.core.types import Variant
    from prompt_ids.detectors.base import DetectorContext

    return DetectorContext(raw=text, canonical=text,
                           variants=[Variant("original", text)])


def test_executor_pool_is_not_a_single_worker_queue():
    """L3 原来 max_workers=1：所有请求排队，而超时并不取消已提交的任务。"""
    detector = SemanticDetector(enabled=True, backend=_FlakyBackend(threading.Barrier(1)),
                                timeout_s=1.0)
    assert detector._max_workers >= 2, "单 worker 池等于把代理的 L3 并发压成 1"
    # 懒初始化在并发下只能建一个池
    pools = []

    def grab() -> None:
        detector._submit(lambda: None)
        pools.append(detector._executor)

    threads = [threading.Thread(target=grab) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)
    assert len({id(p) for p in pools}) == 1, "并发首访建了多个线程池，其中一个会泄漏"
