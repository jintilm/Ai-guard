"""L3 语义判定器。

分工：`SemanticDetector` 负责调度策略（预筛门禁）、超时兜底与统计，
具体的打分交给可插拔 backend（DeBERTa / LLM 裁判 / 轻量词袋）。
"""
from __future__ import annotations

import threading
import time
from concurrent.futures import CancelledError, ThreadPoolExecutor
from dataclasses import replace
from typing import Any

from prompt_ids.core.types import DETECTOR_SEMANTIC, Finding
from prompt_ids.detectors.base import Detector, DetectorContext
from prompt_ids.detectors.semantic.base import (
    NullBackend,
    Prediction,
    SemanticBackend,
    current_deadline,
    prediction_deadline,
    remaining_timeout,
)
from prompt_ids.detectors.semantic.factory import build_backend

# fallback: 只在初判不确定的区间调用，省成本
# always:   全量调用，作为效果上限对照组
# hybrid:   初判有一点可疑就调用
# confirm:  只对初判 medium/high 复核，用于降误杀
MODES = ("fallback", "always", "hybrid", "confirm")

_EVIDENCE_LEN = 120

#: 调用失败（弃权）占比超过它就算「降级」。**唯一事实来源**：
#: 运行时 `stats()["degraded"]` 与离线 `scripts/eval_semantic.py` 的
#: reliability 账用的是同一个阈值 —— 之前脚本里写死 0.20、运行时压根没有这个判断，
#: 于是「离线会把超时组标成不可用、线上却一切正常」这类不一致无从发现。
DEGRADED_CALL_FAIL_SHARE = 0.20


class SemanticOverloaded(RuntimeError):
    """All running and queued prediction slots are occupied."""


def _coerce(raw: Any, backend_name: str) -> Prediction:
    """兼容 Predicton 对象与 (prob, rationale) 元组两种返回。"""
    if isinstance(raw, Prediction):
        return raw
    if isinstance(raw, tuple) and len(raw) >= 2:
        return Prediction(float(raw[0]), str(raw[1]), backend_name)
    raise TypeError(f"不支持的预测返回类型：{type(raw).__name__}")


class SemanticDetector(Detector):
    layer = 3
    name = "semantic"

    def __init__(
        self,
        mode: str = "fallback",
        enabled: bool = False,
        model_name: str = "",
        backend: SemanticBackend | str | None = None,
        timeout_s: float | None = None,
        backend_kwargs: dict[str, Any] | None = None,
        max_workers: int = 4,
        max_pending: int | None = None,
    ):
        super().__init__(enabled=enabled)
        if mode not in MODES:
            raise ValueError(f"未知语义层模式 {mode}，可选：{MODES}")
        if isinstance(max_workers, bool) or not isinstance(max_workers, int) or max_workers < 1:
            raise ValueError("max_workers 必须是正整数")
        if max_pending is None:
            max_pending = max_workers
        if isinstance(max_pending, bool) or not isinstance(max_pending, int) or max_pending < 0:
            raise ValueError("max_pending 必须是非负整数")
        self.mode = mode
        self.model_name = model_name
        self.backend: SemanticBackend = self._resolve_backend(
            backend, model_name, enabled, backend_kwargs or {}
        )
        self.timeout_s = self.backend.default_timeout_s if timeout_s is None else timeout_s

        self.calls = 0
        self.timeouts = 0
        self.errors = 0
        self.abstained = 0
        self.total_latency_ms = 0.0
        self.last_error: str | None = None
        # `last_prediction` 是**线程局部**的：它承担的是「本次扫描的判决要递给
        # contribution()」这条通道，而实例字段是全进程共享的 ——
        # 两个请求并发时，A 写完 last_prediction、B 覆盖它，A 的 contribution()
        # 就会读到 B 的概率：良性请求继承 0.99 被 block、攻击请求继承 0.0 被放行。
        # 「ok=False 必须弃票」那条不变量也会被跨线程破坏（读到别人的 ok）。
        self._tls = threading.local()
        self._executor: ThreadPoolExecutor | None = None
        self._executor_lock = threading.Lock()
        self._max_workers = max_workers
        # scripts/semantic_load_check.py: 16 个请求超时后旧队列仍额外执行 12 次后端调用。
        self._max_pending = max_pending
        self._capacity = max_workers + max_pending
        self._work_lock = threading.Lock()
        self._in_flight = 0
        self._running = 0
        self._closed = False
        self._backend_closed = False
        self.overloaded = 0
        self.cancelled = 0

    @property
    def last_prediction(self) -> Prediction | None:
        """**当前线程**最近一次预测。别的线程读不到 —— 这是刻意的。"""
        return getattr(self._tls, "prediction", None)

    @last_prediction.setter
    def last_prediction(self, prediction: Prediction | None) -> None:
        self._tls.prediction = prediction

    # ---------- 构造 ----------
    def _resolve_backend(
        self,
        backend: SemanticBackend | str | None,
        model_name: str,
        enabled: bool,
        backend_kwargs: dict[str, Any] | None = None,
    ) -> SemanticBackend:
        extra = dict(backend_kwargs or {})
        if isinstance(backend, SemanticBackend):
            return backend
        if backend is not None:
            return build_backend(backend, model_name=model_name, **extra)
        if not enabled:
            return NullBackend()
        return build_backend("auto", model_name=model_name, **extra)

    @property
    def effective_model_name(self) -> str:
        return self.model_name or getattr(self.backend, "model_name", "") or self.backend.name

    # ---------- 生命周期 ----------
    def warmup(self) -> None:
        if self.enabled and self.backend.is_available():
            self.backend.warmup()

    def close(self) -> None:
        with self._executor_lock:
            with self._work_lock:
                self._closed = True
            executor = self._executor
            self._executor = None
        if executor is not None:
            executor.shutdown(wait=False, cancel_futures=True)
        self._close_if_idle()

    def _close_if_idle(self) -> None:
        with self._work_lock:
            if not self._closed or self._in_flight or self._backend_closed:
                return
            self._backend_closed = True
        try:
            self.backend.close()
        except Exception as exc:  # noqa: BLE001 - shutdown must also be safe from a worker callback
            with self._work_lock:
                self.last_error = f"语义后端关闭失败：{type(exc).__name__}"

    def _completed(self, future=None, state=None) -> None:
        with self._work_lock:
            self._in_flight -= 1
            if future is not None and future.cancelled() and not state["cancelled"]:
                self.cancelled += 1
        self._close_if_idle()

    # ---------- 预测（对外入口，带超时与异常兜底） ----------
    def predict(self, text: str) -> Prediction:
        started = time.perf_counter()
        failure = ""
        try:
            raw = self._submit(lambda: self.predict_impl(text))
            prediction = _coerce(raw, self.backend.name)
        except SemanticOverloaded:
            failure = "overloaded"
            prediction = Prediction(0.0, "语义层过载，已弃票", self.backend.name, ok=False)
        except CancelledError:
            prediction = Prediction(0.0, "语义任务已取消，已弃票", self.backend.name, ok=False)
        except TimeoutError:
            failure = "timeout"
            prediction = Prediction(
                0.0, f"语义后端超时（>{self.timeout_s}s）", self.backend.name, ok=False
            )
        # 说明（抑制见下一行行尾的 noqa）：21 家提供商 + 自定义端点抛的异常类型各不相同
        # （urllib / HTTPError / JSONDecodeError / KeyError…），
        # 而**每一类都必须走同一条弃票路径**：ok=False ⇒
        # contribution() 返回 None。漏掉任何一类都会让后端故障
        # 变成整条扫描抛异常。
        except Exception as exc:  # noqa: BLE001
            failure = "error"
            prediction = Prediction(
                0.0, f"语义后端异常：{str(exc)[:200]}", self.backend.name, ok=False
            )

        prediction = prediction.clamp()
        if prediction.latency_ms <= 0:
            prediction = replace(prediction, latency_ms=(time.perf_counter() - started) * 1000)
        # 弃权计数：ok=False 意味着这一层从融合里退出（不贡献分数），
        # 连续大量弃权 = L3 实际上没在工作，必须能被 metrics 看见。
        with self._work_lock:
            self.calls += 1
            self.timeouts += int(failure == "timeout")
            self.errors += int(failure == "error")
            self.overloaded += int(failure == "overloaded")
            if not prediction.ok:
                self.abstained += 1
                self.last_error = prediction.rationale[:200]
            self.total_latency_ms += prediction.latency_ms
        self.last_prediction = prediction
        return prediction

    def predict_impl(self, text: str) -> Prediction | tuple[float, str]:
        """扩展点：默认委托 backend，想自定义就重写本方法。"""
        return self.backend.predict(text)

    def _submit(self, task):
        deadline = time.monotonic() + self.timeout_s if self.timeout_s and self.timeout_s > 0 else None
        parent = current_deadline()
        if parent is not None:
            deadline = parent if deadline is None else min(parent, deadline)
        with self._work_lock:
            if self._closed:
                raise RuntimeError("语义检测器已关闭")
            if self._in_flight >= self._capacity:
                raise SemanticOverloaded()
            self._in_flight += 1
        state = {"started": False, "cancelled": False}

        def execute():
            with self._work_lock:
                if state["cancelled"] or self._closed:
                    if not state["cancelled"]:
                        state["cancelled"] = True
                        self.cancelled += 1
                    raise CancelledError()
                state["started"] = True
                self._running += 1
            try:
                with prediction_deadline(deadline):
                    remaining_timeout()
                    value = task()
                    remaining_timeout()
                    return value
            finally:
                with self._work_lock:
                    self._running -= 1

        if deadline is None:
            try:
                return execute()
            finally:
                self._completed()
        future = None
        try:
            with self._executor_lock:
                with self._work_lock:
                    if self._closed:
                        raise RuntimeError("语义检测器已关闭")
                if self._executor is None:
                    self._executor = ThreadPoolExecutor(
                        max_workers=self._max_workers, thread_name_prefix="semantic")
                future = self._executor.submit(execute)
            future.add_done_callback(lambda completed: self._completed(completed, state))
        except BaseException:
            if future is None:
                self._completed()
            raise
        try:
            return future.result(timeout=max(0.0, deadline - time.monotonic()))
        except TimeoutError:
            # Future.cancel() leaves its work item in the executor queue. Keep the slot
            # until the worker drains it, so repeated timeouts cannot grow that queue.
            with self._work_lock:
                if not state["started"] and not state["cancelled"]:
                    state["cancelled"] = True
                    self.cancelled += 1
            raise

    # ---------- Detector 接口 ----------
    def detect(self, ctx: DetectorContext) -> list[Finding]:
        self.last_prediction = None
        if not self.enabled:
            return []
        text = (ctx.canonical or ctx.raw or "").strip()
        if not text:
            return []
        prediction = self.predict(text)
        # 低于阈值不产生 finding，但概率值仍由 last_prediction 供决策层降噪使用
        if prediction.probability <= 0.5:
            return []
        return [
            Finding(
                detector=DETECTOR_SEMANTIC,
                pattern_id="SE-001",
                category="semantic",
                weight=9.0,
                evidence=prediction.rationale[:_EVIDENCE_LEN],
                confidence=round(prediction.probability, 4),
                variant="semantic",
                note=f"[{prediction.backend}] {self.effective_model_name}",
            )
        ]

    def subscore(self, findings: list[Finding]) -> float:
        """语义层不需要堆叠衰减，直接用最高置信度映射 0-100。"""
        if not findings:
            return 0.0
        return round(min(100.0, max(f.confidence for f in findings) * 100.0), 2)

    def contribution(self) -> float | None:
        """本层对融合的贡献分。未调用过则返回 None。

        即使没产生 finding 也返回分数 —— 语义层同样能扮演"降噪"角色，
        把规则层误判的正常文本拉回安全区。

        **但"没拿到判决"不等于"确信正常"**：后端不可用 / 超时 / 网络或解析
        失败时 `ok=False`，此处必须弃票（返回 None，让该层从融合里退出），
        否则 p=0 会经乘性因子把规则层证据打到 75 折 —— 一次网络抖动就能
        凭空制造漏报，而外面完全看不出来。
        """
        if not self.enabled or self.last_prediction is None:
            return None
        if not self.last_prediction.ok:
            return None
        return round(self.last_prediction.probability * 100.0, 2)

    def should_invoke(self, preliminary_score: float, level: str) -> bool:
        """预筛门禁：正则层 0.5ms，语义层 50-200ms，这道门省掉约 80% 调用。"""
        if not self.enabled or not self.backend.is_available():
            return False
        if self.mode == "always":
            return True
        if self.mode == "confirm":
            return level in ("medium", "high")
        if self.mode == "hybrid":
            return preliminary_score >= 10.0
        return 20.0 <= preliminary_score <= 70.0

    def stats(self) -> dict[str, Any]:
        info = {
            "backend": self.backend.name,
            "model": self.effective_model_name,
            "mode": self.mode,
            "available": self.backend.is_available(),
            "timeout_s": self.timeout_s,
            "input_sampling": getattr(self.backend, "input_sampling", None),
            # 弃权计数。**后端自己返回 ok=False 时 timeouts/errors 都是 0** ——
            # 而「网关 401/503」「推理模型 content 为空」这些恰恰走这条路。
            # 缺了它，一次死网关就是 L3 彻底静默失效：每次调用都弃票，
            # 分数回到只有规则层，看板上一切正常（`ablation.json` 那次
            # 87.2% 超时把召回压到 0.33 的教训，同一个坑在运行时也会踩）。
        }
        with self._work_lock:
            info.update({
                "calls": self.calls, "timeouts": self.timeouts, "errors": self.errors,
                "abstained": self.abstained, "overloaded": self.overloaded,
                "cancelled": self.cancelled, "in_flight": self._in_flight,
                "running": self._running, "queued": self._in_flight - self._running,
                "capacity": self._capacity, "max_workers": self._max_workers,
                "max_pending": self._max_pending, "closed": self._closed,
                "failed_share": round(self.abstained / self.calls, 4) if self.calls else 0.0,
                "degraded": self.calls > 0 and self.abstained / self.calls > DEGRADED_CALL_FAIL_SHARE,
                "avg_latency_ms": round(self.total_latency_ms / self.calls, 2) if self.calls else 0.0,
                "last_error": self.last_error,
            })
        return info
