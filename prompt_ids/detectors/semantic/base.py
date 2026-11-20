"""语义后端抽象。

三种后端（本地模型 / LLM 裁判 / 轻量词袋）共用这一个接口，
缺失依赖时统一降级到 NullBackend，保证流水线永远有后端可用、绝不因为
模型装不上而把主链路搞崩。
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, replace
from time import monotonic
from typing import Any

from prompt_ids.core.context import ScanContext
from prompt_ids.core.types import TextCoverage

_DEADLINE: ContextVar[float | None] = ContextVar("semantic_deadline", default=None)


class PredictionTimeout(TimeoutError):
    """The complete prediction budget, including retries and queueing, has expired."""


def current_deadline() -> float | None:
    return _DEADLINE.get()


@contextmanager
def prediction_deadline(deadline: float | None):
    parent = current_deadline()
    if parent is not None:
        deadline = parent if deadline is None else min(parent, deadline)
    token = _DEADLINE.set(deadline)
    try:
        yield
    finally:
        _DEADLINE.reset(token)


def remaining_timeout(maximum: float | None = None) -> float | None:
    deadline = current_deadline()
    if deadline is None:
        return maximum
    remaining = deadline - monotonic()
    if remaining <= 0:
        raise PredictionTimeout("语义预测总时间预算已耗尽")
    return min(maximum, remaining) if maximum and maximum > 0 else remaining


@dataclass(frozen=True, slots=True)
class Prediction:
    """语义判定的统一返回。"""

    probability: float  # 注入概率 0-1
    rationale: str
    backend: str
    latency_ms: float = 0.0
    #: False = **没拿到可用判决**（后端不可用 / 超时 / 网络或解析失败）。
    #: 这类预测**不携带任何关于文本的信息**，因此不能当"确信正常"用：
    #: 判别层的 contribution() 见到 ok=False 必须弃票，否则一次网络抖动
    #: 会把规则层证据打 75 折（p=0 → 乘性因子 0.75），凭空制造漏报。
    ok: bool = True
    coverage: TextCoverage | None = None
    context_used: bool = False
    failure_code: str = ""
    http_status: int | None = None

    def clamp(self) -> Prediction:
        p = min(1.0, max(0.0, self.probability))
        if p == self.probability:
            return self
        return replace(self, probability=p)


class SemanticBackend(ABC):
    name: str = "abstract"
    requires_network: bool = False
    default_timeout_s: float = 5.0
    supports_context: bool = False

    @abstractmethod
    def predict(self, text: str) -> Prediction:
        """对单条文本给出注入概率与依据。实现必须自行吞掉可预期的异常。"""

    def predict_context(self, text: str, context: ScanContext) -> Prediction:
        """Abstain explicitly when the selected backend cannot use task context."""
        return Prediction(0.0, "语义后端不支持任务上下文，已弃票", self.name, ok=False,
                          failure_code="unsupported_context")

    def is_available(self) -> bool:
        """依赖是否齐备。不等于模型已经下载。"""
        return True

    def warmup(self) -> None:
        """预加载模型权重，避免首条请求的冷启动延迟被计入指标。"""

    def close(self) -> None:
        """释放显存/连接。"""

    def info(self) -> dict[str, Any]:
        return {
            "backend": self.name,
            "available": self.is_available(),
            "requires_network": self.requires_network,
            "default_timeout_s": self.default_timeout_s,
        }

    def __repr__(self) -> str:  # pragma: no cover - 调试辅助
        return f"<{self.name} available={self.is_available()}>"


class NullBackend(SemanticBackend):
    """显式空实现。语义层关闭或未装任何后端时使用。"""

    name = "null"

    def predict(self, text: str) -> Prediction:
        return Prediction(0.0, "语义后端不可用，已跳过", self.name, ok=False,
                          failure_code="backend_unavailable")

    def is_available(self) -> bool:
        return False
