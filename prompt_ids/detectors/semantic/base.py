"""语义后端抽象。

三种后端（本地模型 / LLM 裁判 / 轻量词袋）共用这一个接口，
缺失依赖时统一降级到 NullBackend，保证流水线永远有后端可用、绝不因为
模型装不上而把主链路搞崩。
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any


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

    def clamp(self) -> "Prediction":
        p = min(1.0, max(0.0, self.probability))
        if p == self.probability:
            return self
        return Prediction(p, self.rationale, self.backend, self.latency_ms, self.ok)


class SemanticBackend(ABC):
    name: str = "abstract"
    requires_network: bool = False
    default_timeout_s: float = 5.0

    @abstractmethod
    def predict(self, text: str) -> Prediction:
        """对单条文本给出注入概率与依据。实现必须自行吞掉可预期的异常。"""

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
        return Prediction(0.0, "语义后端不可用，已跳过", self.name, ok=False)

    def is_available(self) -> bool:
        return False
