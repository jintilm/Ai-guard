"""Content-free semantic execution metadata shared by runtime and observers."""
from __future__ import annotations

from dataclasses import dataclass

REASONS = {
    "disabled": ("not_enabled",),
    "skipped": ("not_reached", "caller_disabled", "short_circuit", "budget_exhausted",
                "gate", "backend_unavailable", "rate_limited", "input_rejected", "empty_input"),
    "succeeded": ("verdict",),
    "abstained": ("backend_error", "backend_unavailable", "unsupported_context", "request_override",
                  "timeout", "overloaded", "cancelled", "invalid_response", "http_error", "empty_input"),
}

REASON_ZH = {
    "not_enabled": "语义层未启用", "not_reached": "语义层未执行",
    "caller_disabled": "本次调用显式关闭语义层", "short_circuit": "高危规则短路",
    "budget_exhausted": "检测预算耗尽", "gate": "预筛门控跳过",
    "backend_unavailable": "后端不可用", "rate_limited": "请求被限流",
    "input_rejected": "输入被护栏拒绝", "empty_input": "输入为空",
    "verdict": "取得有效判决", "backend_error": "后端调用失败",
    "unsupported_context": "后端不支持任务上下文", "request_override": "请求体覆盖与上下文不兼容",
    "timeout": "调用超时", "overloaded": "语义层过载", "cancelled": "任务已取消",
    "invalid_response": "响应无有效判决", "http_error": "上游 HTTP 错误",
}


@dataclass(frozen=True, slots=True)
class SemanticExecution:
    status: str
    reason: str
    http_status: int | None = None

    def __post_init__(self):
        if not isinstance(self.status, str) or self.reason not in REASONS.get(self.status, ()):
            raise ValueError("Invalid semantic execution status/reason")
        if self.http_status is not None and (
            self.reason != "http_error" or type(self.http_status) is not int
            or not 400 <= self.http_status <= 599
        ):
            raise ValueError("Invalid semantic HTTP failure status")

    def to_dict(self) -> dict:
        return {"status": self.status, "reason": self.reason, "http_status": self.http_status}

    @classmethod
    def from_dict(cls, data: dict) -> SemanticExecution:
        return cls(data["status"], data["reason"], data.get("http_status"))

    @classmethod
    def from_prediction(cls, prediction) -> SemanticExecution:
        if prediction.ok:
            return cls("succeeded", "verdict")
        code = getattr(prediction, "failure_code", "")
        if code not in REASONS["abstained"]:
            code = "backend_error"
        status = getattr(prediction, "http_status", None) if code == "http_error" else None
        if type(status) is not int or not 400 <= status <= 599:
            status = None
        return cls("abstained", code, status)

    def summary(self) -> str:
        text = REASON_ZH[self.reason]
        return f"{text}（{self.http_status}）" if self.http_status else text
