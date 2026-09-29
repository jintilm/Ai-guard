"""代理侧审计 —— 已并入统一审计模型（兼容层）。

历史上代理有一套独立字段（AuditRecord / AuditLog），与 prompt_ids/audit 的
AuditEvent / AuditLogger 并存，两边字段不一致，下游必须写两遍聚合逻辑。
现已统一：**代理写入的就是标准 AuditEvent**（kind="proxy", source="proxy"）。

字段映射（旧 -> 新）

| 旧 AuditRecord 字段 | 新位置                                  |
|---------------------|-----------------------------------------|
| decision            | extra["decision"]（语义见 query.decision_of）|
| level/action/score  | 顶层，同名                               |
| fp                  | 顶层 fp（仍只存指纹，绝不落原文）          |
| findings            | 顶层 findings + patterns + top_pattern   |
| top_pattern         | 顶层 top_pattern                         |
| upstream_ms/status  | extra["upstream_ms"] / extra["status"]   |
| client/path/stream  | extra[...]；client 同时写入顶层 user     |
| detect_ms           | 顶层 detect_ms                           |

本模块只保留向后兼容的薄封装，新代码请直接用：

    from prompt_ids.audit import AuditLogger, event_from_proxy
"""

from __future__ import annotations

from typing import Any

from prompt_ids.audit.events import PROXY_EXTRA_FIELDS, AuditEvent, event_from_proxy
from prompt_ids.audit.logger import AuditLogger
from prompt_ids.audit.query import decision_of, summarize

#: 新名字，语义更直白
build_event = event_from_proxy

#: 保存兼容用：签名与 build_record 完全一致
build_record = event_from_proxy


class AuditLog(AuditLogger):
    """旧代理审计器的兼容包装。

    内部就是 AuditLogger（同一套 JSONL 格式、轮转与容错），
    额外保留一份内存事件列表，以便继续支持旧的 count()/summary() 查询接口。
    新代码请直接用 AuditLogger + prompt_ids.audit.query。
    """

    def __init__(self, path: str | None = None):
        super().__init__(path)
        self.records: list[AuditEvent] = []

    def write(self, event: AuditEvent) -> None:
        """兼容旧接口：写一条审计事件。"""
        self.records.append(event)
        self.log(event)

    def count(self, decision: str | None = None) -> int:
        if decision is None:
            return len(self.records)
        return sum(1 for e in self.records if decision_of(e) == decision)

    def summary(self) -> dict[str, Any]:
        if not self.records:
            return {"total": 0}
        summary = summarize(self.records)
        return {
            "total": summary.total,
            "by_decision": dict(summary.by_decision or {}),
            "by_level": dict(summary.by_level or {}),
            "avg_detect_ms": round(summary.avg_detect_ms, 2),
        }


#: 类型别名，旧的 `from prompt_ids.proxy.audit import AuditRecord` 仍可用
AuditRecord = AuditEvent


__all__ = [
    "AuditLog",
    "AuditRecord",
    "PROXY_EXTRA_FIELDS",
    "build_event",
    "build_record",
]
