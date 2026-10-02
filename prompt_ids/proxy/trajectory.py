"""agent 轨迹：把「逐段判定」记下来，回答**注入从哪一条进来的**。

## 为什么不需要原文就能可视化

一开始的设想是「轨迹必然含原文，所以它是审计层刻意不存的第二个数据面」。
实测下来**不成立**：代理已经把消息切成带 `role` + `index` 的段
（`Segment`），而「哪一条被判攻击」由 **(role, index) 唯一定位** ——
应用方看得到自己发出去的请求，把 `tool#2` 对回自己的第 3 条工具结果即可。

所以本模块的轨迹是**纯索引**的：默认**不含任何原文**，因而

- 可以直接进审计事件的 `extra`，不需要第二个数据面、不需要额外配置、
  也不会把「关掉落盘」变成一个必须记得开的开关；
- 代价是看板上**看不到工具返回了什么**，只看到「第 2 条工具结果被判 critical、
  命中 PV-C021」。

⚠ 真的要看内容时不要加进这里 —— 那是 `review_corpus` 那类「显式配置才写 +
进 .gitignore」的第二个数据面，别把两件事混在一个字段里。

## 覆盖账必须跟着轨迹一起走

一次「tool#2 命中 PV-C021」和一次「预算不够、只看了每段开头就命中 PV-C021」
在只记结论时长得一模一样。所以每一步都带 `chars` / `truncated` / `sampled`，
整体再带一份 `coverage`（预算、截断段数、丢弃段数、总扫描字符）。
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

#: 单条轨迹最多记多少步。消息数由 `max_tool_segments` 与 body 上限共同限制，
#: 但代理可能被喂 32 段工具结果 —— 审计文件不该被一条请求写爆。
MAX_STEPS = 64


@dataclass(frozen=True, slots=True)
class SegmentStep:
    """一段的判定结果。**没有任何原文**（role/index 定位 + pattern_id 说明原因）。"""

    role: str
    index: int
    level: str
    action: str
    score: float
    patterns: tuple[str, ...]
    chars: int
    elapsed_ms: float = 0.0
    truncated: bool = False
    sampled: bool = False
    rules_only: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "role": self.role,
            "index": self.index,
            "level": self.level,
            "action": self.action,
            "score": round(self.score, 1),
            "patterns": list(self.patterns),
            "chars": self.chars,
            "elapsed_ms": round(self.elapsed_ms, 2),
            "truncated": self.truncated,
            "sampled": self.sampled,
            "rules_only": self.rules_only,
        }

    @property
    def label(self) -> str:
        """人类可读的定位串，如 `tool#2`。与代理错误信息里的说法一致。"""
        return f"{self.role}#{self.index}"


def build_steps(plan: list[tuple[Any, str, bool]],
                results: list[Any]) -> tuple[SegmentStep, ...]:
    """由「分段计划 + 每段结果」构造轨迹。

    ⚠ 两个列表必须**一一对应且同序** —— `scan_segments` 是按 `plan` 的顺序扫的。
    这里显式断言长度一致而不是 `zip` 静默截断：`zip` 会把「结果少了一个」
    变成「轨迹少了一步」，而少的那一步恰好可能是注入入口。
    """
    if len(plan) != len(results):
        raise ValueError(
            f"分段计划与结果数量不一致：plan={len(plan)} results={len(results)}")
    steps: list[SegmentStep] = []
    for (segment, text, sampled), result in zip(plan, results):
        latency = dict(getattr(result, "latency_ms", {}) or {})
        steps.append(SegmentStep(
            role=segment.role,
            index=segment.index,
            level=getattr(getattr(result, "level", None), "value", ""),
            action=getattr(getattr(result, "action", None), "value", ""),
            score=float(getattr(result, "score", 0.0)),
            # 只取 pattern_id：`evidence` 是命中的原文片段，绝不进轨迹
            patterns=tuple(f.pattern_id for f in (getattr(result, "findings", []) or [])),
            chars=len(text),
            elapsed_ms=float(latency.get("total", 0.0)),
            truncated=bool(getattr(segment, "truncated", False)) or bool(sampled and False),
            sampled=bool(sampled),
            rules_only=bool(getattr(segment, "rules_only", False)),
        ))
    return tuple(steps[:MAX_STEPS])


def worst_step(steps: tuple[SegmentStep, ...]) -> SegmentStep | None:
    """最严重的那一步（与 `scan_segments` 的取法一致：先比等级，再比分数）。"""
    rank = {"safe": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    if not steps:
        return None
    return max(steps, key=lambda step: (rank.get(step.level, 0), step.score))


def to_dict(steps: tuple[SegmentStep, ...], *, coverage: dict[str, Any] | None = None,
            trigger_role: str = "", trigger_index: int | None = None) -> dict[str, Any]:
    """轨迹的审计表示。**不含原文**，可以直接进 `extra`。

    顶层给一个 `entry`（`"tool#2"` 这样的定位串）而不是让读的人自己在
    steps 里找 —— 「注入从哪条进来」是最常被问的问题，别让人每次都重算一遍。
    """
    worst = worst_step(steps)
    entry = ""
    if trigger_role:
        entry = (f"{trigger_role}#{trigger_index}" if trigger_index is not None
                 else trigger_role)
    elif worst is not None and worst.level != "safe":
        entry = worst.label
    return {
        "steps": [step.to_dict() for step in steps],
        "entry": entry,
        "worst": worst.to_dict() if worst is not None else None,
        "coverage": dict(coverage or {}),
        "note": "纯索引轨迹：按 role#index 定位到请求里的那一条消息，不含原文。"
                "要看内容请走复核语料（显式配置才落盘），不要加到这里。",
    }
