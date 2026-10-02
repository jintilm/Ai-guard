"""审计日志查询与分析。

读取统一事件模型（AuditEvent）。代理、CLI、API、pipeline 写入的是同一套字段，
代理特有信息（decision/status/client/...）在 extra 里，因此**同一份报表代码
可以直接分析任一入口产生的日志**。

读取器对字段缺失保持容错：历史上代理写过旧格式（顶层 decision 之类），
这类行仍能被读进来而不报错。
"""
from __future__ import annotations

import json
import time
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Sequence

from prompt_ids.eval.metrics import markdown_table
from prompt_ids.audit.events import (
    KIND_LEAK,
    LEGACY_OUTBOUND_DECISIONS,
    OUTBOUND_NONE,
    OUTBOUND_REDACTED,
    OUTBOUND_REJECTED,
    OUTBOUND_REPLACED,
    OUTBOUND_WARNED,
    REVIEW_LEVELS,
    AuditEvent,
)

#: 「算拦截」的动作集合。**不含 sandbox** ——
#: 代理对 sandbox 是**放行 + 记审计**（HTTP 200，见 proxy/server.py 的 decide()），
#: 只有 `--block-sandbox` 才真拦。把 sandbox 计进来会让「阻断数」虚高，
#: 而且与 `scripts/threshold_sweep.py` 的口径（已按 sandbox 不算拦截修正）自相矛盾。
BLOCK_ACTIONS = frozenset({"block"})
#: 放行但仍被标记为「需要关注」的动作，报表里单独记一笔而不是混进拦截数。
NOTICE_ACTIONS = frozenset({"sandbox", "review"})


def review_verdict(event: AuditEvent) -> str:
    """复核事件的结论：attack / false_positive / 空（非复核事件）。"""
    if event.kind != "review":
        return ""
    return str((event.extra or {}).get("verdict", ""))


def review_stats(events: Iterable[AuditEvent]) -> dict:
    """复核闭环的运营指标。

    值得单独看的是 `confirmed_rate`：人工复核里「确实误杀」的比例。
    它直接对应 Lakera / Calypso 那类产品强调的 *over-defense* 指标 ——
    系统自己报的 FPR 只统计 high/critical，而人工复核会额外捞出
    「停在 medium、需要人看一眼」的那部分，那才是真正伤用户的地方。
    """
    attacks = false_positives = 0
    absorbed = 0
    for event in events:
        verdict = review_verdict(event)
        if verdict == "attack":
            attacks += 1
        elif verdict == "false_positive":
            false_positives += 1
        if (event.extra or {}).get("memory_absorbed"):
            absorbed += 1
    total = attacks + false_positives
    return {
        "reviews": total,
        "confirmed_attack": attacks,
        "false_positive": false_positives,
        "memory_absorbed": absorbed,
        # 分母只有人工复核过的样本，不是全量流量，所以读作「复核样本里的误杀占比」
        "false_positive_rate_on_reviewed": round(false_positives / total, 4) if total else 0.0,
    }


def rule_ledger(events: Iterable[AuditEvent]) -> dict[str, dict[str, int]]:
    """每条规则在人工复核里的表现：判对多少次、误报多少次。

    这是「反哺规则」的原料。注意口径：
    - **分母是人工复核过的样本**，不是全量流量。所以这里的「误报率」只反映
      「被人工看到的那些误报」，规则在没进队列的样本上什么表现，这里看不到。
    - 一条复核事件可能同时归因多条规则（所有命中的都记），所以各行加起来
      会大于复核总数 —— 这是有意的：一条误报里 PV-C001 和 PV-C003 都有责任。
    - **按指纹去重**：同一条文本重复复核只计一次。不去重的话，
      「把同一篇文档复核 5 次」就能凭空造出一个 100% 误报率的嫌疑规则 ——
      而这个榜是要拿去指导改规则的，不能让人为刷分。
    """
    ledger: dict[str, dict[str, int]] = {}
    seen: set[tuple[str, str]] = set()
    for event in events:
        verdict = review_verdict(event)
        if not verdict:
            continue
        # patterns 缺失的老事件退回 top_pattern，保证账不断
        names = list(getattr(event, "patterns", ()) or ())
        if not names and event.top_pattern:
            names = [event.top_pattern]
        key_base = event.fp or f"ts:{event.ts:.3f}"
        for name in names:
            marker = (name, key_base)
            if marker in seen:
                continue
            seen.add(marker)
            row = ledger.setdefault(name, {"attack": 0, "false_positive": 0, "total": 0})
            row[verdict] += 1
            row["total"] += 1
    return ledger


def rule_suspects(ledger: dict[str, dict[str, int]], *, min_reviews: int = 3,
                  min_fp_rate: float = 0.8) -> list[dict[str, Any]]:
    """误报嫌疑榜：被人工反复判为误报、却几乎没被确认过的规则。

    **只出建议，不自动改规则。** 理由不是保守，是这套数据根本不够自动决策：
    - 分母是「进过复核队列的样本」，偏向那些已经触发的规则，冷门规则天然样本少；
    - 3 次误报不能证明规则有问题，只能证明有几条样本该改；
    - 自动降权会让「可解释」这个规则层的核心优势当场消失，而且攻击者只要
      知道哪条规则被降权就能专门打它 —— 这是安全上的净损失。
    所以产出的是「带证据的候选」，动作由人做，做完用同样的脚本复跑看数字动没动。
    """
    out: list[dict[str, Any]] = []
    for name, row in ledger.items():
        total = row.get("total", 0)
        fp = row.get("false_positive", 0)
        if total < min_reviews or not fp:
            continue
        fp_rate = fp / total
        if fp_rate < min_fp_rate:
            continue
        out.append({
            "pattern_id": name,
            "total": total,
            "false_positive": fp,
            "attack": row.get("attack", 0),
            "fp_rate": round(fp_rate, 4),
            "reason": "人工复核里以误报为主，建议人工核查该规则（或用 review_corpus 重跑）",
        })
    return sorted(out, key=lambda x: (-x["fp_rate"], -x["total"]))


def pending_reviews(events: Sequence[AuditEvent], limit: int = 20) -> list[AuditEvent]:
    """待复核队列：等级够高、且还没有人工结论的检测事件（按时间倒序）。

    只给指纹与元信息 —— 审计层不存原文，所以队列**不是**内容列表，
    而是一份「这些指纹需要人拿原文去 `/v1/review` 定性」的工单列表。
    """
    reviewed = {e.fp for e in events if e.kind == "review" and e.fp}
    out: list[AuditEvent] = []
    for event in reversed(events):
        if event.kind != "scan" or event.level not in REVIEW_LEVELS:
            continue
        if not event.fp or event.fp in reviewed:
            continue
        out.append(event)
        if len(out) >= limit:
            break
    return out


#: 响应侧「真的做了处置」的取值。`warned` 不在其中：内容已经发出去了。
_ACTED_OUTBOUND = frozenset({OUTBOUND_REDACTED, OUTBOUND_REPLACED, OUTBOUND_REJECTED})
#: 「令牌确实露了」的取值（含只能事后告警的流式）。
_LEAKED_OUTBOUND = frozenset({OUTBOUND_REPLACED, OUTBOUND_WARNED})


def _acted(event: AuditEvent) -> bool:
    """读历史事件时也要走 outbound_of()（那里才有 legacy 值映射）。"""
    return outbound_of(event) in _ACTED_OUTBOUND


def _leaked(event: AuditEvent) -> bool:
    return event.kind == KIND_LEAK or outbound_of(event) in _LEAKED_OUTBOUND


def decision_of(event: AuditEvent) -> str:
    """统一读取「放行 / 拦截」语义。

    代理入口把放行结论写在 extra["decision"]（allow/review/sandbox/block），
    CLI / API / pipeline 没有这个字段，回退到 action。这样两套来源可以用同一段
    聚合逻辑分析，不需要调用方知道日志是哪个入口产生的。

    ⚠ 出站结论**不在**这里：它是另一个维度（`outbound_of`）。历史上曾经用
    decision="leak"/"redact_secrets"/"secret_leak" 表达，于是
    「同一个请求出现两个 decision」—— 一次请求在 by_decision 里被数成两次。
    """
    extra = event.extra or {}
    value = extra.get("decision")
    return str(value) if value else event.action


def outbound_of(event: AuditEvent) -> str:
    """出站处置：none / redacted / replaced / warned / rejected。

    旧日志里没有这个字段，而是把出站结论塞进 decision
    （leak / redact_secrets / secret_leak）—— 读的时候按 `LEGACY_OUTBOUND_DECISIONS`
    映射过去，这样历史文件与新文件能用同一段聚合逻辑。
    """
    extra = event.extra or {}
    value = extra.get("outbound")
    if value:
        return str(value)
    legacy = LEGACY_OUTBOUND_DECISIONS.get(str(extra.get("decision") or ""))
    if legacy:
        return legacy
    return OUTBOUND_NONE


def load(path: str | Path) -> list[AuditEvent]:
    file = Path(path)
    if not file.exists():
        return []
    events: list[AuditEvent] = []
    for line in file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            events.append(AuditEvent.from_dict(json.loads(line)))
        except (json.JSONDecodeError, TypeError, ValueError):
            continue
    return events


def within(events: Iterable[AuditEvent], since_s: float | None = None,
           until_s: float | None = None) -> list[AuditEvent]:
    out = []
    for event in events:
        if since_s is not None and event.ts < since_s:
            continue
        if until_s is not None and event.ts > until_s:
            continue
        out.append(event)
    return out


def last_hours(events: Iterable[AuditEvent], hours: float = 24) -> list[AuditEvent]:
    return within(events, since_s=time.time() - hours * 3600)


@dataclass(frozen=True, slots=True)
class AuditSummary:
    total: int = 0
    by_kind: dict[str, int] = None  # type: ignore[assignment]
    by_level: dict[str, int] = None  # type: ignore[assignment]
    by_action: dict[str, int] = None  # type: ignore[assignment]
    by_decision: dict[str, int] = None  # type: ignore[assignment]
    by_outbound: dict[str, int] = None  # type: ignore[assignment]
    by_source: dict[str, int] = None  # type: ignore[assignment]
    blocked: int = 0
    noticed: int = 0
    #: 响应侧**真的做了处置**（脱敏 / 替换 / 拒收）。与 `blocked` 正交：
    #: 一个请求可以被放行、而它的响应被脱敏；也可以被拦下、而响应压根没发生。
    outbound_acted: int = 0
    #: Canary 令牌确实出现在输出里（含「只能事后告警」的流式）。
    leaked: int = 0
    avg_detect_ms: float = 0.0
    p95_detect_ms: float = 0.0
    span_s: float = 0.0

    def as_dict(self) -> dict:
        return {
            "total": self.total,
            "by_kind": dict(self.by_kind or {}),
            "by_level": dict(self.by_level or {}),
            "by_action": dict(self.by_action or {}),
            "by_decision": dict(self.by_decision or {}),
            "by_outbound": dict(self.by_outbound or {}),
            "by_source": dict(self.by_source or {}),
            # 三个正交的口径，别再混成一个「阻断/泄漏」：
            #   blocked        请求被拒
            #   outbound_acted 响应侧做了处置（脱敏/替换/拒收）
            #   leaked         令牌确实露了
            # 历史日志里出站结论塞在 decision 里（leak/redact_secrets/secret_leak），
            # 那三个值在 by_decision 里仍会出现，但它们的处置在 by_outbound。
            "blocked": self.blocked,
            # 放行但被标记（sandbox / review）：不算拦截，但要看得到
            "noticed": self.noticed,
            "outbound_acted": self.outbound_acted,
            "leaked": self.leaked,
            "avg_detect_ms": round(self.avg_detect_ms, 2),
            "p95_detect_ms": round(self.p95_detect_ms, 2),
            "span_s": round(self.span_s, 1),
        }


def _tally(events: Sequence[AuditEvent], key) -> dict[str, int]:
    acc: Counter = Counter()
    for event in events:
        value = key(event)
        if value:
            acc[value] += 1
    return dict(sorted(acc.items(), key=lambda kv: -kv[1]))


def summarize(events: Sequence[AuditEvent]) -> AuditSummary:
    if not events:
        return AuditSummary()
    from prompt_ids.eval.metrics import percentile

    durations = [e.detect_ms for e in events if e.detect_ms > 0]
    timestamps = [e.ts for e in events if e.ts > 0]
    return AuditSummary(
        total=len(events),
        by_kind=_tally(events, lambda e: e.kind),
        by_level=_tally(events, lambda e: e.level),
        by_action=_tally(events, lambda e: e.action),
        by_decision=_tally(events, decision_of),
        by_outbound=_tally(events, outbound_of),
        by_source=_tally(events, lambda e: e.source),
        # `blocked` 只认**请求处置**。此前 `or e.kind == "leak"` 把「输出里
        # 出现了 Canary 令牌」也算成拦截 —— 那是响应侧的事。混在一起的直接后果：
        # 报表写「阻断/泄漏 N」，而代理日志里真正被拒的只有其中一部分，
        # 读的人无法知道差值是「放行了」还是「已处置但没拦」。
        blocked=sum(1 for e in events if decision_of(e) in BLOCK_ACTIONS),
        noticed=sum(1 for e in events if decision_of(e) in NOTICE_ACTIONS),
        # 用 outbound_of() 而不是直接读 extra：历史日志的出站结论在 decision 里
        outbound_acted=sum(1 for e in events if _acted(e)),
        leaked=sum(1 for e in events if _leaked(e)),
        avg_detect_ms=sum(durations) / len(durations) if durations else 0.0,
        p95_detect_ms=percentile(durations, 0.95) if durations else 0.0,
        span_s=(max(timestamps) - min(timestamps)) if len(timestamps) > 1 else 0.0,
    )


def top_patterns(events: Sequence[AuditEvent], limit: int = 10) -> list[tuple[str, int]]:
    acc: Counter = Counter()
    for event in events:
        if event.patterns:
            # 每条事件的所有命中规则各计一次
            for pattern in event.patterns:
                acc[pattern] += 1
        elif event.top_pattern:
            acc[event.top_pattern] += 1
    return acc.most_common(limit)


def render_report(events: Sequence[AuditEvent], title: str = "审计摘要") -> str:
    summary = summarize(events)
    if not summary.total:
        return f"## {title}\n\n（无记录）"

    lines = [f"## {title}", ""]
    # 三个口径分开写：混成「阻断/泄漏 N」时，读的人无法知道差值是
    # 「放行了」还是「已处置但没拦」—— 这正是本项要修的东西。
    lines.append(
        f"- 事件总数 **{summary.total}** ｜ 请求被拦 **{summary.blocked}**"
        f" ｜ 放行但标记（sandbox/review）**{summary.noticed}**"
        f" ｜ 响应侧已处置 **{summary.outbound_acted}**"
        f" ｜ 令牌泄漏 **{summary.leaked}**"
    )
    lines.append("  （三者正交：响应被脱敏/替换的请求**不在**「请求被拦」里；"
                 "流式只能事后告警的泄漏**不在**「响应侧已处置」里。）")
    lines.append(f"- 平均检测耗时 {summary.avg_detect_ms:.2f} ms，P95 {summary.p95_detect_ms:.2f} ms")
    if summary.span_s > 0:
        lines.append(f"- 时间跨度 {summary.span_s / 3600:.1f} 小时")
    lines.append("")

    if summary.by_outbound:
        lines.append(f"- 出站处置：{summary.by_outbound}")
    if summary.by_kind:
        lines.append("按事件类型：")
        lines.append(markdown_table(
            ["类型", "次数"], [[k, v] for k, v in summary.by_kind.items()], aligns="lr"))
        lines.append("")
    if summary.by_level:
        lines.append("按风险等级：")
        lines.append(markdown_table(
            ["等级", "次数"], [[k, v] for k, v in summary.by_level.items()], aligns="lr"))
        lines.append("")
    if summary.by_decision:
        lines.append("按处置决策：")
        lines.append(markdown_table(
            ["决策", "次数"], [[k, v] for k, v in summary.by_decision.items()], aligns="lr"))
        lines.append("")
    if summary.by_source:
        lines.append("按来源：")
        lines.append(markdown_table(
            ["来源", "次数"], [[k, v] for k, v in summary.by_source.items()], aligns="lr"))
        lines.append("")

    patterns = top_patterns(events)
    if patterns:
        lines.append("命中最多的规则：")
        lines.append(markdown_table(
            ["规则", "次数"], [[p, c] for p, c in patterns], aligns="lr"))
    return "\n".join(lines)
