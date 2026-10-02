"""审计日志查看与分析。

    python -m prompt_ids.audit summary logs/audit.jsonl
    python -m prompt_ids.audit summary logs/proxy.jsonl --hours 24 --markdown
    python -m prompt_ids.audit tail logs/audit.jsonl -n 10
    python -m prompt_ids.audit top logs/audit.jsonl
    python -m prompt_ids.audit review logs/audit.jsonl --queue
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

from prompt_ids.audit.events import AuditEvent
from prompt_ids.audit.logger import disk_usage, file_size
from prompt_ids.audit.query import (
    last_hours,
    load,
    pending_reviews,
    render_report,
    review_stats,
    rule_ledger,
    rule_suspects,
    summarize,
    top_patterns,
    within,
)


def _fmt_ts(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%m-%d %H:%M:%S") if ts else "-"


def cmd_summary(args: argparse.Namespace) -> int:
    events = load(args.path)
    if args.hours:
        events = last_hours(events, args.hours)
    if args.level:
        events = [e for e in events if e.level == args.level]
    if args.kind:
        events = [e for e in events if e.kind == args.kind]

    if args.markdown:
        print(render_report(events, title=f"审计摘要 · {args.path}"))
        return 0

    summary = summarize(events)
    if not summary.total:
        print("无匹配的审计记录")
        return 1
    print(f"文件: {args.path}  ({file_size(args.path) / 1024:.1f} KB，"
          f"含轮转 {disk_usage(args.path) / 1024:.1f} KB)")
    print(f"事件: {summary.total}  阻断/泄漏: {summary.blocked}")
    print(f"耗时: 平均 {summary.avg_detect_ms:.2f} ms  P95 {summary.p95_detect_ms:.2f} ms")
    if summary.span_s > 0:
        print(f"跨度: {summary.span_s / 3600:.1f} 小时")
    for name, mapping in (
        ("类型", summary.by_kind), ("等级", summary.by_level),
        ("动作", summary.by_action), ("决策", summary.by_decision),
        ("来源", summary.by_source),
    ):
        if mapping:
            detail = "  ".join(f"{k}={v}" for k, v in mapping.items())
            print(f"{name}: {detail}")
    return 0


def cmd_tail(args: argparse.Namespace) -> int:
    events = load(args.path)
    picked = events[-args.n:] if args.n else events
    if args.json:
        for event in picked:
            print(event.to_line())
        return 0
    for event in picked:
        extra = f"  {json.dumps(event.extra, ensure_ascii=False)}" if event.extra and args.verbose else ""
        print(f"{_fmt_ts(event.ts)}  [{event.kind}] {event.level or '-':<8} "
              f"{event.action or '-':<7} score={event.score:5.1f} "
              f"fp={event.fp[:10] or '-'} {event.top_pattern or '-'}"
              f"{'  ' + event.note if event.note else ''}{extra}")
    return 0


def cmd_top(args: argparse.Namespace) -> int:
    events = load(args.path)
    if args.hours:
        events = last_hours(events, args.hours)
    patterns = top_patterns(events, limit=args.n)
    if not patterns:
        print("无规则命中记录")
        return 1
    print(f"{'规则':<14} 命中次数")
    for pattern, count in patterns:
        print(f"{pattern:<14} {count}")
    return 0


def cmd_review(args: argparse.Namespace) -> int:
    """复核台账：人工结论统计 + 待复核队列（只含指纹）。

    单独给一个子命令而不是塞进 summary：误报治理是**每天要看**的运营数字，
    埋在通用摘要里等于不存在。而 `false_positive_rate_on_reviewed` 这个指标
    系统自己算不出来 —— 它只统计 high/critical，而大量误伤停在 medium。
    """
    events = load(args.path)
    if args.hours:
        events = last_hours(events, args.hours)
    stats = review_stats(events)
    if not stats["reviews"]:
        print("尚无人工复核记录")
        print("提示：用 POST /v1/review 提交结论，或在检测台的「人工复核」页操作")
        return 1
    print(f"已复核 {stats['reviews']} 条："
          f"确认攻击 {stats['confirmed_attack']} · 标记误报 {stats['false_positive']} "
          f"（复核样本内误报率 {stats['false_positive_rate_on_reviewed']:.1%}）")
    print(f"其中写入记忆层 {stats['memory_absorbed']} 条")

    ledger = rule_ledger(events)
    if ledger:
        print("\n规则级台账（分母=人工复核过的样本）：")
        print(f"  {'规则':<12} {'复核':>5} {'确认攻击':>8} {'误报':>5} {'误报率':>7}")
        for name, row in sorted(ledger.items(), key=lambda kv: -kv[1]["total"])[:15]:
            rate = row["false_positive"] / row["total"] if row["total"] else 0.0
            print(f"  {name:<12} {row['total']:>5} {row['attack']:>8} "
                  f"{row['false_positive']:>5} {rate:>7.1%}")
        suspects = rule_suspects(ledger)
        if suspects:
            print("\n误报嫌疑（只给建议，系统不会自动改规则）：")
            for row in suspects:
                print(f"  {row['pattern_id']:<12} 复核 {row['total']} 次、"
                      f"其中误报 {row['false_positive']} 次（{row['fp_rate']:.0%}）")
            print("  下一步：用 --review-corpus 落下的原文跑 miss_analysis，看漏检/过杀结构；")
            print("        改完用同一脚本复跑对比数字。注意不要拿留出集调参。")
    if args.queue:
        pending = pending_reviews(events, limit=args.n)
        print(f"\n待复核 {len(pending)} 条（等级 >= medium 且尚无人工结论）：")
        if not pending:
            print("  队列为空")
        for e in pending:
            print(f"  {_fmt_ts(e.ts)}  {e.level:<8} score={e.score:5.1f} "
                  f"fp={e.fp[:10]} {e.top_pattern or '-':<10} {e.source}")
        print("\n注：队列只含指纹。原文需自行提供后调 POST /v1/review 定性。")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="prompt-ids-audit", description="审计日志查看")
    sub = parser.add_subparsers(dest="command", required=True)

    p_sum = sub.add_parser("summary", help="聚合摘要")
    p_sum.add_argument("path")
    p_sum.add_argument("--hours", type=float, help="只看最近 N 小时")
    p_sum.add_argument("--level", help="按等级过滤")
    p_sum.add_argument("--kind", help="按事件类型过滤")
    p_sum.add_argument("--markdown", action="store_true", help="输出 markdown 报表")
    p_sum.set_defaults(func=cmd_summary)

    p_tail = sub.add_parser("tail", help="查看最近事件")
    p_tail.add_argument("path")
    p_tail.add_argument("-n", type=int, default=20)
    p_tail.add_argument("--json", action="store_true", help="原始 JSON 行输出")
    p_tail.add_argument("--verbose", "-v", action="store_true")
    p_tail.set_defaults(func=cmd_tail)

    p_top = sub.add_parser("top", help="命中最多的规则")
    p_top.add_argument("path")
    p_top.add_argument("-n", type=int, default=10)
    p_top.add_argument("--hours", type=float)
    p_top.set_defaults(func=cmd_top)

    p_rev = sub.add_parser("review", help="人工复核台账与待复核队列")
    p_rev.add_argument("path")
    p_rev.add_argument("--hours", type=float)
    p_rev.add_argument("--queue", action="store_true", help="一并列出待复核队列")
    p_rev.add_argument("-n", type=int, default=20, help="队列最多列多少条")
    p_rev.set_defaults(func=cmd_review)

    args = parser.parse_args(argv)
    if not Path(args.path).exists():
        print(f"文件不存在：{args.path}", file=sys.stderr)
        return 1
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
