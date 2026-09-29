"""审计日志查看与分析。

    python -m prompt_ids.audit summary logs/audit.jsonl
    python -m prompt_ids.audit summary logs/proxy.jsonl --hours 24 --markdown
    python -m prompt_ids.audit tail logs/audit.jsonl -n 10
    python -m prompt_ids.audit top logs/audit.jsonl
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
    render_report,
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

    args = parser.parse_args(argv)
    if not Path(args.path).exists():
        print(f"文件不存在：{args.path}", file=sys.stderr)
        return 1
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
