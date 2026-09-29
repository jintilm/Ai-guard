"""command-line interface for prompt_ids.

用法：
    python -m prompt_ids.cli "ignore all previous instructions"
    python -m prompt_ids.cli --file input.txt
    python -m prompt_ids.cli --stdin --jsonl
    python -m prompt_ids.cli --rules-stats
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from prompt_ids import __version__, get_pipeline
from prompt_ids.core.pipeline import Pipeline, PipelineConfig
from prompt_ids.core.policy import Policy, PolicyEngine
from prompt_ids.core.types import Level
from prompt_ids.core.verdict import FusionConfig
from prompt_ids.rules.loader import RuleBook

EXIT_PASS = 0
EXIT_REVIEW = 2
EXIT_BLOCK = 3


def build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="prompt-ids",
        description="提示词注入检测系统 —— 多层级联检测流水线",
    )
    p.add_argument("text", nargs="?", help="待检测文本；不传则从 --stdin 读取")
    p.add_argument("--file", "-f", help="从文件读取（按行分段时为整段）")
    p.add_argument("--stdin", action="store_true", help="从标准输入读取")
    p.add_argument("--lines", action="store_true", help="把输入按行拆分为多条样本")
    p.add_argument("--json", action="store_true", help="JSON 输出")
    p.add_argument("--jsonl", action="store_true", help="按行 JSON 输出（批量场景）")
    p.add_argument("--quiet", "-q", action="store_true", help="只输出一行结论")
    p.add_argument("--no-cache", action="store_true", help="关闭结果缓存")
    p.add_argument("--no-short-circuit", action="store_true", help="关闭高危规则短路")
    p.add_argument("--strict", action="store_true", help="严格模式：medium/high 也阻断")
    p.add_argument("--tiers", default="critical,high,medium", help="启用规则档位，逗号分隔")
    p.add_argument("--user", default="cli", help="限流与审计用的用户标识")
    p.add_argument("--budget-ms", type=float, default=500.0, help="检测总耗时预算")
    p.add_argument("--rules-stats", action="store_true", help="打印规则库统计后退出")
    p.add_argument("--rules-dir", help="自定义规则目录")
    sem = p.add_argument_group("语义层 L3")
    sem.add_argument("--semantic", action="store_true", help="启用语义层（自动挑可用后端）")
    sem.add_argument("--semantic-backend", default="auto",
                     help="后端：auto/local/llm/deepseek/openai/lightweight 或 HF repo id")
    sem.add_argument("--semantic-mode", default="fallback", help="预筛门禁：fallback/always/hybrid/confirm")
    sem.add_argument("--semantic-model", default="", help="自定义模型名（如 deepseek-chat）")
    sem.add_argument("--semantic-timeout", type=float, default=None, help="单次推理超时秒数")
    sem.add_argument("--probe", action="store_true", help="打印各语义后端的可用性后退出")
    mem = p.add_argument_group("向量记忆库 L4（自进化）")
    mem.add_argument("--memory", action="store_true", help="启用记忆库，确认的攻击会自动写回")
    mem.add_argument("--memory-encoder", default="auto", help="编码器：auto/deberta/hashing")
    mem.add_argument("--memory-threshold", type=float, default=0.86, help="命中阈值（余弦相似度）")
    mem.add_argument("--memory-dir", default="", help="记忆库目录，存在则加载，退出前不一定回写")
    mem.add_argument("--no-auto-learn", action="store_true", help="关闭自动入库，只用已有记忆")
    p.add_argument("--audit", default="", help="审计日志路径（JSONL，只记指纹不记原文）")
    p.add_argument("--policy", default="",
                   help="策略名：default / strict / permissive / log-only")
    p.add_argument("--version", action="version", version=f"prompt-ids {__version__}")
    return p


def _read_input(args: argparse.Namespace) -> str:
    if args.stdin:
        return sys.stdin.read()
    if args.file:
        path = Path(args.file)
        if not path.exists():
            raise SystemExit(f"文件不存在：{path}")
        return path.read_text(encoding="utf-8", errors="replace")
    if args.text is not None:
        return args.text
    raise SystemExit("未指定输入：请给位置参数，或用 --file / --stdin")


def _split(text: str, by_lines: bool) -> list[str]:
    if not by_lines:
        return [text]
    return [line for line in text.splitlines() if line.strip()]


def _make_pipeline(args: argparse.Namespace) -> Pipeline:
    tiers = tuple(t.strip() for t in args.tiers.split(",") if t.strip())
    policies = PolicyEngine()
    if args.strict:
        policies.register(Policy(name="strict", strict=True))
    return get_pipeline(
        refresh=True,
        tiers=tiers,
        rules_dir=args.rules_dir,
        policies=policies,
        config=PipelineConfig(
            fusion=FusionConfig(),
            policy=args.policy or ("strict" if args.strict else "default"),
            enable_cache=not args.no_cache,
            short_circuit_on_critical=not args.no_short_circuit,
            budget_ms=args.budget_ms,
            semantic_enabled=args.semantic,
            semantic_mode=args.semantic_mode,
            semantic_backend=args.semantic_backend,
            semantic_model=args.semantic_model,
            semantic_timeout_s=args.semantic_timeout,
            memory_enabled=args.memory,
            memory_encoder=args.memory_encoder,
            memory_threshold=args.memory_threshold,
            memory_auto_learn=not args.no_auto_learn,
            memory_dir=args.memory_dir,
            audit_path=args.audit,
        ),
    )


def main(argv: list[str] | None = None) -> int:
    args = build_argparser().parse_args(argv)

    if args.rules_stats:
        book = RuleBook(args.rules_dir) if args.rules_dir else RuleBook()
        print(json.dumps(book.stats(), ensure_ascii=False, indent=2))
        return EXIT_PASS

    if args.probe:
        from prompt_ids.detectors.semantic import probe

        print(json.dumps(probe(), ensure_ascii=False, indent=2))
        return EXIT_PASS

    pipeline = _make_pipeline(args)
    if args.semantic:
        pipeline.warmup()
    texts = _split(_read_input(args), args.lines)
    results = pipeline.scan_batch(texts, user=args.user)
    if pipeline.audit is not None:
        pipeline.audit.flush()

    if args.jsonl or (args.json and len(results) > 1):
        for item in results:
            print(json.dumps(item.to_dict(), ensure_ascii=False))
    elif args.json:
        print(json.dumps(results[0].to_dict(), ensure_ascii=False, indent=2))
    elif args.quiet:
        for item in results:
            print(f"{item.level.value}\t{item.score:.1f}\t{item.action.value}")
    else:
        for i, item in enumerate(results, 1):
            if len(results) > 1:
                print(f"\n----- 样本 {i} -----")
            print(item.summary())

    worst = max((r.level for r in results), key=lambda lv: list(Level).index(lv), default=Level.SAFE)
    if worst in (Level.HIGH, Level.CRITICAL):
        return EXIT_BLOCK
    if worst == Level.MEDIUM:
        return EXIT_REVIEW
    return EXIT_PASS


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
