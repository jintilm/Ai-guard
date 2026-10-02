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
EXIT_FAIL = 1
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
                     help="后端：auto/local/lightweight/null，或 21 家提供商之一"
                          "（deepseek/openai/azure/qwen/zhipu/moonshot/siliconflow/volces/"
                          "qianfan/minimax/anthropic/groq/mistral/together/openrouter/xai/"
                          "perplexity/ollama/vllm/lmstudio/custom），"
                          "也接受 LiteLLM 风格一行写法 groq/llama-3.3-70b-versatile，"
                          "或 HuggingFace repo id。用 --list-providers 看全部")
    sem.add_argument("--semantic-mode", default="fallback", help="预筛门禁：fallback/always/hybrid/confirm")
    sem.add_argument("--semantic-model", default="", help="自定义模型名（如 deepseek-v4-flash）")
    sem.add_argument("--semantic-timeout", type=float, default=None, help="单次推理超时秒数")
    sem.add_argument("--semantic-fallbacks", default="",
                     help="回退链，逗号分隔的 provider/model，主端点失败时顺次尝试。"
                          "如 groq/llama-3.3-70b-versatile,xai/grok-4.3")
    sem.add_argument("--semantic-local-only", action="store_true",
                     help="不用云端 Key，强制走本地推理后端")
    sem.add_argument("--probe", action="store_true", help="打印各语义后端的可用性后退出")
    sem.add_argument("--list-providers", action="store_true",
                     help="列出全部提供商、默认模型、Key 变量与当前可用性后退出")
    sem.add_argument("--list-models", metavar="PROVIDER", nargs="?", const="",
                     help="向端点查当前真实模型清单后退出（模型名换代时用它核对）")
    mem = p.add_argument_group("向量记忆库 L4（自进化）")
    mem.add_argument("--memory", action="store_true", help="启用记忆库，确认的攻击会自动写回")
    mem.add_argument("--memory-encoder", default="auto", help="编码器：auto/deberta/hashing")
    mem.add_argument("--memory-threshold", type=float, default=0.86, help="命中阈值（余弦相似度）")
    mem.add_argument("--memory-dir", default="", help="记忆库目录，存在则加载，退出前不一定回写")
    mem.add_argument("--no-auto-learn", action="store_true", help="关闭自动入库，只用已有记忆")
    p.add_argument("--audit", default="", help="审计日志路径（JSONL，只记指纹不记原文）")
    p.add_argument("--policy", default="",
                   help="策略名：default / strict / permissive / log-only")
    out = p.add_argument_group("出站扫描（扫模型输出，不是扫输入）")
    out.add_argument("--scan-output", action="store_true",
                     help="把输入当作**模型输出**扫描：找第三方凭据并脱敏后退出")
    out.add_argument("--version", action="version", version=f"prompt-ids {__version__}")
    return p


def _run_output_scan(args: argparse.Namespace) -> int:
    """出站扫描：不建流水线、不跑规则层，只看凭据。

    刻意与请求侧检测分开：输入是「用户说的话」，输出是「模型生成的话」，
    混在一个开关里会让运维以为两侧覆盖面相同。
    """
    from prompt_ids.output import redact, scan_secrets, summary

    texts = _split(_read_input(args), args.lines)
    if args.jsonl or (args.json and len(texts) > 1):
        for text in texts:
            hits = scan_secrets(text)
            print(json.dumps({"found": len(hits), "by_kind": summary(hits),
                              "secrets": [h.as_dict() for h in hits],
                              "redacted": redact(text, hits)}, ensure_ascii=False))
    elif args.json:
        hits = scan_secrets(texts[0])
        print(json.dumps({"found": len(hits), "by_kind": summary(hits),
                          "secrets": [h.as_dict() for h in hits],
                          "redacted": redact(texts[0], hits)}, ensure_ascii=False, indent=2))
    elif args.quiet:
        for text in texts:
            print(f"secrets\t{len(scan_secrets(text))}")
    else:
        for i, text in enumerate(texts, 1):
            hits = scan_secrets(text)
            if len(texts) > 1:
                print(f"\n----- 样本 {i} -----")
            if not hits:
                print("未发现凭据")
                continue
            print(f"发现 {len(hits)} 处凭据：{summary(hits)}")
            for hit in hits:
                print(f"  - {hit.kind} @ {hit.start}  {hit.masked()}")
            print("\n脱敏后：")
            print(redact(text, hits))
    return EXIT_BLOCK if any(scan_secrets(t) for t in texts) else EXIT_PASS


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
            semantic_fallbacks=args.semantic_fallbacks,
            semantic_local_only=args.semantic_local_only,
            memory_enabled=args.memory,
            memory_encoder=args.memory_encoder,
            memory_threshold=args.memory_threshold,
            memory_auto_learn=not args.no_auto_learn,
            memory_dir=args.memory_dir,
            audit_path=args.audit,
        ),
    )


def _disp_width(text: str) -> int:
    """终端显示宽度：CJK 全角字符占 2 列。

    直接拿 len() 排版会在中文列上歪掉 —— 「未配置」是 3 个字符但 6 列宽，
    `f"{s:<6}"` 只补 3 个空格，于是中文列右边的列整体错位。
    """
    import unicodedata

    return sum(2 if unicodedata.east_asian_width(ch) in "WF" else 1 for ch in text)


def _pad(text: str, width: int) -> str:
    return text + " " * max(0, width - _disp_width(text))


def _print_providers() -> int:
    """人类可读的提供商清单 —— 比 --probe 的 JSON 更适合排环境问题。"""
    from prompt_ids.detectors.semantic import provider_table

    rows = provider_table()
    available = [r for r in rows if r["available"]]
    headers = ("提供商", "状态", "默认模型", "Key 环境变量")
    cells = [
        (r["provider"], "可用" if r["available"] else "未配置", r["model"] or "—",
         " / ".join(r["key_env"]) or "（免 Key）")
        for r in rows
    ]
    widths = [
        max(_disp_width(headers[i]), *(_disp_width(row[i]) for row in cells))
        for i in range(len(headers))
    ]

    print(f"共 {len(rows)} 家提供商，当前可用 {len(available)} 家\n")
    print("  ".join(_pad(h, w) for h, w in zip(headers, widths)).rstrip())
    print("-" * (sum(widths) + 2 * (len(widths) - 1)))
    for row in cells:
        print("  ".join(_pad(c, w) for c, w in zip(row, widths)).rstrip())
    print()
    if available:
        print("可用：" + ", ".join(r["provider"] for r in available))
    else:
        print("一家都没配。把 Key 填进项目根目录 .env 即可（模板见 .env.example）。")
        print("提示：ollama / vllm / lmstudio 免 Key，但要显式 --semantic-backend 才会用。")
    print("\n写法：--semantic-backend <提供商>，或一行写完 --semantic-backend groq/llama-3.3-70b-versatile")
    print("模型名会随厂商换代漂移，用 --list-models <提供商> 查当前真实清单。")
    return EXIT_PASS


def _print_models(provider: str) -> int:
    """向端点查模型清单 —— 模型名换代时的唯一可靠来源。"""
    from prompt_ids.detectors.semantic import list_models, provider_names

    target = (provider or "").strip().lower()
    if not target:
        from prompt_ids.detectors.semantic.providers import resolve_provider

        target = resolve_provider("auto")
        if not target:
            print("未指定提供商，且没有已配 Key 的可推断提供商。")
            print("用法：--list-models deepseek    可选：" + ", ".join(provider_names()))
            return EXIT_PASS
        print(f"（未指定提供商，按 auto 选型推断为 {target}）")

    result = list_models(target)
    if not result.get("ok"):
        print(f"查询失败：{result.get('error')}")
        print(f"端点：{result.get('url', '(未配置)')}")
        return EXIT_FAIL

    print(f"{target} 端点 {result['url']} 共返回 {result['count']} 个模型：\n")
    for name in result["models"]:
        print(f"  {name}")
    return EXIT_PASS


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

    if args.list_providers:
        return _print_providers()

    if args.list_models is not None:
        return _print_models(args.list_models or "")

    if args.scan_output:
        return _run_output_scan(args)

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
