"""python -m prompt_ids.api —— REST 检测服务。

    python -m prompt_ids.api
    python -m prompt_ids.api --port 8790 --canary --semantic
    python -m prompt_ids.api --rate-limit 60 --api-key <key>
"""
from __future__ import annotations

import argparse

from prompt_ids.api.app import ApiContext
from prompt_ids.api.server import DEFAULT_PORT, ApiServerConfig, serve
from prompt_ids.canary.tokens import CanaryRegistry


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="prompt-ids-api", description="提示词注入检测 REST 服务"
    )
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--api-key", default="", help="开启鉴权；也可设 PROMPT_IDS_API_KEY")
    parser.add_argument("--rate-limit", type=int, default=0, help="每个 Key/IP 的窗口内请求上限")
    parser.add_argument("--rate-window", type=float, default=60.0)
    parser.add_argument("--no-cors", action="store_true")
    parser.add_argument("--canary", action="store_true", help="启用 Canary 端点")
    parser.add_argument("--canary-issue-limit", type=int, default=30,
                        help="POST /v1/canary/issue 每身份的窗口内签发上限，"
                             "0 = 关闭（默认 30；该端点明文返回完整令牌，默认开着）")
    parser.add_argument("--canary-issue-window", type=float, default=60.0)
    parser.add_argument("--semantic", action="store_true", help="启用 L3 语义层")
    parser.add_argument("--semantic-mode", default="fallback")
    parser.add_argument("--memory", action="store_true", help="启用 L4 向量记忆库（自进化）")
    parser.add_argument("--memory-encoder", default="auto", help="auto / deberta / hashing")
    parser.add_argument("--memory-threshold", type=float, default=0.86)
    parser.add_argument("--memory-dir", default="", help="记忆库目录，存在则加载")
    parser.add_argument("--audit", default="", help="审计日志路径（JSONL，只记指纹不记原文）")
    parser.add_argument("--review-corpus", default="",
                        help="复核语料路径（JSONL，**含原文**）。不配就不写。"
                             "用于把人工结论喂回规则迭代；会自动加进 .gitignore")
    args = parser.parse_args(argv)

    ctx = ApiContext(
        canary=CanaryRegistry() if args.canary else None,
        semantic=args.semantic,
        semantic_mode=args.semantic_mode,
        memory=args.memory,
        memory_encoder=args.memory_encoder,
        memory_threshold=args.memory_threshold,
        memory_dir=args.memory_dir,
        audit_path=args.audit,
        review_corpus_path=args.review_corpus,
    )
    if args.review_corpus:
        # 语料含原文，必须挡住误提交。只加精确路径，不用通配符 ——
        # 通配符会顺手盖掉别的数据文件，那是不可逆的副作用。
        from prompt_ids.audit.review_corpus import add_to_gitignore

        if add_to_gitignore(args.review_corpus):
            print(f"已把 {args.review_corpus} 加进 .gitignore（含原文，刻意不入库）")
    if args.semantic:
        ctx.pipeline.warmup()

    config = ApiServerConfig(
        port=args.port,
        host=args.host,
        api_key=args.api_key or None,
        rate_limit=args.rate_limit,
        rate_window_s=args.rate_window,
        cors=not args.no_cors,
        canary_issue_limit=args.canary_issue_limit,
        canary_issue_window_s=args.canary_issue_window,
    )
    # 配额透进 ctx：`/v1/metrics` 只拿到 ctx，而「配额是多少」正是运维要看的数
    ctx.canary_issue_limit = config.canary_issue_limit
    ctx.canary_issue_window_s = config.canary_issue_window_s
    if args.canary:
        print(f"Canary: 已启用  签发配额: "
              f"{config.canary_issue_limit}/{int(config.canary_issue_window_s)}s/身份"
              f"{'（已关闭）' if not config.canary_issue_limiter else ''}")
    serve(ctx, config)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
