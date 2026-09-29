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
    parser.add_argument("--semantic", action="store_true", help="启用 L3 语义层")
    parser.add_argument("--semantic-mode", default="fallback")
    parser.add_argument("--memory", action="store_true", help="启用 L4 向量记忆库（自进化）")
    parser.add_argument("--memory-encoder", default="auto", help="auto / deberta / hashing")
    parser.add_argument("--memory-threshold", type=float, default=0.86)
    parser.add_argument("--memory-dir", default="", help="记忆库目录，存在则加载")
    parser.add_argument("--audit", default="", help="审计日志路径（JSONL，只记指纹不记原文）")
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
    )
    if args.semantic:
        ctx.pipeline.warmup()

    config = ApiServerConfig(
        port=args.port,
        host=args.host,
        api_key=args.api_key or None,
        rate_limit=args.rate_limit,
        rate_window_s=args.rate_window,
        cors=not args.no_cors,
    )
    serve(ctx, config)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
