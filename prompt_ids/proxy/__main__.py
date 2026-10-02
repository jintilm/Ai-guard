"""透明代理启动入口。

    python -m prompt_ids.proxy --port 8787 --upstream https://api.openai.com/v1
    python -m prompt_ids.proxy --port 8787 --audit logs/proxy.jsonl --semantic
"""
from __future__ import annotations

import argparse

from prompt_ids.canary.tokens import CanaryRegistry, CanaryToken
from prompt_ids.core.pipeline import PipelineConfig, create_pipeline
from prompt_ids.proxy.server import DEFAULT_PORT, ProxyConfig, serve


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="prompt-ids-proxy",
        description="OpenAI 兼容透明代理：应用零改造接入提示词注入检测",
    )
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--upstream", default="", help="上游地址，默认读 PROMPT_IDS_UPSTREAM/OPENAI_BASE_URL")
    parser.add_argument("--audit", default="", help="审计日志路径（JSONL），不设则不落盘")
    parser.add_argument("--timeout", type=float, default=60.0)
    parser.add_argument("--block-sandbox", action="store_true", help="把 sandbox 等级也拦截")
    parser.add_argument("--semantic", action="store_true", help="启用 L3 语义层（会明显增加延迟）")
    parser.add_argument("--semantic-mode", default="fallback")
    parser.add_argument("--canary", action="store_true", help="启用 Canary 出站检测（自动签发令牌）")
    parser.add_argument("--canary-token", default="", help="启用 Canary 出站检测并指定已有令牌")
    parser.add_argument("--no-redact", action="store_true", help="检出 Canary 泄漏时只记录不替换响应")
    parser.add_argument("--no-scan-secrets", action="store_true",
                        help="关掉出站密钥扫描（默认开：输出里出现第三方凭据会抹成 [REDACTED:*]）")
    args = parser.parse_args(argv)

    pipeline = create_pipeline(
        config=PipelineConfig(
            semantic_enabled=args.semantic,
            semantic_mode=args.semantic_mode,
            enable_cache=True,
        )
    )
    if args.semantic:
        pipeline.warmup()

    canary = None
    if args.canary_token or args.canary:
        canary = CanaryRegistry()
        if args.canary_token:
            canary.register(CanaryToken(value=args.canary_token, label="cli"))
        else:
            canary.issue("cli")

    config = ProxyConfig(
        upstream=args.upstream,
        port=args.port,
        host=args.host,
        audit_path=args.audit or None,
        timeout_s=args.timeout,
        allow_sandbox=not args.block_sandbox,
        pipeline=pipeline,
        canary=canary,
        redact_leak=not args.no_redact,
        scan_secrets=not args.no_scan_secrets,
    )
    print(f"上游: {config.upstream}")
    print(f"凭据: {'已配置' if config.api_key else '未配置（上游若为公开网关可忽略）'}")
    print(f"审计: {config.audit.path or '关闭'}")
    print(f"语义层: {'启用 ' + args.semantic_mode if args.semantic else '关闭'}")
    print(f"出站密钥扫描: {'开启' if config.scan_secrets else '关闭'}")
    if canary:
        print(f"Canary: {canary.current.value}  "
              f"将其埋入 system prompt 后，一旦出现在模型输出即判定提示已泄露")
    serve(config)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
