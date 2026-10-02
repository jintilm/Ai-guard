"""监听地址的暴露面检查 —— 「默认只绑本机」是**默认值**，不是保证。

## 为什么要有这个模块

三个 HTTP 入口的 `--host` 都是自由字符串，默认 `127.0.0.1`，但**没有任何东西
拦住 `--host 0.0.0.0`**。而三个入口里**只有 API 有客户端鉴权**
（`PROMPT_IDS_API_KEY` / `--api-key`）：

| 入口 | 客户端鉴权 | 暴露的路由 |
|---|---|---|
| `api` | ✅ 有（可关） | `/v1/scan`、`/v1/canary/issue`、`/v1/metrics` … |
| `proxy` | ❌ **无** —— 客户端 `Authorization` 头是**透传给上游**的，代理自己不验证 | 全部直通端点 + 注入检测面 |
| `web --serve`（检测台） | ❌ **无** —— 完全没有鉴权概念 | `/v1/scan`、`/v1/scan/batch`、`/v1/review`、`/v1/canary/issue`、`/v1/events` |

代理侧只有按来源 IP 的限流与 canary 签发配额（30/分钟·每身份），**那不是鉴权**：
能过 IP 限流的人照样能代跑检测、签发 canary、读审计事件。

所以「让同事也能看到看板」而改 `--host` 是很自然的动作 —— 而它恰好落进
无鉴权暴露面。本模块把这个组合**响亮说出来**，而不是让用户自己撞上。

## 为什么不直接禁止非回环绑定

容器/K8s 部署**必然**要求 `--host 0.0.0.0`（Pod 里 `127.0.0.1` 别的容器摸不到），
直接禁止等于让这个部署形态不可用。所以这里给的是**告警 + 明确的正确姿势**
（前置反向代理做鉴权），不是硬拦 —— 与本项目「响亮失败优于静默降级」同一纪律，
但硬拦会变成另一种静默失败（用户改用别的端口暴露）。

## 与「默认不鉴权不回显内部信息」是同一套考量

审计记录里有一条：曾把绝对路径 / 内网 base_url（含内嵌凭据）通过 500 响应
回显给客户端。那次修的是**单个路由的信息泄漏**；这里是**整个服务的暴露面**，
此前没人把「监听地址」纳入同一套考量。
"""
from __future__ import annotations

import ipaddress
import sys

#: 视为「只在本机」的地址写法。`localhost` 单独列，因为它不是 IP 字面量。
LOOPBACK_NAMES = frozenset({"localhost", "localhost.localdomain", ""})


def is_loopback(host: str) -> bool:
    """`host` 是否只监听本机。

    判定不了的一律按**非本机**处理（`False`）—— 这是安全检查的方向：
    宁可多报一次告警，也不要因为某个奇怪的写法而静默放行。
    """
    text = (host or "").strip().lower()
    if text in LOOPBACK_NAMES:
        # 空串在 HTTPServer 里等价于绑定全部地址（0.0.0.0），所以不能算本机。
        return bool(text)
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    try:
        return ipaddress.ip_address(text).is_loopback
    except ValueError:
        return False


def exposure_report(host: str, *, service: str, authenticated: bool) -> str:
    """绑非回环地址且没有客户端鉴权时，返回一句给运维看的告警；否则返回空串。

    纯函数：不打印、不退出 —— 这样守护测试能直接断言它的内容，
    打印与否由调用方决定（告警一律走 stderr，见 `warn_if_exposed`）。
    """
    if is_loopback(host) or authenticated:
        return ""
    return (
        f"⚠ {service} 正监听 {host}（非回环地址）且**没有客户端鉴权**。\n"
        f"    同网段的任何人可以：调 /v1/scan 让本机替它跑检测、读 /v1/events 的"
        f"审计事件、调用 /v1/canary/issue 领取令牌。\n"
        f"    正确姿势：保持 {service} 绑 127.0.0.1，在前面用反向代理"
        f"（Nginx / Caddy / 网关）做 TLS 与鉴权；\n"
        f"    或给 API 设 PROMPT_IDS_API_KEY —— 但代理与检测台没有这个机制，"
        f"只能靠前置代理。"
    )


def warn_if_exposed(host: str, *, service: str, authenticated: bool) -> str:
    """`exposure_report` 的打印版：**只写 stderr**，返回是否告警了。

    走 stderr 是本项目的既有纪律：Windows PowerShell 会把 stderr 渲染成红色错误行，
    但污染 stdout 更糟 —— `--json` / `--jsonl` 的输出流必须是干净的 JSON。
    """
    message = exposure_report(host, service=service, authenticated=authenticated)
    if message:
        print(message, file=sys.stderr)
    return message
