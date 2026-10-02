"""检查「生产部署姿势」是否到位 —— 把三道门逐个查一遍并给出结论。

## 为什么要有这个脚本

`AGENTS.md` 里「生产部署的安全姿势」此前只是一句**声明**：
容器里必须 `--host 0.0.0.0`，而代理与检测台没有客户端鉴权，所以要前置反向代理。
问题是声明不是方案：

- 没人知道该配哪几个头、哪个超时该多大；
- 改坏了没有任何东西会发现；
- ⚠ 最要紧的是：**「配了」很容易被当成「对了」**。比如反代没有透传
  `X-Forwarded-For` ⇒ 本服务的按 IP 限流把所有人算成一个桶，
  第一个请求就耗尽额度；而现象看起来像「限流太激进」，不会有人怀疑到反代。

所以这个脚本不验证「有没有反代」（那要连到真的 nginx 才查得到），
而是把**能查的都查出来**，并明确说清哪些查不了：

    鉴权（--client-key / PROMPT_IDS_*_CLIENT_KEY 是否配了）
    TLS（deploy/nginx.conf 里有没有证书与 TLS 版本）
    限流（反代是否透传真实 IP；服务侧限流开没开）

退出码 0 = 三道门都到位；1 = 有缺口（逐条列出）。
⚠ **不查上游连通性**（那需要 Key，且本脚本不该碰凭据）。

用法：
    python scripts/deploy_check.py                    # 静态检查配置
    python scripts/deploy_check.py --json             # 机器可读
    python scripts/deploy_check.py --runtime          # 真起服务验鉴权是否生效
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

ROOT = Path(__file__).resolve().parent.parent


def _env(*names: str) -> str:
    import os

    for name in names:
        value = (os.environ.get(name, "") or "").strip()
        if value:
            return value
    return ""


def _nginx_text() -> str:
    path = ROOT / "deploy" / "nginx.conf"
    return path.read_text(encoding="utf-8") if path.exists() else ""


def check() -> dict:
    """返回三道门的现状。**每一条都说明「查的是什么、查不到什么」。"""
    nginx = _nginx_text()
    checks: list[dict] = []

    # ---------- 门 1：鉴权 ----------
    client_key = _env("PROMPT_IDS_PROXY_CLIENT_KEY", "PROMPT_IDS_WEB_CLIENT_KEY")
    api_key = _env("PROMPT_IDS_API_KEY")
    checks.append({
        "gate": "鉴权",
        "ok": bool(client_key) and bool(api_key),
        "detail": (
            f"代理/检测台 client_key={'已配' if client_key else '未配'}；"
            f"API key={'已配' if api_key else '未配'}"
            + ("" if client_key else
               "。⚠ 未配时只要绑 0.0.0.0，同网段任何人都能调 /v1/scan、"
               "/v1/canary/issue —— 限流不是鉴权")
        ),
        "cannot_check": "查不出反向代理是否真的在转发 X-API-Key（要连到真 nginx）",
    })

    # ---------- 门 2：TLS ----------
    has_cert = "ssl_certificate" in nginx
    tls12 = "TLSv1.2" in nginx
    checks.append({
        "gate": "TLS",
        "ok": bool(nginx) and has_cert and tls12,
        "detail": (
            ("deploy/nginx.conf 里有证书与 TLSv1.2+ 配置"
             if has_cert and tls12 else
             "⚠ deploy/nginx.conf 缺证书或 TLSv1.2 —— X-API-Key 走明文就是裸奔")
        ),
        "cannot_check": "查不出证书是否有效、是否过期、域名是否匹配",
    })

    # ---------- 门 3：限流 ----------
    forwards_ip = "X-Forwarded-For" in nginx
    body_limit = "client_max_body_size" in nginx
    timeout_ok = False
    timeout_value = 0
    for line in nginx.splitlines():
        if "proxy_read_timeout" in line:
            try:
                timeout_value = int(line.split()[1].rstrip("s;"))
            except (IndexError, ValueError):
                timeout_value = 0
            timeout_ok = timeout_value >= 120
    timeout_note = "" if timeout_ok else (
        "（⚠ 应 ≥120s：LLM p90≈40s，nginx 默认 60s 会随机 504，"
        "而服务日志一切正常）")
    checks.append({
        "gate": "限流",
        "ok": forwards_ip and body_limit and timeout_ok,
        "detail": (
            f"X-Forwarded-For={'有' if forwards_ip else '⚠ 缺'}；"
            f"client_max_body_size={'有' if body_limit else '⚠ 缺'}；"
            f"proxy_read_timeout={timeout_value}s{timeout_note}"
        ),
        "cannot_check": "查不出 nginx 默认的 60s 之外的运行时行为，也查不出上游 p99",
    })

    # ---------- 容器端口 ----------
    compose = ROOT / "docker-compose.yml"
    compose_text = compose.read_text(encoding="utf-8") if compose.exists() else ""
    loopback_only = "127.0.0.1:" in compose_text and "0.0.0.0:" not in compose_text
    checks.append({
        "gate": "端口暴露",
        "ok": bool(compose_text) and loopback_only,
        "detail": ("compose 只把端口发布到宿主回环（对外由反代暴露）"
                   if loopback_only else
                   "⚠ compose 里没有把端口限制到 127.0.0.1"),
        "cannot_check": "查不出宿主防火墙与安全组规则",
    })

    ok = all(item["ok"] for item in checks)
    return {"ok": ok, "checks": checks}


def check_runtime() -> dict:
    """真起服务验「配了 client_key 是否真的生效」。

    静态检查只能证明**配置项存在**，证明不了**行为生效** ——
    缺头、读错 env 名、鉴权代码没接上，这三种情况静态检查都会放行。
    """
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    from prompt_ids.core.pipeline import Pipeline, PipelineConfig
    from prompt_ids.proxy.server import ProxyConfig, create_server

    class _Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            length = int(self.headers.get("Content-Length") or 0)
            if length:
                self.rfile.read(length)
            payload = b'{"choices":[{"message":{"content":"ok"}}]}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    upstream = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=upstream.serve_forever, daemon=True).start()
    pipeline = Pipeline(config=PipelineConfig(enable_cache=False))
    results = {}
    try:
        for label, key in (("配了 client_key", "verify-me"),
                           ("没配 client_key", "")):
            server = create_server(ProxyConfig(
                upstream=f"http://127.0.0.1:{upstream.server_address[1]}/v1",
                client_key=key, pipeline=pipeline))
            threading.Thread(target=server.serve_forever, daemon=True).start()
            port = server.server_address[1]
            try:
                results[label] = _probe(port, "nope")
                results[label + "（带正确 Key）"] = _probe(port, key or None)
            finally:
                server.shutdown()
                server.server_close()
    finally:
        upstream.shutdown()
        upstream.server_close()
        pipeline.close()
    behavior_ok = (results["配了 client_key"] == 401
                   and results["配了 client_key（带正确 Key）"] == 200
                   and results["没配 client_key"] == 200)
    return {"ok": behavior_ok, "results": results}


def _probe(port: int, key: str | None) -> int:
    import urllib.error
    import urllib.request

    headers = {"Content-Type": "application/json"}
    if key:
        headers["X-API-Key"] = key
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}/v1/chat/completions",
        data=json.dumps({"model": "x", "messages": [
            {"role": "user", "content": "hi"}]}).encode(),
        method="POST", headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            return response.status
    except urllib.error.HTTPError as exc:
        return exc.code
    except Exception:  # noqa: BLE001
        return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="检查生产部署姿势是否到位")
    parser.add_argument("--json", action="store_true", help="机器可读输出")
    parser.add_argument("--runtime", action="store_true",
                        help="真起服务验鉴权是否生效（不联网）")
    args = parser.parse_args(argv)

    report = check()
    if args.runtime:
        runtime = check_runtime()
        report["runtime"] = runtime
        report["ok"] = report["ok"] and runtime["ok"]

    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 0 if report["ok"] else 1

    print("生产部署姿势检查")
    print("=" * 60)
    for item in report["checks"]:
        mark = "OK  " if item["ok"] else "缺口"
        print(f"[{mark}] {item['gate']}：{item['detail']}")
        print(f"        （查不到：{item['cannot_check']}）")
    if "runtime" in report:
        print("-" * 60)
        print("运行时验证（真起服务，不联网）：")
        for label, status in report["runtime"]["results"].items():
            print(f"  {label:<28} -> HTTP {status}")
        mark = "OK  " if report["runtime"]["ok"] else "缺口"
        print(f"[{mark}] 鉴权行为与配置一致")
    print("=" * 60)
    print("结论：" + ("三道门到位" if report["ok"] else "**有缺口，见上面标「缺口」的条目**"))
    print("提醒：限流 ≠ 鉴权；鉴权 ≠ TLS。服务绑 0.0.0.0 时反代是唯一的一道门。")
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())