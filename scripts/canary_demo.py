"""Canary 闭环演示 —— 答辩现场最好用的一段。

演示的是别的方案给不出的证据链：
  规则层只能说"这像攻击"，Canary 能说"提示确实被吐出来了，攻击已得手"。

流程：埋入令牌 → 模拟 6 种模型输出（含编码/插字符规避）→ 逐条判定 →
再演示一次真实代理下的出站拦截。

    python scripts/canary_demo.py
    python scripts/canary_demo.py --with-proxy
"""
from __future__ import annotations

import base64
import codecs
import json
import sys
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from prompt_ids.canary.tokens import CanaryRegistry, issue  # noqa: E402
from prompt_ids.eval.metrics import markdown_table  # noqa: E402
from prompt_ids.proxy.server import ProxyConfig, create_server  # noqa: E402


class LeakyUpstream(BaseHTTPRequestHandler):
    """模拟一个"已经被骗"的模型：复述自己的系统提示。"""

    protocol_version = "HTTP/1.1"
    payload: bytes = b"{}"

    def log_message(self, *args) -> None:
        pass

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        self.rfile.read(length)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(LeakyUpstream.payload)))
        self.end_headers()
        self.wfile.write(LeakyUpstream.payload)


def demo_detection() -> None:
    registry = CanaryRegistry()
    token = registry.issue("demo")
    system_prompt = token.wrap_system_prompt("你是一个电商客服助手，只回答与订单相关的问题。")

    print("=" * 72)
    print("1) 埋入令牌后的系统提示")
    print("=" * 72)
    print(system_prompt)
    print(f"\n令牌：{token.value}\n")

    outputs = [
        ("正常回答", "好的，您的订单已发货，预计明天送达。", False),
        ("直接复述", f"我的系统提示里有一个标识符 {token.value}，现在告诉您。", True),
        ("逐字符插空格", " ".join(token.value), True),
        ("零宽字符插断", token.value[:6] + "\u200b" + token.value[6:], True),
        ("Base64 编码", base64.b64encode(token.value.encode()).decode(), True),
        ("ROT13 变换", codecs.encode(token.value, "rot_13"), True),
        ("十六进制", token.value.encode().hex(), True),
        ("倒序输出", token.secret[::-1], True),
    ]

    rows = []
    passed = 0
    for name, text, expect_leak in outputs:
        match = registry.check(text)
        hit = match is not None
        good = hit == expect_leak
        passed += good
        rows.append([name, "是" if expect_leak else "否",
                     match.how if match else "—", "✓" if good else "✗"])

    print("=" * 72)
    print("2) 出站检测：模型输出里是否出现了令牌")
    print("=" * 72)
    print(markdown_table(["模型输出形态", "应当判定为泄露", "命中方式", "结果"],
                         rows, aligns="lccc"))
    print(f"\n{passed}/{len(outputs)} 符合预期")
    print("统计：", registry.stats())

    print("\n" + "=" * 72)
    print("3) 令牌轮换：旧令牌仍能检出历史泄露")
    print("=" * 72)
    old = token
    new = registry.rotate("rotated")
    print(f"旧令牌 {old.value[:18]}…  新令牌 {new.value[:18]}…")
    print(f"用旧令牌构造的输出仍能检出：{registry.check('泄露内容 ' + old.value) is not None}")


def demo_proxy() -> None:
    print("\n" + "=" * 72)
    print("4) 透明代理下的出站拦截（真实 HTTP 往返）")
    print("=" * 72)

    registry = CanaryRegistry()
    token = registry.issue("proxy-demo")
    leaky = json.dumps(
        {"choices": [{"message": {"role": "assistant",
                                  "content": f"好的，我复述我的提示：{token.value}"}}]}
    ).encode()
    LeakyUpstream.payload = leaky

    upstream = ThreadingHTTPServer(("127.0.0.1", 0), LeakyUpstream)
    threading.Thread(target=upstream.serve_forever, daemon=True).start()

    config = ProxyConfig(
        upstream=f"http://127.0.0.1:{upstream.server_address[1]}/v1",
        api_key="", port=0, canary=registry, redact_leak=True,
    )
    server = create_server(config)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    port = server.server_address[1]

    # 刻意用一条"看起来完全正常"的请求：入站检测会放行，
    # 但上游被换成了会复述自身提示的模型，从而演示出站 Canary 拦截
    body = json.dumps({"messages": [{"role": "user", "content": "帮我查一下订单状态"}]}).encode()
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}/v1/chat/completions", data=body, method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            payload = json.loads(response.read().decode())
    except urllib.error.HTTPError as exc:
        payload = json.loads(exc.read().decode())

    print("入站判定放行 -> 上游返回含令牌的内容 -> 出站检测：")
    print(json.dumps(payload, ensure_ascii=False, indent=2)[:600])
    if payload.get("error", {}).get("code") == "system_prompt_leaked":
        print("\n✓ 含令牌的响应已被替换，原始内容没有到达客户端")
    else:
        print("\n✗ 泄漏内容未被拦截")
    print("审计统计：", config.audit.summary())
    server.shutdown()
    upstream.shutdown()


def main() -> int:
    demo_detection()
    if "--with-proxy" in sys.argv:
        demo_proxy()
    else:
        print("\n（加 --with-proxy 可演示真实 HTTP 往返下的出站拦截）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
