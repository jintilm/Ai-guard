"""看板冒烟校验：用真实 JS 引擎执行内联脚本，确认渲染出内容而非空白。

静态页面最容易出的错是「HTML 结构正确但 JS 报错导致表格空白」，
这类问题只有真跑一遍才抓得到。

    python scripts/check_dashboard.py
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HTML = ROOT / "reports" / "dashboard.html"
NODE = r"D:\Software\nodejs\node.exe"


def main() -> int:
    if not HTML.exists():
        print("看板不存在，先运行 python -m prompt_ids.web")
        return 1
    html = HTML.read_text(encoding="utf-8")
    script = re.search(r"<script>(.*?)</script>", html, re.S).group(1)

    # 最小 DOM 桩：记录每个 id 被写入的内容
    harness = """
const store = {};
globalThis.window = globalThis;
globalThis.document = {
  getElementById: (id) => ({
    set innerHTML(v){ store[id] = v; }, get innerHTML(){ return store[id] || ''; },
    set textContent(v){ store[id] = v; }, get textContent(){ return store[id] || ''; },
    style: {},
  }),
};
"""
    runner = harness + script + "\nconsole.log(JSON.stringify(store));"
    proc = subprocess.run([NODE, "-e", runner], capture_output=True, text=True, timeout=60)
    if proc.returncode != 0:
        print("JS 执行失败：")
        print(proc.stderr[:800])
        return 1

    store = json.loads(proc.stdout.strip().splitlines()[-1])
    checks = {
        "ablation-body": ("消融表格", lambda v: v.count("<tr") >= 3),
        "best-note": ("核心结论", lambda v: "F1" in v),
        "source-list": ("分数据源对比", lambda v: v.count("<li") >= 3),
        "rule-chips": ("规则库构成", lambda v: "chip" in v),
        "dataset-list": ("数据集构成", lambda v: v.count("<li") >= 2),
    }
    ok = 0
    for key, (name, test) in checks.items():
        value = store.get(key, "")
        passed = bool(value) and test(value)
        ok += passed
        print(f"[{'OK  ' if passed else 'FAIL'}] {name:<12} 长度 {len(value)}")
        if not passed:
            print(f"       内容: {value[:200]}")
    total = len(checks)
    print(f"\n{ok}/{total} 个区域渲染成功")
    if store.get("ablation-body"):
        first = re.sub(r"<[^>]+>", " ", store["ablation-body"]).split()
        print("表格首行：", " ".join(first[:8]))
    return 0 if ok == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
