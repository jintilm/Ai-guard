"""看板冒烟校验：用真实 JS 引擎执行内联脚本，确认渲染出内容而非空白。

静态页面最容易出的错是「HTML 结构正确但 JS 报错导致表格空白」，
这类问题只有真跑一遍才抓得到。检测台的 JS 同理 —— 它还要在
「服务连不上」时自己切到离线说明态，这段分支也得真跑一次才算验证过。

    python scripts/check_dashboard.py
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HTML = ROOT / "reports" / "dashboard.html"

#: 优先用 PATH 上的 node，再退回本机已知位置（别把开发机的路径写死成唯一解）
NODE_CANDIDATES = (
    "node",
    r"D:\Software\nodejs\node.exe",
    r"C:\Users\lin\.workbuddy\binaries\node\versions\22.22.2-3\node.exe",
)


def find_node() -> str | None:
    for candidate in NODE_CANDIDATES:
        found = shutil.which(candidate) if not candidate.endswith(".exe") else (
            candidate if Path(candidate).exists() else None)
        if found:
            return found
    return None


#: 够用的 DOM 桩。刻意把 addEventListener / style / fetch 都补上 ——
#: 只支持 innerHTML 的桩会让检测台的 JS 直接抛 TypeError，
#: 于是「真跑一遍」这件事本身就失效了。
HARNESS = r"""
const store = {}, els = {};
function mkEl(id){
  if (els[id]) return els[id];
  const el = {
    id: id, _html: '', _text: '', value: '', disabled: false,
    style: {},
    addEventListener(){ return el; },
    removeEventListener(){ return el; },
    focus(){}, blur(){},
    getAttribute(){ return ''; }, setAttribute(){},
    classList: { add(){}, remove(){}, toggle(){}, contains(){ return false; } },
  };
  Object.defineProperty(el, 'innerHTML', {
    get(){ return el._html; }, set(v){ el._html = String(v); store[id] = el._html; }
  });
  Object.defineProperty(el, 'textContent', {
    get(){ return el._text; }, set(v){ el._text = String(v); store[id] = el._text; }
  });
  els[id] = el;
  return el;
}
globalThis.window = globalThis;
globalThis.document = {
  getElementById: (id) => mkEl(id),
  querySelectorAll: () => [],
  querySelector: () => null,
  addEventListener(){},
};
// 静态打开：探活必然失败，正好验证「切到离线说明」这条分支。
// 返回 rejected promise 而不是不定义 —— 不定义会抛 ReferenceError，
// 那样测的就不是降级路径而是语法错误了。
globalThis.fetch = () => Promise.reject(new Error('offline'));
"""

FOOTER = r"""
setTimeout(() => {
  console.log('__RESULT__' + JSON.stringify({
    store: store,
    display: {
      'pg-panel': (els['pg-panel'] || {}).style ? els['pg-panel'].style.display : undefined,
      'pg-offline': (els['pg-offline'] || {}).style ? els['pg-offline'].style.display : undefined,
    },
  }));
}, 60);
"""


def main() -> int:
    if not HTML.exists():
        print("看板不存在，先运行 python -m prompt_ids.web")
        return 1
    node = find_node()
    if not node:
        print("未找到 node，跳过（这是可选的渲染校验，不影响看板本身）")
        return 0

    html = HTML.read_text(encoding="utf-8")
    script = re.search(r"<script>(.*?)</script>", html, re.S).group(1)

    # 写到临时文件再跑：整段脚本有 20KB+，走 -e 会撞 Windows 命令行长度上限
    with tempfile.TemporaryDirectory() as tmp:
        runner = Path(tmp) / "runner.js"
        runner.write_text(HARNESS + script + FOOTER, encoding="utf-8")
        proc = subprocess.run([node, str(runner)], capture_output=True, text=True, timeout=90)

    if proc.returncode != 0:
        print("JS 执行失败：")
        print(proc.stderr[:1200])
        return 1

    line = next((ln for ln in proc.stdout.splitlines() if ln.startswith("__RESULT__")), None)
    if not line:
        print("JS 没有产出结果：")
        print(proc.stdout[:600])
        return 1

    payload = json.loads(line[len("__RESULT__"):])
    store, display = payload["store"], payload["display"]

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

    # 离线降级：面板隐藏、说明显示 —— 用户看到的必须是「怎么开启」而不是空白
    offline_ok = display.get("pg-panel") == "none" and display.get("pg-offline") == ""
    ok += offline_ok
    print(f"[{'OK  ' if offline_ok else 'FAIL'}] {'检测台离线降级':<10} "
          f"panel={display.get('pg-panel')!r} offline={display.get('pg-offline')!r}")

    total = len(checks) + 1
    print(f"\n{ok}/{total} 个区域渲染成功")
    if store.get("ablation-body"):
        first = re.sub(r"<[^>]+>", " ", store["ablation-body"]).split()
        print("表格首行：", " ".join(first[:8]))
    return 0 if ok == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
