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
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HTML = ROOT / "reports" / "dashboard.html"

#: 优先用 PATH 上的 node（`shutil.which`），再退回**平台标准安装位置**。
#:
#: ⚠ 绝不写死某个开发机的路径 —— 那等于把本机用户名、盘符、包管理器的
#:   私有目录发布到公开仓库里（既泄露信息，也让别人的 checkout 里
#:   留一段永不生效的死代码）。
NODE_CANDIDATES = (
    "node",
    # Windows 的标准安装位置（nodejs.org MSI 默认路径）
    r"C:\Program Files\nodejs\node.exe",
    r"C:\Program Files (x86)\nodejs\node.exe",
    "/usr/local/bin/node",
    "/usr/bin/node",
    "/opt/homebrew/bin/node",
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

    # ⚠ **数字必须从报告现算，不能硬编码。**
    # 踩过：`indirect-body` 断言 `"0.2583" in v`（120 样本的旧读数），后来把
    # 报告换成 n=250 的 0.1960 时忘了改这条断言 ⇒ 看板检查**一直是红的**，
    # 而失败信息长得像「这张卡片没渲染出来」，很容易被当成渲染问题放过去。
    # 硬编码测量值的检查有一个共同毛病：每次重跑报告都可能变红，而红的原因
    # 与「卡片没画出来」完全不同。现算之后它守的不变式才是真正值得守的那个：
    # **看板显示的数字 == 报告里的数字**。
    def from_report(relative: str, *path: str, fmt: str = "{:.4f}") -> str | None:
        target = ROOT / "reports" / relative
        if not target.exists():
            return None
        node = json.loads(target.read_text(encoding="utf-8"))
        for key in path:
            if not isinstance(node, dict) or key not in node:
                return None
            node = node[key]
        return fmt.format(node) if isinstance(node, (int, float)) else None

    # 卡片显示名（原 checks 的第一个元素，保持控制台输出不变）
    CARD_NAMES = {
        "indirect-body": "间接注入面", "agent-body": "agent 面",
        "policy-body": "分角色策略", "output-body": "出站检测",
        "sweep-body": "策略影响", "knee-body": "阈值取舍",
    }

    # (报告, 取值路径, 格式) -> 期望出现在渲染结果里的字符串
    expected = {
        "indirect-body": from_report("indirect.json", "shapes", "tool_only",
                                     "scan_tool", "block_recall"),
        "agent-body": from_report("agent_check.json", "runs", "rules_tool",
                                  "attack_block_recall"),
        "policy-body": from_report("agent_check.json", "rag_traffic",
                                   "system_rules_only", "block_rate"),
        "output-body": from_report("output_scan.json", "synthetic", "caught",
                                   fmt="{:.0f}"),
        "output-corpus": from_report("output_scan.json", "benign", "groups",
                                     "corpus", "flagged", fmt="{:.0f}"),
        "output-corpus-n": from_report("output_scan.json", "benign", "groups",
                                       "corpus", "n", fmt="{:.0f}"),
        "sweep-body": from_report("threshold_sweep.json", "policies", "default",
                                  "block_recall"),
        "knee-body": from_report("threshold_sweep.json", "knee",
                                 "fpr_at_budget_0_01", "threshold", fmt="{:.2f}"),
    }

    def rows_at_least(key: str, rows: int) -> tuple[str, tuple[str, object]]:
        """行数下限 + 「报告里现算的数字」都要满足；报告缺失时只查行数。"""
        want = expected.get(key)
        label = CARD_NAMES[key]

        def test(value: str) -> bool:
            if value.count("<tr") < rows:
                return False
            return want is None or want in value

        return (key, (label, test))

    def rows_exactly(key: str, rows: int) -> tuple[str, tuple[str, object]]:
        want = expected.get(key)
        label = CARD_NAMES[key]

        def test(value: str) -> bool:
            if value.count("<tr") != rows:
                return False
            return want is None or want in value

        return (key, (label, test))

    checks = {
        "ablation-body": ("消融表格", lambda v: v.count("<tr") >= 3),
        "best-note": ("核心结论", lambda v: "F1" in v),
        "source-list": ("分数据源对比", lambda v: v.count("<li") >= 3),
        "rule-chips": ("规则库构成", lambda v: "chip" in v),
        "dataset-list": ("数据集构成", lambda v: v.count("<li") >= 2),
        "sampling-body": ("取样覆盖", lambda v: v.count("<tr") >= 3 and "%" in v),
        **dict([
            rows_at_least("indirect-body", 3),
            rows_at_least("agent-body", 2),
            rows_exactly("policy-body", 2),
            rows_exactly("output-body", 4),
            rows_exactly("sweep-body", 4),
            rows_exactly("knee-body", 3),
        ]),
    }
    missing = sorted(key for key, value in expected.items() if value is None)
    if missing:
        print(f"[提示] 这些报告缺失，对应卡片只查结构不查数字：{missing}")

    ok = 0
    for key, (name, test) in checks.items():
        value = store.get(key, "")
        # 卡片靠 reports/indirect.json 才出：没这个文件时区域本来就该是空的，
        # 那不算失败（宁可少一张卡，也不要硬凑一个数字）。
        optional = key in ("indirect-body", "sampling-body", "agent-body", "policy-body",
                           "output-body", "sweep-body", "knee-body")
        if optional and not value:
            print(f"[SKIP ] {name:<12} reports/indirect.json 不存在，看板按设计不出这张卡")
            continue
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

    total = sum(1 for key in checks
                if not (key in ("indirect-body", "sampling-body", "agent-body", "policy-body")
                        and not store.get(key))) + 1
    print(f"\n{ok}/{total} 个区域渲染成功")
    if store.get("ablation-body"):
        first = re.sub(r"<[^>]+>", " ", store["ablation-body"]).split()
        print("表格首行：", " ".join(first[:8]))
    return 0 if ok == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
