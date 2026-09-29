"""Web 看板 —— 把项目的实验数据与运行状态整合成一页。

设计上刻意做零外部依赖：图表是内联 SVG，字体回退系统栈，数据全部内联。
生成的 HTML 双击即可打开，也可以直接交作业，不需要联网或起服务。

    python -m prompt_ids.web                       # 生成 reports/dashboard.html
    python -m prompt_ids.web --serve --port 8765   # 起服务并定时刷新
"""
from __future__ import annotations

import argparse
import json
import sys
import threading
import time
import webbrowser
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from prompt_ids.eval.datasets import Dataset  # noqa: E402
from prompt_ids.rules.loader import RuleBook  # noqa: E402

# .../prompt_ids/web/dashboard.py -> parents[2] 才是项目根
ROOT = Path(__file__).resolve().parents[2]
REPORT = ROOT / "reports"
DEFAULT_OUT = REPORT / "dashboard.html"
DEFAULT_ABLATION = REPORT / "ablation.json"

SOURCE_LABELS = {
    "builtin": "自建种子集",
    "deepset_train": "deepset 训练集",
    "deepset_test": "deepset 留出集",
    "garak": "garak 生成集",
}


# ---------------------------------------------------------------- 数据采集
def collect(ablation_path: Path, audit_path: Path | None) -> dict:
    data: dict = {"generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

    if ablation_path.exists():
        data["ablation"] = json.loads(ablation_path.read_text(encoding="utf-8"))
    else:
        data["ablation"] = {}

    book = RuleBook()
    data["rules"] = book.stats()

    for name, path in (("full", "data/full.jsonl"), ("deepset", "data/public_deepset.jsonl")):
        p = ROOT / path
        if p.exists():
            ds = Dataset.from_jsonl(p)
            data.setdefault("datasets", {})[name] = {
                "counts": ds.counts(),
                "by_source": {k: v for k, v in _count_sources(ds).items()},
            }

    if audit_path and audit_path.exists():
        rows = [json.loads(l) for l in audit_path.read_text(encoding="utf-8").splitlines() if l.strip()]
        data["proxy"] = {
            "total": len(rows),
            "by_decision": _tally(rows, "decision"),
            "by_level": _tally(rows, "level"),
            "avg_detect_ms": round(sum(r.get("detect_ms", 0) for r in rows) / max(len(rows), 1), 2),
            "recent": rows[-8:],
        }
    return data


def _count_sources(ds: Dataset) -> dict[str, int]:
    acc: dict[str, int] = {}
    for sample in ds:
        acc[SOURCE_LABELS.get(sample.source, sample.source)] = (
            acc.get(SOURCE_LABELS.get(sample.source, sample.source), 0) + 1
        )
    return acc


def _tally(rows: list[dict], key: str) -> dict[str, int]:
    acc: dict[str, int] = {}
    for row in rows:
        acc[str(row.get(key, "-"))] = acc.get(str(row.get(key, "-")), 0) + 1
    return acc


# ---------------------------------------------------------------- 渲染
CSS = """
:root{
  --bg:#f9fafb; --surface:#ffffff; --line:rgba(24,24,27,.07);
  --ink:#18181b; --ink-2:#52525b; --ink-3:#a1a1aa;
  --accent:#0d9488; --accent-soft:rgba(13,148,136,.10);
  --warn:#b45309; --warn-soft:rgba(180,83,9,.10);
  --mono:'Geist Mono','JetBrains Mono',ui-monospace,SFMono-Regular,Menlo,monospace;
  --sans:'Geist','Satoshi','Outfit',system-ui,-apple-system,'Segoe UI',sans-serif;
}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--ink);font-family:var(--sans);
  -webkit-font-smoothing:antialiased;line-height:1.55;padding:48px 32px 80px}
.wrap{max-width:1280px;margin:0 auto}
.num{font-family:var(--mono);font-variant-numeric:tabular-nums}

/* header：左对齐，非居中 */
header{display:grid;grid-template-columns:1.6fr 1fr;gap:40px;align-items:end;
  padding-bottom:28px;border-bottom:1px solid var(--line);margin-bottom:40px}
h1{font-size:30px;font-weight:600;letter-spacing:-.02em;line-height:1.2}
.sub{color:var(--ink-2);font-size:14px;margin-top:8px;max-width:62ch}
.meta{text-align:right;color:var(--ink-3);font-size:12px}
.meta .num{display:block;font-size:13px;color:var(--ink-2)}

/* KPI：用分隔线分组，不套盒子 */
.kpi{display:grid;grid-template-columns:repeat(4,1fr);gap:0;margin-bottom:44px;
  border:1px solid var(--line);border-radius:20px;overflow:hidden;background:var(--surface)}
.kpi>div{padding:22px 24px;border-right:1px solid var(--line)}
.kpi>div:last-child{border-right:0}
.kpi .k{font-size:11px;letter-spacing:.06em;text-transform:uppercase;color:var(--ink-3)}
.kpi .v{font-size:26px;font-weight:600;letter-spacing:-.02em;margin-top:6px}

/* Bento：不对称网格 */
.bento{display:grid;gap:20px;grid-template-columns:2fr 1fr;margin-bottom:20px}
.bento-2{display:grid;gap:20px;grid-template-columns:1.7fr 1fr;margin-bottom:20px}
.card{background:var(--surface);border:1px solid var(--line);border-radius:20px;padding:28px}
.card h2{font-size:15px;font-weight:600;letter-spacing:-.01em;margin-bottom:4px}
.card .hint{font-size:12.5px;color:var(--ink-3);margin-bottom:20px}

table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;font-weight:500;color:var(--ink-3);font-size:11px;
  letter-spacing:.05em;text-transform:uppercase;padding:0 0 10px;border-bottom:1px solid var(--line)}
td{padding:11px 0;border-bottom:1px solid var(--line);vertical-align:middle}
tr:last-child td{border-bottom:0}
td.n,th.n{text-align:right;font-family:var(--mono);font-variant-numeric:tabular-nums}
.bar{position:relative;height:6px;border-radius:3px;background:rgba(24,24,27,.06);overflow:hidden;min-width:90px}
.bar i{position:absolute;left:0;top:0;bottom:0;border-radius:3px;background:var(--ink-3)}
tr.best td{font-weight:600}
tr.best .bar i{background:var(--accent)}

.note{background:var(--accent-soft);border-radius:14px;padding:18px 20px;font-size:13px;color:#134e4a}
.note strong{display:block;margin-bottom:6px;font-weight:600}
.note.warn{background:var(--warn-soft);color:#7c2d12}

.chips{display:flex;flex-wrap:wrap;gap:8px;margin-top:14px}
.chip{font-size:12px;padding:5px 11px;border-radius:999px;background:rgba(24,24,27,.04);color:var(--ink-2)}
.chip .num{font-size:12px;color:var(--ink)}

ul.mini{list-style:none;font-size:13px}
ul.mini li{display:flex;justify-content:space-between;gap:16px;padding:9px 0;border-bottom:1px solid var(--line)}
ul.mini li:last-child{border-bottom:0}
ul.mini span:last-child{font-family:var(--mono);color:var(--ink-2)}

footer{margin-top:44px;padding-top:22px;border-top:1px solid var(--line);
  color:var(--ink-3);font-size:12px;display:grid;grid-template-columns:1fr 1fr;gap:32px}
footer ul{list-style:none;font-size:12px}
footer li{padding:3px 0}

@media(max-width:960px){
  body{padding:28px 16px 56px}
  header,.bento,.bento-2,.kpi,footer{grid-template-columns:1fr}
  .meta{text-align:left}
  .kpi>div{border-right:0;border-bottom:1px solid var(--line)}
}
.rise{animation:rise .5s cubic-bezier(.2,.7,.3,1) both}
@keyframes rise{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:none}}
"""

JS = """
function bar(v, max, cls){
  var pct = Math.max(2, Math.min(100, v / max * 100));
  return '<div class="bar"><i style="width:' + pct + '%"></i></div>';
}
function render(){
  var d = window.__DATA__, html = '';

  // 消融主表
  var keys = Object.keys(d.ablation || {});
  var rows = keys.map(function(k){
    var c = d.ablation[k].confusion, l = d.ablation[k].latency_ms;
    return {k:k, p:c.precision, r:c.recall, f:c.f1, fpr:c.false_positive_rate,
            p50:l.p50, p95:l.p95, calls:d.ablation[k].semantic_calls||0};
  });
  var best = rows.reduce(function(a,b){ return (b.f > a.f) ? b : a; }, rows[0]);
  var tbody = rows.map(function(x){
    var cls = (x.k === best.k) ? 'class="best"' : '';
    return '<tr '+cls+'><td>'+x.k+'</td>'+
      '<td class="n">'+x.p.toFixed(3)+'</td>'+
      '<td class="n">'+x.r.toFixed(3)+'</td>'+
      '<td class="n">'+x.f.toFixed(3)+' '+bar(x.f,1)+'</td>'+
      '<td class="n">'+x.fpr.toFixed(3)+'</td>'+
      '<td class="n">'+x.p50.toFixed(1)+'</td>'+
      '<td class="n">'+x.p95.toFixed(1)+'</td>'+
      '<td class="n">'+x.calls+'</td></tr>';
  }).join('');
  document.getElementById('ablation-body').innerHTML = tbody;
  document.getElementById('best-note').innerHTML =
    '<strong>最优配置：'+best.k+'</strong>F1 '+best.f.toFixed(3)+
    '，精确率 '+best.p.toFixed(3)+'，误报率 '+best.fpr.toFixed(3)+
    '，语义调用 '+best.calls+' 次。';

  // 分数据源对比：动态挑选"规则层"与"完整流水线"，不依赖具体命名
  var pick = function(want, fallback){ for(var i=0;i<keys.length;i++){
      if(keys[i].indexOf(want)>=0) return keys[i]; } return fallback; };
  var l1Key = keys.filter(function(k){ return k.indexOf('L3')<0; })[0] || keys[0];
  var allKey = pick('always', keys[keys.length-1]);
  var l1g = d.ablation[l1Key]||{}, allg = d.ablation[allKey]||{};

  var srcKeys = {};
  keys.forEach(function(k){
    Object.keys(d.ablation[k].by_source||{}).forEach(function(s){ srcKeys[s]=1; });
  });
  var srcRows = Object.keys(srcKeys).map(function(s){
    var a = (l1g.by_source||{})[s]||{}, b = (allg.by_source||{})[s]||{};
    return '<li><span>'+ (d.labels[s]||s) +'</span><span>规则 '+
      (a.recall||0).toFixed(3)+' → 完整 '+(b.recall||0).toFixed(3)+'</span></li>';
  }).join('');
  var srcHead = document.getElementById('source-head');
  if(srcHead) srcHead.textContent = l1Key + '  →  ' + allKey;
  document.getElementById('source-list').innerHTML = srcRows;

  // 规则库与数据集
  var r = d.rules||{};
  document.getElementById('rule-chips').innerHTML =
    (r.tiers?Object.keys(r.tiers):[]).map(function(k){
      return '<span class="chip">'+k+' <span class="num">'+r.tiers[k]+'</span></span>';
    }).join('') + (r.categories?Object.keys(r.categories).slice(0,8):[]).map(function(k){
      return '<span class="chip">'+k+' <span class="num">'+r.categories[k]+'</span></span>';
    }).join('');

  var ds = (d.datasets||{}).full || (d.datasets||{}).deepset;
  if(ds){
    document.getElementById('dataset-list').innerHTML =
      Object.keys(ds.by_source).map(function(k){
        return '<li><span>'+k+'</span><span>'+ds.by_source[k]+'</span></li>';
      }).join('') +
      '<li><span><b>合计</b></span><span><b>'+ds.counts.total+'</b>（攻击 '+
      ds.counts.attack+' / 正常 '+ds.counts.benign+'）</span></li>';
  }
  if(d.proxy){
    document.getElementById('proxy-card').style.display='';
    document.getElementById('proxy-list').innerHTML =
      '<li><span>请求总数</span><span>'+d.proxy.total+'</span></li>' +
      Object.keys(d.proxy.by_decision).map(function(k){
        return '<li><span>'+k+'</span><span>'+d.proxy.by_decision[k]+'</span></li>';
      }).join('') +
      '<li><span>平均检测耗时</span><span>'+d.proxy.avg_detect_ms+' ms</span></li>';
  }
}
render();
"""


def render_html(data: dict) -> str:
    payload = json.dumps(data, ensure_ascii=False)
    rules = data.get("rules", {})
    ds = (data.get("datasets") or {}).get("full") or {}
    best = ""
    if data.get("ablation"):
        best = max(data["ablation"].items(), key=lambda kv: kv[1]["confusion"]["f1"])[0]

    kpis = _kpis(data, best)
    return f"""<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>提示词注入检测系统 · 运行看板</title>
<style>{CSS}</style></head>
<body><div class="wrap">

<header class="rise">
  <div>
    <h1>提示词注入检测系统</h1>
    <p class="sub">四级级联流水线（归一化 → 解码展开 → L1 规则 / L2 启发 / L3 语义 → 融合决策）
    在公开数据集上的实验数据与运行状态。判定阈为 high / critical 记预测攻击。</p>
  </div>
  <div class="meta">
    生成时间<span class="num">{data['generated_at']}</span>
    规则库<span class="num">{rules.get('total', 0)} 条 · 中英德三语</span>
  </div>
</header>

<section class="kpi rise">{kpis}</section>

<section class="bento rise">
  <div class="card">
    <h2>三层消融对比</h2>
    <p class="hint">Precision / Recall / F1 / 误报率 / 延迟分位 / 语义层调用次数</p>
    <table>
      <thead><tr><th>配置</th><th class="n">P</th><th class="n">R</th>
        <th class="n">F1</th><th class="n">误报率</th><th class="n">P50</th>
        <th class="n">P95</th><th class="n">语义调用</th></tr></thead>
      <tbody id="ablation-body"></tbody>
    </table>
  </div>
  <div class="card">
    <h2>核心结论</h2>
    <p class="hint">为什么需要三层，而不是只用一层</p>
    <div class="note" id="best-note"></div>
    <div class="note warn" style="margin-top:14px">
      <strong>自建集会高估系统能力</strong>
      规则层在自建种子集上召回 0.72，换到从未参与调参的 deepset 留出集只剩 0.10。
      所有结论以公开集为准。
    </div>
  </div>
</section>

<section class="bento-2 rise">
  <div class="card">
    <h2>同一套配置在不同数据源上的召回</h2>
    <p class="hint" id="source-head">规则层 → 完整流水线（含语义层）</p>
    <ul class="mini" id="source-list"></ul>
  </div>
  <div class="card">
    <h2>规则库构成</h2>
    <p class="hint">档位与攻击类别分布</p>
    <div class="chips" id="rule-chips"></div>
    <h2 style="margin-top:26px">评测集构成</h2>
    <p class="hint">deepset + garak + 内置种子</p>
    <ul class="mini" id="dataset-list"></ul>
  </div>
</section>

<section class="bento rise" id="proxy-card" style="display:none">
  <div class="card">
    <h2>透明代理运行概览</h2>
    <p class="hint">来自审计日志（只记录指纹，不落原文）</p>
    <ul class="mini" id="proxy-list"></ul>
  </div>
  <div class="card">
    <h2>已知限制</h2>
    <p class="hint">答辩前需要主动说明的部分</p>
    <ul class="mini">
      <li><span>启发层语言偏置</span><span>特征词为英文</span></li>
      <li><span>轻量模型数据重叠</span><span>仅 CV 可信</span></li>
      <li><span>LLM 裁判未连通</span><span>缺 API Key</span></li>
      <li><span>DeBERTa 冷启动</span><span>约 35s</span></li>
    </ul>
  </div>
</section>

<footer>
  <ul>
    <li>数据源：deepset/prompt-injections（662）+ NVIDIA/garak（70）+ 内置种子（85）</li>
    <li>规则迭代只使用 deepset train，留出集全程不参与调参</li>
  </ul>
  <ul>
    <li>语义模型：protectai/deberta-v3-base-prompt-injection-v2（CPU 推理）</li>
    <li>本页为静态快照，重新生成：python -m prompt_ids.web</li>
  </ul>
</footer>

<script>window.__DATA__ = {payload};
window.__DATA__.labels = {json.dumps(SOURCE_LABELS, ensure_ascii=False)};
{JS}</script>
</div></body></html>"""


def _kpis(data: dict, best: str) -> str:
    abl = data.get("ablation") or {}
    total = (data.get("datasets") or {}).get("full", {}).get("counts", {}).get("total", 0)
    items = []
    if abl and best:
        c = abl[best]["confusion"]
        items += [
            ("最优配置 F1", f'{c["f1"]:.3f}', best),
            ("最优配置误报率", f'{c["false_positive_rate"]:.3f}', "越低越好"),
        ]
    items += [
        ("评测样本", str(total), "攻击 / 正常混合"),
        ("规则库", f'{data.get("rules", {}).get("total", 0)}', "三档分级"),
    ]
    return "".join(
        f'<div><div class="k">{k}</div><div class="v num">{v}</div>'
        f'<div style="font-size:11.5px;color:var(--ink-3);margin-top:2px">{note}</div></div>'
        for k, v, note in items
    )


# ---------------------------------------------------------------- 入口
def build(ablation_path: Path, out: Path, audit_path: Path | None) -> Path:
    data = collect(ablation_path, audit_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render_html(data), encoding="utf-8")
    return out


def serve(out: Path, port: int, refresh_s: int, ablation: Path, audit: Path | None) -> None:  # pragma: no cover
    from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

    class Handler(SimpleHTTPRequestHandler):
        def __init__(self, *a, **kw):
            super().__init__(*a, directory=str(out.parent), **kw)

        def log_message(self, *args) -> None:
            pass

    def rebuild():
        build(ablation, out, audit)
        print(f"[{time.strftime('%H:%M:%S')}] 已刷新 {out.name}")

    rebuild()
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    # 监听必须在独立线程里跑，主线程负责定时重新生成
    threading.Thread(target=server.serve_forever, daemon=True).start()
    print(f"看板已启动 http://127.0.0.1:{port}/{out.name}  （每 {refresh_s}s 刷新）")
    try:
        webbrowser.open(f"http://127.0.0.1:{port}/{out.name}")
    except Exception:
        pass
    try:
        while True:
            time.sleep(refresh_s)
            rebuild()
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
        server.server_close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="生成 Web 看板")
    parser.add_argument("--out", default=str(DEFAULT_OUT))
    parser.add_argument("--ablation", default=str(DEFAULT_ABLATION))
    parser.add_argument("--audit", default="", help="代理审计日志路径（JSONL）")
    parser.add_argument("--serve", action="store_true", help="起本地服务并定时刷新")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--refresh", type=int, default=15)
    args = parser.parse_args(argv)

    out = Path(args.out)
    ablation = Path(args.ablation)
    audit = Path(args.audit) if args.audit else None

    if args.serve:
        serve(out, args.port, args.refresh, ablation, audit)
        return 0

    path = build(ablation, out, audit)
    size = path.stat().st_size
    print(f"看板已生成 -> {path}  ({size / 1024:.1f} KB)")
    print("直接用浏览器打开即可，无需联网或起服务。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
