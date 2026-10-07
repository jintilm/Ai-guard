"""PINT 形状基准的评测 —— 重点是**过防御**与分语种/分类别的失分定位。

与 `eval_semantic.py` 的分工
---------------------------
- `eval_semantic.py`：三层消融的主脚本（论文实验章节主力），LLM 后端评测也用它。
- 本脚本：不重复造消融框架（复用 eval_semantic 的 `build_pipeline` /
  `stratified_slice` / `CachedSemanticBackend`），只做两件别处没有的事：

  1. **review 口径**。现有所有报告的 FPR 都按 `high/critical` 算，于是「停在
     MEDIUM、需要人工复核」的过防御**完全不可见**。实测（2026-10）正常英文长句会被
     `reglued` 变体压成一条字母 run 触发 `PV-M017`，落在 MEDIUM/REVIEW ——
     在现有口径里 FPR 是 0.000，但在 PINT 那种 93% 良性、含长文档的分布下它才是主要失分。
     本脚本同时给出 block（high+critical）与 review（medium 及以上）两套口径。
  2. **分语种 / 分类别失分**。PINT 公布的是一个总分，看不到「哪个语种、哪一类良性」
     在失分。本脚本按 `category`（含语种后缀）分组，报 recall / FPR / review 率。

用法：
    # 规则侧（快、零调用、离线可跑）
    python scripts/eval_pint_shape.py
    python scripts/eval_pint_shape.py --dataset data/pint_recall.jsonl --out reports/pint_recall.json

    # 加语义层（本地 DeBERTa，默认不带 --semantic-backend 就不加载，避免误触发 LLM 花钱）
    python scripts/eval_pint_shape.py --semantic-backend local --groups "L1 仅规则,L1+L2 规则+启发,L3 仅语义"

    # LLM 后端：先算额度，再用分层抽样 + 硬上限
    python scripts/eval_pint_shape.py --semantic-backend custom --sample 45 --max-llm-calls 45
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from eval_semantic import CachedSemanticBackend, build_pipeline, stratified_slice  # noqa: E402

from prompt_ids.core.types import Level  # noqa: E402
from prompt_ids.eval.datasets import Dataset  # noqa: E402
from prompt_ids.eval.metrics import BLOCK_LEVELS, Confusion, latency_stats, markdown_table  # noqa: E402

REPORT_DIR = ROOT / "reports"

#: review 口径：medium 及以上就要人工看一眼。生产上真正伤用户的是这一档，
#: 因为它不是「误拦」而是「误拦进人工队列」，但同样表现为「正常请求被判成攻击」。
REVIEW_LEVELS = frozenset({"medium", "high", "critical"})

RULE_GROUPS = {
    "L1 仅规则": dict(use_rule=True, use_heuristic=False),
    "L1+L2 规则+启发": dict(use_rule=True, use_heuristic=True),
}


def _levels(sample) -> tuple[str, str]:
    """把 category 拆成 (类别, 语种)。语料构建时就是 `category:lang` 的写法。"""
    parts = sample.category.split(":")
    return (parts[0], parts[1] if len(parts) > 1 else "?")


def _top_patterns(rows: list[dict], levels: frozenset[str], limit: int = 3) -> list[dict]:
    """被标记的样本里，命中规则出现频次 TopN —— 定位「谁在误伤」的第一手证据。"""
    counter: Counter[str] = Counter()
    for r in rows:
        if r["level"] in levels:
            counter.update(r.get("patterns") or [])
    return [{"pattern": pid, "hits": n} for pid, n in counter.most_common(limit)]


def run_group(name: str, spec: dict, dataset: Dataset, max_llm_calls: int = 0) -> dict:
    pipeline = build_pipeline(**spec)
    pipeline.warmup()  # 冷启动不计入延迟统计

    det = pipeline.semantic_detector
    before = det.calls if det else 0

    rows: list[dict] = []
    scanned = 0
    truncated = False
    total = len(dataset)
    step = max(1, total // 10)
    for index, sample in enumerate(dataset, 1):
        if det and max_llm_calls and (det.calls - before) >= max_llm_calls:
            truncated = True
            break
        result = pipeline.scan(sample.text)
        # ScanResult.latency_ms 是分层的字典（preprocess/rule/heuristic/semantic/total），
        # 没有 total 时退回求和
        lat = result.latency_ms or {}
        rows.append({
            "label": sample.label,
            "category": sample.category,
            "source": sample.source,
            "level": result.level.value if isinstance(result.level, Level) else str(result.level),
            "ms": float(lat.get("total") or sum(lat.values())),
            # 命中的 pattern id：良性样本被标记时，直接告诉你是哪条规则在误伤
            "patterns": [getattr(f, "pattern_id", f.detector) for f in result.findings],
        })
        scanned += 1
        if index % step == 0:
            print(f"    {name}: {index}/{total}")

    def view(levels: frozenset[str], subset: list[dict] | None = None) -> dict:
        data = subset if subset is not None else rows
        c = Confusion.from_pairs([r["label"] for r in data],
                                  [1 if r["level"] in levels else 0 for r in data])
        row = c.as_row()
        row["flagged_rate"] = round((c.tp + c.fp) / c.total, 4) if c.total else 0.0
        row["top_patterns"] = _top_patterns(data, levels)
        return row

    by_category: dict[str, list[dict]] = {}
    for row in rows:
        by_category.setdefault(row["category"], []).append(row)

    lang_of = {s.category: _levels(s)[1] for s in dataset.samples}
    report = {
        "confusion": view(BLOCK_LEVELS),
        "review_view": view(REVIEW_LEVELS),
        "latency_ms": latency_stats([r["ms"] for r in rows]),
        "scanned": scanned,
        "truncated": truncated,
        "by_category": {
            cat: {"lang": lang_of.get(cat, "?"), "block": view(BLOCK_LEVELS, sub),
                  "review": view(REVIEW_LEVELS, sub), "n": len(sub)}
            for cat, sub in sorted(by_category.items())
        },
        "semantic_calls": (det.calls - before) if det else 0,
    }
    if det is not None:
        report["semantic"] = det.stats()
    return report


def _fmt(row: dict) -> list[str]:
    return [f"{row['precision']:.4f}", f"{row['recall']:.4f}", f"{row['f1']:.4f}",
            f"{row['false_positive_rate']:.4f}", f"{row['accuracy']:.4f}", str(row["tp"]),
            str(row["fp"]), str(row["tn"]), str(row["fn"])]


HEAD = ["P", "R", "F1", "FPR", "Acc", "TP", "FP", "TN", "FN"]


def main() -> int:
    parser = argparse.ArgumentParser(description="PINT 形状基准评测（过防御 + 分语种/分类别）")
    parser.add_argument("--dataset", default=str(ROOT / "data" / "pint_shape_full.jsonl"))
    parser.add_argument("--out", default=str(REPORT_DIR / "pint_shape.json"))
    parser.add_argument("--groups", default=",".join(RULE_GROUPS),
                        help="逗号分隔；默认只跑规则侧（零调用）")
    parser.add_argument("--semantic-backend", default="",
                        help="给了才加跑语义组（如 local / lightweight / custom）。"
                             "不传则完全不加载模型，避免误触发 LLM 计费")
    parser.add_argument("--semantic-timeout", type=float, default=0.0, help="0 = 用后端默认")
    parser.add_argument("--cache", default="", help="语义结果缓存文件（LLM 后端强烈建议给）")
    parser.add_argument("--sample", type=int, default=0, help="分层抽样条数（LLM 后端按次计费用）")
    parser.add_argument("--seed", type=int, default=20261001)
    parser.add_argument("--max-llm-calls", type=int, default=0, help="硬上限，到点即停并标 truncated")
    args = parser.parse_args()

    data = Dataset.from_jsonl(Path(args.dataset))
    if args.sample:
        data = stratified_slice(data, args.sample, args.seed)
    attacks = sum(1 for s in data.samples if s.label == 1)
    print(f"数据集：{args.dataset}")
    print(f"样本 {len(data)} 条（攻击 {attacks} / 正常 {len(data) - attacks}，占比 {attacks/len(data):.1%}）\n")

    groups = dict(RULE_GROUPS)
    if args.semantic_backend:
        overrides = {"backend": args.semantic_backend}
        if args.semantic_timeout:
            overrides["timeout_s"] = args.semantic_timeout
        groups["L1+L2+L3 (fallback 门禁)"] = dict(
            use_rule=True, use_heuristic=True, semantic={"mode": "fallback", "enabled": True, **overrides})
        groups["L1+L2+L3 (always 全量)"] = dict(
            use_rule=True, use_heuristic=True, semantic={"mode": "always", "enabled": True, **overrides})
        groups["L3 仅语义"] = dict(
            use_rule=False, use_heuristic=False, semantic={"mode": "always", "enabled": True, **overrides})

    wanted = [g.strip() for g in args.groups.split(",") if g.strip()]
    unknown = [g for g in wanted if g not in groups]
    if unknown:
        # 响亮失败：静默跳过会让「少跑了一组」这件事看不出来
        raise SystemExit(f"未知组 {unknown}；可选：{list(groups)}")

    # ⚠ 只记文件名，不记绝对路径（理由同 `engine_ab.py`）。
    report: dict = {"dataset": Path(args.dataset).name, "n": len(data), "attacks": attacks, "groups": {}}
    for name in wanted:
        print(f"  运行 {name} ...")
        spec = dict(groups[name])
        if spec.get("semantic") and args.cache:
            from prompt_ids.detectors.semantic.factory import build_backend

            backend = build_backend(spec["semantic"]["backend"],
                                    timeout_s=args.semantic_timeout or None)
            spec["semantic"]["backend"] = CachedSemanticBackend(backend, Path(args.cache))
        report["groups"][name] = run_group(name, spec, data, args.max_llm_calls)

    print("\n## block 口径（判定阈 = high/critical，与既有所有报告一致）")
    table = [_fmt(g["confusion"]) for g in report["groups"].values()]
    print(markdown_table(["组"] + HEAD, [[n] + r for n, r in zip(report["groups"], table)], "l" + "r" * 9))
    print("\n## review 口径（判定阈 = medium 及以上；这一档是人工复核队列的入口）")
    table = [_fmt(g["review_view"]) for g in report["groups"].values()]
    print(markdown_table(["组"] + HEAD, [[n] + r for n, r in zip(report["groups"], table)], "l" + "r" * 9))

    last_name = wanted[-1]
    last = report["groups"][last_name]
    by_cat = last["by_category"]

    # 攻击类别：跨语种合并（每类只有 ~30 条，逐语种拆开样本太薄）
    agg: dict[str, dict] = {}
    for cat, info in by_cat.items():
        base = cat.split(":")[0]
        bucket = agg.setdefault(base, {"n": 0, "btp": 0, "bfn": 0, "bn": 0, "bfp": 0,
                                       "rtp": 0, "rtn": 0, "langs": set()})
        b, r = info["block"], info["review"]
        bucket["n"] += info["n"]
        bucket["btp"] += b["tp"]
        bucket["bfn"] += b["fn"]
        bucket["bn"] += b["fp"] + b["tn"]
        bucket["bfp"] += b["fp"]
        bucket["rtp"] += r["tp"]
        bucket["rtn"] += r["tp"] + r["fn"]
        bucket["langs"].add(info["lang"])

    attack_rows = []
    for cat, b in sorted(agg.items()):
        if not (b["btp"] + b["bfn"]):
            continue
        n_atk = b["btp"] + b["bfn"]
        attack_rows.append([
            cat, "/".join(sorted(x for x in b["langs"] if x != "?")), str(n_atk),
            f"{b['btp'] / n_atk:.3f}", f"{b['rtp'] / n_atk:.3f}",
            f"{b['bfp'] / b['bn']:.4f}" if b["bn"] else "—",
        ])
    print(f"\n## 攻击类别召回（组：{last_name}；跨语种合并）")
    print(markdown_table(["类别", "语种", "n", "召回(block)", "召回(review)", "FPR"],
                         attack_rows, "llrrrr"))

    benign_rows = []
    for cat, b in sorted(agg.items()):
        if not b["bn"]:
            continue
        info = by_cat[next(c for c in by_cat if c.split(":")[0] == cat)]
        tops = ", ".join(f"{t['pattern']}×{t['hits']}" for t in info["review"]["top_patterns"]) or "-"
        benign_rows.append([
            cat, str(b["bn"]), f"{b['bfp'] / b['bn']:.4f}",
            f"{(b['rtp'] - b['btp']) / b['bn']:.4f}", tops,
        ])
    print("\n## 良性类别的过防御（block FPR 与 review-only FPR 分开；后者是人工复核队列的入口）")
    print(markdown_table(["类别", "n", "FPR(block)", "FPR(review only)", "命中规则 TopN"],
                         benign_rows, "lrrrr"))

    lang_agg: dict[str, dict] = {}
    for cat, info in by_cat.items():
        lang = info["lang"]
        bucket = lang_agg.setdefault(lang, {"atk": 0, "btp": 0, "ben": 0, "bfp": 0, "rtp": 0, "flag": 0})
        b, r = info["block"], info["review"]
        bucket["atk"] += b["tp"] + b["fn"]
        bucket["btp"] += b["tp"]
        bucket["ben"] += b["fp"] + b["tn"]
        bucket["bfp"] += b["fp"]
        bucket["rtp"] += r["tp"]
        bucket["flag"] += r["tp"] + r["fp"]
    lang_rows = []
    for lang, b in sorted(lang_agg.items()):
        n_atk, n_ben = b["atk"], b["ben"]
        lang_rows.append([
            lang, str(n_atk), f"{b['btp']/n_atk:.3f}" if n_atk else "—",
            str(n_ben), f"{b['bfp']/n_ben:.4f}" if n_ben else "—",
            f"{b['rtp']/n_atk:.3f}" if n_atk else "—",
            f"{b['flag']/(n_atk+n_ben):.4f}",
        ])
    print(f"\n## 分语种（{last_name}）")
    print(markdown_table(["语种", "攻击 n", "召回(block)", "良性 n", "FPR(block)",
                          "召回(review)", "review 标记率"], lang_rows, "lrrrrrr"))

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\nJSON 已保存 -> {out}")
    print("口径提醒：良性以长文档为主（手写良性 bank 只有约 250 条，撑不起 PINT 的 93% 良性），")
    print("          因此本基准的绝对值不能与 PINT 公布分相减，只能比形状与失分结构。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())