"""阈值标定与策略影响模拟 —— 「把判定阈挪一格，谁会受影响」。

为什么要有这个脚本
------------------
本项目所有既有报告的判定阈都是**固定**的（block = high/critical，即「生产默认」），
于是「如果我把阈调到 X 会怎样」「如果我换成 strict 策略会怎样」这两个问题
在整个仓库里没有任何数字可以回答。同类系统里 Lakera / Check Point 的
Policy Impact Simulator 就是干这个的，本脚本是它的离线对位物。

两条轴，都要算，且**都必须说清是假设还是现状**
------------------------------------------
1. **分数阈 T**（假设）：`score >= T` 即判为攻击。这是**假设** ——
   生产上判定走的是 `verdict` 的 `level → action` 映射，level 由融合层给，
   不存在「把分数阈调到 40」这个开关。这条轴的价值是看**取舍曲线**，
   以及「想要 FPR ≤ 0.01 的话，分数得压到多少」。
2. **policy**（现状）：default / strict / permissive / log-only 四档，
   这四个是**真实存在**的策略，`Policy.action_for` 直接给出动作。
   这条轴回答「同一批流量，换个策略会误拦多少、会漏放多少」。

口径纪律
--------
- 分数是**浮点**，不做四舍五入到整数（`round()` 会把 83.71 与 83.4 抹成同一个点）。
- 阈值网格取**实际出现过的分数值**，不取人造的 0/10/20/…：
  人造网格会在分数扎堆的地方（规则层大量命中给出同一个分）漏掉整段台阶。
- FPR 的分母是**良性样本数**，与既有报告一致。
- 报告写入 `reports/threshold_sweep.json`，含全部阈值点；控制台只打台阶点。

用法：
    python scripts/threshold_sweep.py                                # 规则层 + 启发层，公开集
    python scripts/threshold_sweep.py --dataset data/full.jsonl
    python scripts/threshold_sweep.py --semantic-backend local      # 加语义层（慢）
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.stdout.reconfigure(encoding="utf-8")

from eval_semantic import CachedSemanticBackend, build_pipeline, stratified_slice  # noqa: E402

from prompt_ids.core.policy import BUILTIN_POLICIES  # noqa: E402
from prompt_ids.core.types import Action, Level  # noqa: E402
from prompt_ids.eval.datasets import Dataset  # noqa: E402

REPORT_DIR = ROOT / "reports"
BLOCK_ACTIONS = {Action.BLOCK.value, Action.SANDBOX.value}
HUMAN_ACTIONS = {Action.REVIEW.value}


def scan_all(pipeline, data: Dataset, max_calls: int = 0) -> list[dict]:
    """扫一遍，把每条样本的 (score, label, level) 收下来。

    一次扫描、多个阈值复用：阈值标定不该重复付推理成本
    （LLM 后端按次计费，重复扫 = 重复花钱）。
    """
    rows: list[dict] = []
    calls = 0
    started = time.perf_counter()
    for sample in data:
        result = pipeline.scan(sample.text, user="sweep")
        detector = getattr(pipeline.semantic_detector, "calls", 0) if pipeline.semantic_detector else 0
        calls = max(calls, int(detector))
        rows.append({
            "score": float(result.score),
            "label": int(sample.label),
            "level": result.level.value,
            "source": sample.source,
        })
        if max_calls and calls >= max_calls:
            break
    elapsed = (time.perf_counter() - started) * 1000
    return rows, calls, elapsed


def sweep_threshold(rows: list[dict], thresholds: list[float]) -> list[dict]:
    out = []
    for t in thresholds:
        tp = fp = tn = fn = 0
        for row in rows:
            flagged = row["score"] >= t
            if row["label"] and flagged:
                tp += 1
            elif row["label"]:
                fn += 1
            elif flagged:
                fp += 1
            else:
                tn += 1
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        benign = fp + tn
        out.append({
            "threshold": round(t, 4),
            "tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "fpr": round(fp / benign, 4) if benign else 0.0,
            "blocked_share": round((tp + fp) / len(rows), 4) if rows else 0.0,
        })
    return out


def policy_impact(rows: list[dict]) -> dict:
    """四档策略在**同一批分数/等级**上的动作分布与后果。

    level 是检测层给的、与策略无关；策略只决定 level → action 的映射
    （`Policy.action_for`），所以一次扫描就能算出四档策略的影响。

    ⚠ **`sandbox` 不算拦截**：`default` 把 high 映射成 sandbox，而 sandbox 的语义是
    「放行 + 记审计」（HTTP 200），只有 `--block-sandbox` 才真的拦。把 sandbox
    计进「拦截」会把召回虚高 —— 本项目 README 的决策表里写明了这一点，
    脚本不能比文档更乐观。
    """
    attacks = sum(r["label"] for r in rows)
    benign = len(rows) - attacks
    total = max(len(rows), 1)
    out: dict = {}
    for name, policy in BUILTIN_POLICIES.items():
        actions: Counter = Counter()
        blocked_attack = blocked_benign = sandbox_benign = review_benign = 0
        for row in rows:
            action = policy.action_for(Level(row["level"])).value
            actions[action] += 1
            if row["label"]:
                if action == Action.BLOCK.value:
                    blocked_attack += 1
            elif action == Action.BLOCK.value:
                blocked_benign += 1
            elif action == Action.SANDBOX.value:
                sandbox_benign += 1
            elif action in HUMAN_ACTIONS:
                review_benign += 1
        out[name] = {
            "actions": dict(actions),
            "blocked_attack": blocked_attack,
            "blocked_benign": blocked_benign,
            "sandbox_benign": sandbox_benign,
            "review_benign": review_benign,
            "block_recall": round(blocked_attack / attacks, 4) if attacks else 0.0,
            "block_fpr": round(blocked_benign / benign, 4) if benign else 0.0,
            "sandbox_share": round(sandbox_benign / benign, 4) if benign else 0.0,
            "review_share": round(review_benign / benign, 4) if benign else 0.0,
            "blocked_share": round((blocked_attack + blocked_benign) / total, 4),
        }
    return out


def pick_knee(curve: list[dict]) -> dict:
    """给三个可操作读数，全部由曲线本身推出，不做人工口味判断。

    - `best_f1`：F1 最大的阈值点（**可能不可用**，见调用处的告警）
    - `fpr_at_budget`：FPR ≤ 0.01（既有报告里 block 口径常用的量级）下召回最高的点
    - `recall_at_zero_fp`：零误报下召回最高的点（良性少时常常存在）

    ⚠ 两个「预算」读数都排除了 `tp == 0` 的点：不排除的话，
    「什么都不拦」这个阈值恒满足 FPR ≤ 0.01，答案会变成「召回 0 的可行点」——
    约束被平凡满足，读数看着合规却毫无用处。
    """
    best_f1 = max(curve, key=lambda r: (r["f1"], -r["fpr"])) if curve else {}
    affordable = [r for r in curve if r["fpr"] <= 0.01 and r["tp"] > 0]
    fpr_at_budget = max(affordable, key=lambda r: r["recall"]) if affordable else {}
    zero_fp = [r for r in curve if r["fp"] == 0 and r["tp"] > 0]
    recall_at_zero_fp = max(zero_fp, key=lambda r: r["recall"]) if zero_fp else {}
    return {
        "best_f1": best_f1,
        "fpr_at_budget_0_01": fpr_at_budget,
        "max_recall_at_zero_fp": recall_at_zero_fp,
        "fpr_budget": 0.01,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="阈值标定与策略影响模拟（离线）")
    parser.add_argument("--dataset", default=str(ROOT / "data" / "public_combined.jsonl"))
    parser.add_argument("--out", default=str(REPORT_DIR / "threshold_sweep.json"))
    parser.add_argument("--semantic-backend", default="",
                        help="给了才加载语义层；不传就只跑规则层 + 启发层（零调用）")
    parser.add_argument("--semantic-timeout", type=float, default=0.0)
    parser.add_argument("--cache", default="", help="语义结果缓存（LLM 后端必给）")
    parser.add_argument("--sample", type=int, default=0, help="分层抽样条数")
    parser.add_argument("--seed", type=int, default=20261001)
    parser.add_argument("--max-llm-calls", type=int, default=0)
    args = parser.parse_args()

    data = Dataset.from_jsonl(Path(args.dataset))
    if args.sample:
        data = stratified_slice(data, args.sample, args.seed)
    attacks = sum(1 for s in data.samples if s.label == 1)
    print(f"数据集：{args.dataset}")
    print(f"样本 {len(data)} 条（攻击 {attacks} / 正常 {len(data) - attacks}）\n")

    semantic = None
    if args.semantic_backend:
        semantic = dict(mode="always", enabled=True, backend=args.semantic_backend,
                        timeout_s=args.semantic_timeout or None)
        if args.cache:
            from prompt_ids.detectors.semantic.factory import build_backend

            semantic["backend"] = CachedSemanticBackend(
                build_backend(args.semantic_backend, timeout_s=args.semantic_timeout or None),
                Path(args.cache))

    pipeline = build_pipeline(use_rule=True, use_heuristic=True, semantic=semantic)
    print("扫描中（一次扫描，多阈值复用）...")
    rows, calls, elapsed = scan_all(pipeline, data, args.max_llm_calls)
    pipeline.close()

    # 阈值取实际出现过的分数 —— 人造网格会在分数扎堆处漏掉整段台阶
    thresholds = sorted({r["score"] for r in rows})
    curve = sweep_threshold(rows, thresholds)
    policies = policy_impact(rows)
    knee = pick_knee(curve)
    level_mix = Counter(r["level"] for r in rows)

    report = {
        "dataset": args.dataset,
        "n": len(rows),
        "attacks": attacks,
        "semantic_backend": args.semantic_backend or "",
        "semantic_calls": calls,
        "elapsed_ms": round(elapsed, 1),
        "level_mix": dict(level_mix),
        "curve": curve,
        "policies": policies,
        "knee": knee,
    }

    print(f"扫描耗时 {elapsed:.0f} ms（语义调用 {calls} 次）· 等级分布 {dict(level_mix)}\n")

    print("## 分数阈标定（假设口径：score >= T 判为攻击；生产判定走 level→action 映射）")
    print("| T | TP | FP | P | R | F1 | FPR | 拦截占比 |")
    print("|---:|---:|---:|---:|---:|---:|---:|---:|")
    prev = None
    printed = 0
    for row in curve:
        signature = (row["tp"], row["fp"])
        if prev is None or signature != prev:
            print(f"| {row['threshold']:.2f} | {row['tp']} | {row['fp']} | {row['precision']:.4f} "
                  f"| {row['recall']:.4f} | {row['f1']:.4f} | {row['fpr']:.4f} "
                  f"| {row['blocked_share']:.4f} |")
            prev = signature
            printed += 1
        if printed >= 40:
            print("| … | （台阶过多，其余点见 JSON） | | | | | | |")
            break

    print("\n## 三个可操作读数")
    for key, label in (("best_f1", "F1 最优"),
                       ("fpr_at_budget_0_01", f"FPR ≤ {knee['fpr_budget']} 下召回最高"),
                       ("max_recall_at_zero_fp", "零误报下召回最高")):
        row = knee.get(key) or {}
        if not row:
            print(f"  {label}：不存在（该数据集上没有满足条件的阈值点）")
            continue
        print(f"  {label}：T={row['threshold']:.2f} → P={row['precision']:.4f} "
              f"R={row['recall']:.4f} F1={row['f1']:.4f} FPR={row['fpr']:.4f}")
    best = knee.get("best_f1") or {}
    if best.get("fpr", 0) > 0.05:
        # 不加这句，读数会被当成推荐值：「F1 最优 T=21.28」在 FPR 0.70 上毫无意义。
        print(f"  ⚠ F1 最优点落在 FPR={best['fpr']:.4f} 上，**不能当运行点用**："
              "该区间分数几乎不区分攻击与良性（规则层给同一档命中同一分数）。"
              "运维要的是误报率约束下的最高召回，看第二行。")

    print("\n## 策略影响（现状口径：这四档是真实策略）")
    print("| 策略 | 动作分布 | 攻击 block 召回 | 良性 block 误报 | 良性 sandbox（放行） | 良性进人工 | 总拦截占比 |")
    print("|---|---|---:|---:|---:|---:|---:|")
    for name, row in policies.items():
        mix = " ".join(f"{k}={v}" for k, v in sorted(row["actions"].items()))
        print(f"| {name} | {mix} | {row['block_recall']:.4f} | {row['block_fpr']:.4f} "
              f"| {row['sandbox_share']:.4f} | {row['review_share']:.4f} "
              f"| {row['blocked_share']:.4f} |")
    print("口径：`sandbox` 是放行 + 记审计（HTTP 200），只有 --block-sandbox 才真拦；"
          "它不计入 block 召回。")

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\nJSON 已保存 -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
