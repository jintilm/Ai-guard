"""三层消融评测 —— 论文实验章节的主力脚本。

跑 5 组配置，输出 Precision/Recall/F1/误报率/延迟分位/语义调用率，
同时产出可直接贴进论文的 markdown 表格与供画图的 JSON。

    python scripts/eval_semantic.py
    python scripts/eval_semantic.py --no-semantic      # 只跑规则/启发，不加载大模型
    python scripts/eval_semantic.py --dataset data/x.jsonl

## 换成 LLM 后端评测时**先算额度**（重要教训）

规则/启发组是 0 次调用，但**语义组每被调用一次就花一次配额**。
以 817 条公开集为例：`always` 组 817 次、`L3 仅语义` 817 次、`fallback` 组还要按
在带内的样本数再花一批 —— 合起来可能 **2000+ 次**。
免费网关常见额度是「100 次 / 24 小时」，一旦打满就是 429，
而 429 不在致命错误表里、会走重试，于是**跑很久、最后什么结果都拿不到**
（本项目在 2026-09-30 真踩过这个坑，白烧掉一整天额度）。

所以用 LLM 后端时请照这个纪律来：

    # 1) 先探一条，确认网关认 response_format（认 ⇒ 1 条样本 1 次请求）
    #    不认 ⇒ 每条样本会先发一次带 response_format 的（400）再发一次不带，等于双倍
    # 2) 用 --sample 做**分层抽样**（别用 --limit，那是按顺序截，会偏某个来源）
    # 3) 用 --max-llm-calls 设硬上限（到点即停，并在报告里标 truncated）
    # 4) 用 --semantic-max-retries 0 去掉重试放大
    python scripts/eval_semantic.py --only --dataset data/full.jsonl \
        --sample 45 --groups "L1 仅规则,L1+L2 规则+启发,L1+L2+L3 (always 全量)" \
        --semantic-backend custom --semantic-max-retries 0 \
        --max-llm-calls 45 --out reports/ablation_llm.json

> 想要全量 LLM 消融（817 条 × 3 组），需要付费额度，免费额度做不了。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from prompt_ids.core.pipeline import Pipeline, PipelineConfig
from prompt_ids.core.verdict import FusionConfig
from prompt_ids.detectors import DetectorRegistry, HeuristicDetector, RuleDetector
from prompt_ids.detectors.semantic.base import Prediction, SemanticBackend
from prompt_ids.detectors.semantic.detector import (
    DEGRADED_CALL_FAIL_SHARE as _DEGRADED_CALL_FAIL_SHARE,
)
from prompt_ids.detectors.semantic.detector import SemanticDetector
from prompt_ids.detectors.semantic.factory import build_backend
from prompt_ids.eval.datasets import BUILTIN, Dataset, source_label
from prompt_ids.eval.metrics import (
    BLOCK_LEVELS,
    Confusion,
    latency_stats,
    markdown_table,
)
from prompt_ids.preprocess.guard import Guard
from prompt_ids.rules.loader import RuleBook

REPORT_DIR = Path(__file__).resolve().parent.parent / "reports"

#: 一组里 LLM 调用失败（超时+错误）超过这个比例，就把该组标记为 degraded。
#: 取 20%：低于它失败基本是零星；高于它，召回的差异更可能来自「谁先跑」
#: 而不是配置本身 —— 跨组比较就不再有意义。详见 run_group 里的注释。
#:
#: ⚠ 阈值本身住在包里（与运行时 `SemanticDetector.stats()["degraded"]` 共用）：
#: 之前这里写死一份、运行时压根没有这个判断，于是「离线把超时组标成不可用、
#: 线上却一切正常」这类不一致谁也发现不了。
DEGRADED_CALL_FAIL_SHARE = _DEGRADED_CALL_FAIL_SHARE


class CachedSemanticBackend(SemanticBackend):
    """跨组复用语义后端结果，可选落盘（`--cache FILE` 开启）。

    为什么需要：`L1+L2+L3 (always 全量)` 与 `L3 仅语义` 会对**同一批文本**各问
    一次后端。对 LLM 这种"一问一付"的后端，这是纯粹的浪费 —— 实测单次约 11s，
    817 条就会多花近 3 小时和等量的钱。而 `semantic_mode`（fallback / always）
    只决定"什么时候问"，不改变"答案是什么"，所以跨组复用是**语义安全**的。

    落盘还有第二个好处：**任务被中断后重跑只补缺失项**。LLM 全量动辄数小时，
    没有这个的话一次网络抖动就得从零开始。

    缓存键 = 后端指纹 + 文本指纹。后端指纹取自 `inner.info()` 里与判定相关的
    字段（模型名 / max_tokens / extra_body / 端点），**改了配置自动失效**，
    不会拿旧模型的判决冒充新模型。
    """

    def __init__(self, inner: SemanticBackend, path: Path, flush_every: int = 20):
        self._inner = inner
        self._path = Path(path)
        self._flush_every = max(1, flush_every)
        self.name = inner.name
        self.requires_network = inner.requires_network
        self.default_timeout_s = inner.default_timeout_s
        self._fingerprint = _backend_fingerprint(inner)
        self._data: dict[str, dict] = self._load()
        self._dirty = 0
        self.hits = 0
        self.misses = 0
        self.unavailable = 0

    # ---------- 落盘 ----------
    def _load(self) -> dict[str, dict]:
        try:
            obj = json.loads(self._path.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            return {}
        entries = obj.get("entries") if isinstance(obj, dict) else None
        if isinstance(entries, dict) and obj.get("fingerprint") == self._fingerprint:
            return entries
        # 指纹对不上（换了模型/参数）⇒ 整份作废，宁可重问也不串用
        return {}

    def flush(self) -> None:
        if not self._dirty:
            return
        self._path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"fingerprint": self._fingerprint, "entries": self._data}
        tmp = self._path.with_suffix(self._path.suffix + ".tmp")
        # 先写临时文件再原子替换：中途被杀也不会留下半个 JSON
        tmp.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
        tmp.replace(self._path)
        self._dirty = 0

    # ---------- 后端接口 ----------
    def predict(self, text: str) -> Prediction:
        key = hashlib.sha256(text.encode("utf-8")).hexdigest()[:32]
        hit = self._data.get(key)
        if hit is not None:
            self.hits += 1
            return Prediction(
                float(hit["p"]),
                str(hit.get("r", "")),
                str(hit.get("b", self.name)),
                float(hit.get("t", 0.0)),
            )
        prediction = self._inner.predict(text)
        self.misses += 1
        if not prediction.ok:
            # 失败**绝不入缓存**：网络抖动/超时是一次性事件，缓存下来会变成
            # 永久性的"这一条已经问过了"，重跑也永远拿不到真实判决。
            self.unavailable += 1
            return prediction
        self._data[key] = {
            "p": prediction.probability,
            "r": prediction.rationale,
            "b": prediction.backend,
            # 保留原始延迟，让命中缓存时不把统计拉成 0
            "t": round(prediction.latency_ms, 3),
        }
        self._dirty += 1
        if self._dirty >= self._flush_every:
            self.flush()
        return prediction

    def is_available(self) -> bool:
        return self._inner.is_available()

    def warmup(self) -> None:
        self._inner.warmup()

    def close(self) -> None:
        self.flush()
        self._inner.close()

    def info(self) -> dict:
        data = dict(self._inner.info())
        data.update({
            "cache_path": str(self._path),
            "cache_entries": len(self._data),
            "cache_hits": self.hits,
            "cache_misses": self.misses,
            "cache_unavailable": self.unavailable,
        })
        return data


def _backend_fingerprint(inner: SemanticBackend) -> str:
    """只取与"判决结果"有关的字段 —— 换模型/换 max_tokens/换开关即失效。"""
    try:
        info = inner.info() or {}
    except Exception:  # noqa: BLE001 - 诊断信息拿不到不该让缓存不可用
        info = {}
    relevant = {
        key: info.get(key)
        for key in ("backend", "provider", "model", "base_url", "max_tokens", "extra_body")
        if key in info
    }
    blob = json.dumps(relevant, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]


def build_pipeline(
    use_rule: bool = True,
    use_heuristic: bool = True,
    semantic: dict | None = None,
    short_circuit: bool = False,
    enable_cache: bool = False,
) -> Pipeline:
    detectors = []
    if use_rule:
        detectors.append(RuleDetector(rules=RuleBook()))
    if use_heuristic:
        detectors.append(HeuristicDetector())
    if semantic:
        detectors.append(SemanticDetector(**semantic))
    return Pipeline(
        registry=DetectorRegistry(detectors=detectors),
        guard=Guard(),
        config=PipelineConfig(
            fusion=FusionConfig(),
            enable_cache=enable_cache,
            short_circuit_on_critical=short_circuit,
            budget_ms=5000.0,
        ),
    )


ABLATIONS = {
    "L1 仅规则": dict(use_rule=True, use_heuristic=False),
    "L1+L2 规则+启发": dict(use_rule=True, use_heuristic=True),
    "L1+L2+L3 (fallback 门禁)": dict(
        use_rule=True, use_heuristic=True, semantic=dict(mode="fallback", enabled=True)
    ),
    "L1+L2+L3 (always 全量)": dict(
        use_rule=True, use_heuristic=True, semantic=dict(mode="always", enabled=True)
    ),
    "L3 仅语义": dict(use_rule=False, use_heuristic=False, semantic=dict(mode="always", enabled=True)),
}


def stratified_slice(data: Dataset, n: int, seed: int) -> Dataset:
    """按 (source, label) 分层抽样，返回确定的 n 条子集。

    为什么不是「取前 n 条」：`full.jsonl` 是按来源顺序拼的，前 n 条会整片落在
    某一个来源上，指标会严重偏。LLM 后端按次计费、额度有限（免费额度 100 次/24h），
    每一次调用都很贵，**必须让这 n 条尽量代表整体**。

    分配方式：按各层占比取整分配，余数按「小数部分最大」补齐，且不超过层容量。
    固定 seed ⇒ 可复跑，同样的切片能被反复引用。
    """
    if n <= 0 or n >= len(data):
        return data
    buckets: dict[tuple[str, int], list] = {}
    for sample in data.samples:
        buckets.setdefault((sample.source, sample.label), []).append(sample)

    total = len(data)
    exact = {k: len(v) * n / total for k, v in buckets.items()}
    take = {k: min(int(exact[k]), len(buckets[k])) for k in buckets}
    # 余数：小数部分大的先补，补满 n 为止
    remainder = n - sum(take.values())
    for key in sorted(buckets, key=lambda k: (-(exact[k] - int(exact[k])), k)):
        if remainder <= 0:
            break
        if take[key] < len(buckets[key]):
            take[key] += 1
            remainder -= 1

    rng = random.Random(seed)
    picked: list = []
    for key in sorted(buckets):
        pool = list(buckets[key])
        rng.shuffle(pool)
        picked.extend(pool[: take[key]])
    rng.shuffle(picked)
    return Dataset(tuple(picked))


def run_group(
    name: str,
    spec: dict,
    dataset: Dataset,
    no_semantic: bool,
    overrides: dict | None = None,
    max_llm_calls: int = 0,
) -> dict:
    if no_semantic and spec.get("semantic"):
        return {"skipped": True}
    spec = dict(spec)
    # 只覆盖语义组；规则/启发组没有 semantic 键，不受影响。
    # 默认 overrides 为空 dict ⇒ 与旧行为逐字段一致（可复现性不受影响）。
    if spec.get("semantic") and overrides:
        spec["semantic"] = {**spec["semantic"], **overrides}
    pipeline = build_pipeline(**spec)
    pipeline.warmup()  # 模型冷启动不计入延迟统计

    y_true: list[int] = []
    y_pred: list[int] = []
    latencies: list[float] = []
    # 按数据来源分别统计，用来对比「公开集 vs 自建集」上的表现差异
    per_source: dict[str, tuple[list[int], list[int]]] = {}
    semantic_calls = 0

    det = pipeline.semantic_detector
    before = det.calls if det else 0
    cache = (
        det.backend
        if det and isinstance(det.backend, CachedSemanticBackend)
        else None
    )
    hits_before = cache.hits if cache else 0

    total = len(dataset)
    step = max(1, total // 10)
    scanned = 0
    truncated = False
    for index, sample in enumerate(dataset, 1):
        # 硬预算闸门：LLM 按次计费，超出额度后网关直接 429。
        # 在这里**主动停**，比跑到一半被限流、拿回一堆中性分要诚实得多。
        if det and max_llm_calls and (det.calls - before) >= max_llm_calls:
            truncated = True
            print(
                f"    {name}: 已达 LLM 调用上限 {max_llm_calls}，本组提前停止"
                f"（已扫描 {scanned}/{total}）",
                flush=True,
            )
            break
        result = pipeline.scan(sample.text)
        scanned += 1
        prediction = 1 if result.level.value in BLOCK_LEVELS else 0
        y_true.append(sample.label)
        y_pred.append(prediction)
        latencies.append(result.latency_ms.get("total", 0.0))
        bucket = per_source.setdefault(sample.source, ([], []))
        bucket[0].append(sample.label)
        bucket[1].append(prediction)
        # 大集上给个进度心跳：LLM 后端一条要 2~3s，800 条就是几十分钟，
        # 后台跑时没有输出会让人以为卡死。
        if total >= 50 and (index % step == 0 or index == total):
            print(f"    {name}: {index}/{total}", flush=True)

    if det:
        semantic_calls = det.calls - before
        stats = det.stats()
    else:
        stats = {}
    cache_hits = (cache.hits - hits_before) if cache else 0

    confusion = Confusion.from_pairs(y_true, y_pred)
    row = confusion.as_row()
    latency = latency_stats(latencies)

    # ---- 可靠性：这一组的数字能不能当结论用 ----
    # LLM 后端会超时，而超时是**弃票**（ok=False → contribution() 返回 None），
    # 于是超时直接表现为「召回变低」。2026-10 那次重跑就踩了：fallback 组
    # 超时率 87.2%（R=0.3305），紧邻的 always 组只有 10.5%（R=0.8091）——
    # 差 0.48 看着像门禁退化，其实是网关在那一段时间里不健康，
    # 而先跑的那组把失败全吃下了。不标记的话，这个数字会被当成「fallback 模式更差」。
    calls = int(stats.get("calls", 0) or 0)
    timeouts = int(stats.get("timeouts", 0) or 0)
    errors = int(stats.get("errors", 0) or 0)
    failed_share = round((timeouts + errors) / calls, 4) if calls else 0.0
    degraded = failed_share > DEGRADED_CALL_FAIL_SHARE
    reliability = {
        "calls": calls,
        "timeouts": timeouts,
        "errors": errors,
        "failed_share": failed_share,
        "degraded": degraded,
        "note": ("超时/错误按弃票处理，会直接压低召回。failed_share > "
                 f"{DEGRADED_CALL_FAIL_SHARE:.0%} 时本组 P/R/F1 不可作为结论，"
                 "请用 --semantic-timeout 调大后重跑这一组。"),
    }
    if degraded:
        print(f"    [警告] {name}: LLM 调用失败率 {failed_share:.1%}"
              f"（{timeouts} 超时 / {errors} 错误，共 {calls} 次）—— "
              "本组数字不可作为结论，请调大 --semantic-timeout 重跑", flush=True)

    return {
        "confusion": row,
        "latency_ms": latency,
        "semantic_calls": semantic_calls,
        "semantic_call_rate": round(semantic_calls / max(scanned, 1), 4),
        "semantic": stats,
        "reliability": reliability,
        # 实际扫描条数 / 是否因预算闸门提前停止 —— 截断的结果必须自证截断，
        # 否则以后有人把这个数字当成全量结论。
        "scanned": scanned,
        "truncated": truncated,
        # 本组有多少条直接复用了别组的缓存结果。
        # 命中 > 0 时**本组延迟统计不可用**（缓存命中不产生真实等待），
        # 但判定概率与原调用完全一致，所以 P/R/F1 仍然有效。
        "cache_hits": cache_hits,
        "by_source": {
            source: Confusion.from_pairs(trues, preds).as_row()
            for source, (trues, preds) in sorted(per_source.items())
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="三层消融评测")
    parser.add_argument("--dataset", nargs="*", help="外部数据集（.jsonl / .csv）")
    parser.add_argument("--no-semantic", action="store_true", help="跳过含语义层的组，不加载大模型")
    parser.add_argument("--only", action="store_true", help="只用外部数据集，不拼接内置种子集")
    parser.add_argument("--out", default=str(REPORT_DIR / "ablation.json"))
    parser.add_argument(
        "--semantic-backend", default="",
        help="覆盖语义组后端（如 custom / llm / deepseek / lightweight）；默认空 = 各层自身选型",
    )
    parser.add_argument(
        "--semantic-timeout", type=float, default=None,
        help="覆盖语义组单次推理超时秒数",
    )
    parser.add_argument(
        "--limit", type=int, default=0,
        help="只取前 N 条（试跑 / 估算用）；0 = 全量。注意这是**按顺序**截取，可能偏某个来源",
    )
    parser.add_argument(
        "--sample", type=int, default=0,
        help="分层抽样 N 条（按 source×label 等比例，确定性）；0 = 不抽样。"
             "LLM 后端按次计费时应优先用它而不是 --limit，否则切片会偏",
    )
    parser.add_argument("--seed", type=int, default=20260930, help="分层抽样的随机种子")
    parser.add_argument(
        "--max-llm-calls", type=int, default=0,
        help="语义组 LLM 调用次数硬上限；达到即提前停止该组并在报告里标记 truncated。0 = 不限制",
    )
    parser.add_argument(
        "--semantic-max-retries", type=int, default=None,
        help="语义组 HTTP 重试次数（默认 2）。额度紧张时设 0，保证 1 条样本最多 1 次尝试",
    )
    parser.add_argument(
        "--groups", default="",
        help="只跑指定组（逗号分隔，按名字子串匹配）；默认空 = 全部",
    )
    parser.add_argument(
        "--cache", default="",
        help="语义后端结果的落盘缓存路径（JSON）。开启后多个语义组共用同一份结果、"
             "被中断也能续跑。LLM 后端强烈建议开：always 与『仅语义』两组问的是"
             "同一批文本，不开就要问两遍、付两遍钱",
    )
    args = parser.parse_args()

    if args.only and args.dataset:
        data = Dataset(())
    else:
        data = BUILTIN
    for spec in args.dataset or []:
        path = Path(spec)
        extra = Dataset.from_jsonl(path) if path.suffix == ".jsonl" else Dataset.from_csv(path)
        data = data.concat(extra)
    if args.sample > 0:
        data = stratified_slice(data, args.sample, args.seed)
    elif args.limit > 0:
        data = Dataset(tuple(data.samples)[: args.limit])
    counts = data.counts()
    print(f"数据集：{counts['total']} 条（攻击 {counts['attack']} / 正常 {counts['benign']}）")
    if args.sample > 0:
        print(f"分层抽样：seed={args.seed}，来源×标签分布 = {data.sources()}")
    print(f"判定阈 level ∈ {sorted(BLOCK_LEVELS)} 记为预测攻击\n")

    overrides: dict = {}
    shared_backend: CachedSemanticBackend | None = None
    if args.cache:
        # 开了缓存就必须自己把后端建出来（SemanticDetector 拿到实例后不会再
        # 走 backend_kwargs 那条路），否则重试参数会被静默忽略。
        inner_kwargs: dict = {}
        if args.semantic_max_retries is not None:
            inner_kwargs["max_retries"] = args.semantic_max_retries
        inner = build_backend(args.semantic_backend or "auto", **inner_kwargs)
        shared_backend = CachedSemanticBackend(inner, Path(args.cache))
        overrides["backend"] = shared_backend
        print(f"语义结果缓存：{args.cache}（已有 {len(shared_backend._data)} 条）")
    elif args.semantic_backend:
        overrides["backend"] = args.semantic_backend
    if args.semantic_timeout is not None:
        overrides["timeout_s"] = args.semantic_timeout
    if args.semantic_max_retries is not None and not args.cache:
        overrides["backend_kwargs"] = {"max_retries": args.semantic_max_retries}
    if overrides:
        print(f"语义组覆盖：{overrides}")
    if args.max_llm_calls:
        print(f"LLM 调用硬上限：{args.max_llm_calls} 次/组")
    print()

    wanted = [g.strip() for g in args.groups.split(",") if g.strip()]
    results: dict[str, dict] = {}
    for name, spec in ABLATIONS.items():
        if wanted and not any(w in name for w in wanted):
            continue
        outcome = run_group(
            name, spec, data, args.no_semantic, overrides, args.max_llm_calls
        )
        if outcome.get("skipped"):
            print(f"[skip] {name}")
            continue
        results[name] = outcome
        row = outcome["confusion"]
        flag = "  ⚠截断" if outcome.get("truncated") else ""
        if outcome.get("cache_hits"):
            flag += f"  ⚠缓存命中{outcome['cache_hits']}（延迟列不可用）"
        rel = outcome.get("reliability") or {}
        if rel.get("degraded"):
            # 这条必须和 P/R/F1 印在同一行：超时按弃票处理、直接压低召回，
            # 不标出来就会把「网关不健康」读成「这个配置更差」。
            flag += (f"  ⚠不可用：LLM 调用失败率 {rel['failed_share']:.0%}"
                     f"（{rel['timeouts']} 超时/{rel['errors']} 错误）")
        print(
            f"[done] {name:<24} P={row['precision']:.3f} R={row['recall']:.3f} "
            f"F1={row['f1']:.3f} FPR={row['false_positive_rate']:.3f} "
            f"P95={outcome['latency_ms']['p95']:.1f}ms "
            f"语义调用={outcome['semantic_calls']} n={outcome['scanned']}{flag}"
        )

    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    out = Path(args.out)
    if shared_backend is not None:
        shared_backend.flush()
        total = shared_backend.hits + shared_backend.misses
        saved = shared_backend.hits
        print(
            f"\n语义缓存：命中 {saved}/{total} 次"
            f"（省下 {saved} 次后端调用），条目 {len(shared_backend._data)} -> {args.cache}"
        )
    out.write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")

    rows = []
    cache_affected = False
    degraded_names: list[str] = []
    for name, outcome in results.items():
        row = outcome["confusion"]
        cached = bool(outcome.get("cache_hits"))
        cache_affected = cache_affected or cached
        rel = outcome.get("reliability") or {}
        degraded = bool(rel.get("degraded"))
        if degraded:
            degraded_names.append(name)
        rows.append([
            name + ("  ⚠不可用" if degraded else ""),
            f"{row['precision']:.4f}",
            f"{row['recall']:.4f}",
            f"{row['f1']:.4f}",
            f"{row['false_positive_rate']:.4f}",
            # 缓存命中不产生真实等待，此时的延迟是假的 —— 宁可留空也不留错
            "—" if cached else f"{outcome['latency_ms']['p50']:.1f}",
            "—" if cached else f"{outcome['latency_ms']['p95']:.1f}",
            str(outcome["semantic_calls"]),
            "—" if not rel.get("calls") else f"{rel['failed_share']:.0%}",
        ])
    table = markdown_table(
        ["配置", "Precision", "Recall", "F1", "误报率", "P50(ms)", "P95(ms)", "语义调用次数",
         "调用失败率"],
        rows,
        aligns="lrrrrrrrr",
    )
    print("\n" + table)
    if cache_affected:
        print(
            "> 标 `—` 的组复用了缓存结果：判定概率与真实调用一致，"
            "所以 P/R/F1 有效；但延迟列无意义（缓存命中没有真实等待）。"
        )
    if degraded_names:
        # 超时按弃票处理，会直接压低召回；先跑的那组还会替后面的组吃掉失败。
        # 所以失败率高的组，其 P/R/F1 **不能**和别的组相减。
        print(
            "> ⚠ 标「不可用」的组：LLM 调用失败率过高（超时按弃票处理，直接压低召回）。"
            f"受影响组：{'、'.join(degraded_names)}。"
            "请用 `--semantic-timeout` 调大后单独重跑这些组，"
            "在此之前不要引用它们的 P/R/F1，也不要与其他组相减。"
        )

    sources = sorted({s for outcome in results.values() for s in outcome.get("by_source", {})})
    if len(sources) > 1:
        print("\n按数据来源拆分（同一套配置的泛化表现）：")
        for source in sources:
            sub_rows = []
            for name, outcome in results.items():
                row = outcome.get("by_source", {}).get(source)
                if not row:
                    continue
                sub_rows.append([
                    name, row["precision"], row["recall"], row["f1"],
                    row["false_positive_rate"], row["tp"] + row["fn"],
                ])
            print(f"\n[{source_label(source)}]")
            print(markdown_table(
                ["配置", "Precision", "Recall", "F1", "误报率", "样本数"],
                sub_rows,
                aligns="lrrrrr",
            ))

    print(f"\nJSON 已保存 -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
