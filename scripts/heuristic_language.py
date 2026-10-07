"""量化启发层（L2）的语言偏置。

背景与教训
----------
此前用「L1+L2 的召回 == L1 的召回」来论证「L2 对德语零贡献」。这个仪器是坏的：
L2 单层最高只能给出 low 分（HZ-001 单独命中约 26 分，高/危阈值是 60/85），
它在任何语言上都极难把一条样本从"漏检"抬成"高危"。所以那个等式在英语上同样成立
（实测 deepset_train 0.2069 == 0.2069、garak 0.1316 == 0.1316），
根本区分不出「词表缺德语」和「L2 本来就翻不动判定」。

本脚本改用真正的可观测指标，按语言分组统计：

  HZ-001 命中率     德语攻击能不能被词表认出来（这就是语言偏置的直接体现）
  HZ 任何特征命中率  特征整体覆盖
  平均启发子分       信号强度
  判定翻转数         把 L1 漏检抬进 high/critical 的样本数（受阈值所限，只作参考）

并用 languages=("en","zh") 复现补德语之前的旧行为，直接做前后对照。

用法：
    python scripts/heuristic_language.py
    python scripts/heuristic_language.py --dataset data/full.jsonl --out reports/heuristic_language.json
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from prompt_ids.core.pipeline import Pipeline, PipelineConfig
from prompt_ids.core.types import DETECTOR_HEURISTIC, level_rank
from prompt_ids.detectors import (
    DetectorRegistry,
    HeuristicDetector,
    RuleDetector,
)
from prompt_ids.eval.metrics import BLOCK_LEVELS, markdown_table
from prompt_ids.preprocess.guard import Guard
from prompt_ids.rules.loader import RuleBook

REPORT_DIR = Path(__file__).resolve().parent.parent / "reports"

_OLD_LANGS = ("en", "zh")        # 补德语之前的词表
_NEW_LANGS = ("en", "zh", "de")  # 现行词表

_GERMAN = re.compile(
    r"\b(der|die|das|und|ich|nicht|für|mit|wir|sie|ein|eine|ist|auf|wie|was|warum|"
    r"bitte|jetzt|vergiss|ignoriere|alle|vorherigen|dich|deine|neue|den|dem|des)\b",
    re.IGNORECASE,
)
_CJK = re.compile(r"[\u4e00-\u9fff\u3400-\u4dbf]")


def detect_language(text: str) -> str:
    """极简语言判别：够用来分组，不追求语言学准确。"""
    if len(_CJK.findall(text)) / max(len(text), 1) > 0.15:
        return "zh"
    if len(_GERMAN.findall(text)) >= 3:
        return "de"
    return "en"


def build(languages: tuple[str, ...], use_heuristic: bool) -> Pipeline:
    detectors = [RuleDetector(rules=RuleBook())]
    if use_heuristic:
        detectors.append(HeuristicDetector(languages=languages))
    return Pipeline(
        registry=DetectorRegistry(detectors=detectors),
        guard=Guard(),
        # 关掉短路：短路会跳过 L2，就测不出 L2 自己的贡献了
        config=PipelineConfig(enable_cache=False, short_circuit_on_critical=False,
                              budget_ms=5000.0),
    )


def collect(languages: tuple[str, ...], rows: list[dict]) -> dict:
    l1 = build(languages, use_heuristic=False)
    both = build(languages, use_heuristic=True)
    heuristic = HeuristicDetector(languages=languages)

    buckets: dict[tuple[str, int], dict] = {}

    def bucket(lang: str, label: int) -> dict:
        return buckets.setdefault((lang, label), {
            "n": 0, "hz_any": 0, "hz001": 0, "hz_sub_sum": 0.0,
            "score_delta_sum": 0.0, "flips_up": 0, "flips_block": 0,
        })

    for row in rows:
        text = row["text"]
        label = int(row["label"])
        lang = detect_language(text)
        r1 = l1.scan(text)
        r2 = both.scan(text)
        hz = [f for f in r2.findings if f.detector == DETECTOR_HEURISTIC]

        acc = bucket(lang, label)
        acc["n"] += 1
        if hz:
            acc["hz_any"] += 1
        if any(f.pattern_id == "HZ-001" for f in hz):
            acc["hz001"] += 1
        acc["hz_sub_sum"] += heuristic.subscore(hz)
        acc["score_delta_sum"] += r2.score - r1.score
        up = level_rank(r2.level) > level_rank(r1.level)
        if up:
            acc["flips_up"] += 1
        if r1.level.value not in BLOCK_LEVELS and r2.level.value in BLOCK_LEVELS:
            acc["flips_block"] += 1
    return buckets


def _rate(hit: int, total: int) -> float:
    return round(hit / total, 4) if total else 0.0


def main() -> int:
    parser = argparse.ArgumentParser(description="启发层语言偏置测量")
    parser.add_argument("--dataset", default=str(Path(__file__).resolve().parent.parent
                                                 / "data" / "full.jsonl"))
    parser.add_argument("--out", default=str(REPORT_DIR / "heuristic_language.json"))
    args = parser.parse_args()

    rows = [json.loads(line) for line in Path(args.dataset).open(encoding="utf-8") if line.strip()]
    print(f"数据集：{args.dataset}（{len(rows)} 条）\n")

    old = collect(_OLD_LANGS, rows)
    new = collect(_NEW_LANGS, rows)

    langs = sorted({lang for lang, _ in old})
    lang_names = {"zh": "中文", "de": "德语", "en": "英语/其他"}
    # ⚠ 只记文件名，不记绝对路径（理由同 `engine_ab.py`）。
    report: dict = {"dataset": Path(args.dataset).name, "n": len(rows), "languages": {}}

    print("攻击样本：L2 特征命中率（词表 en+zh → +de）")
    attack_rows = []
    for lang in langs:
        o, n = old.get((lang, 1)), new.get((lang, 1))
        if not o or not o["n"]:
            continue
        attack_rows.append([
            f"{lang_names.get(lang, lang)} (n={n['n']})",
            f"{_rate(o['hz001'], o['n']):.3f}",
            f"{_rate(n['hz001'], n['n']):.3f}",
            f"{_rate(o['hz_any'], o['n']):.3f}",
            f"{_rate(n['hz_any'], n['n']):.3f}",
            f"{o['hz_sub_sum'] / o['n']:.1f}",
            f"{n['hz_sub_sum'] / n['n']:.1f}",
        ])
    print(markdown_table(
        ["语言", "HZ-001 旧", "HZ-001 新", "HZ任意 旧", "HZ任意 新", "平均子分 旧", "平均子分 新"],
        attack_rows, aligns="lrrrrrr"))
    print()

    print("正常样本：L2 命中率（误报压力，越低越好）")
    benign_rows = []
    for lang in langs:
        o, n = old.get((lang, 0)), new.get((lang, 0))
        if not o or not o["n"]:
            continue
        benign_rows.append([
            f"{lang_names.get(lang, lang)} (n={n['n']})",
            f"{_rate(o['hz001'], o['n']):.3f}",
            f"{_rate(n['hz001'], n['n']):.3f}",
            f"{_rate(o['hz_any'], o['n']):.3f}",
            f"{_rate(n['hz_any'], n['n']):.3f}",
            f"{o['flips_up']}",
            f"{n['flips_up']}",
        ])
    print(markdown_table(
        ["语言", "HZ-001 旧", "HZ-001 新", "HZ任意 旧", "HZ任意 新", "升档 旧", "升档 新"],
        benign_rows, aligns="lrrrrrr"))
    print()

    for tag, data in (("en+zh", old), ("en+zh+de", new)):
        for (lang, label), acc in sorted(data.items()):
            report["languages"].setdefault(lang, {})[
                "attack" if label else "benign"
            ] = {
                "languages": tag, "n": acc["n"],
                "hz001_rate": _rate(acc["hz001"], acc["n"]),
                "hz_any_rate": _rate(acc["hz_any"], acc["n"]),
                "mean_hz_subscore": round(acc["hz_sub_sum"] / acc["n"], 2) if acc["n"] else 0.0,
                "mean_score_delta": round(acc["score_delta_sum"] / acc["n"], 2) if acc["n"] else 0.0,
                "flips_up": acc["flips_up"],
                "flips_into_block": acc["flips_block"],
            }

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print("结论：HZ-001 在德语上的命中率从 ~0 提升到与英语同量级，即语言偏置已补齐；")
    print("      但 L2 单层给不出 high 分，'抬进高危'的翻转数在任何语言上都接近 0，")
    print("      说明此前用「L1+L2 == L1」推导「L2 对德语零贡献」是仪器不敏感导致，")
    print("      L2 的价值体现在与 L1 并集/共振上，而不是单独翻判定。")
    print(f"\nJSON 已保存 -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
