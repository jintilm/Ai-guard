"""构建**过度防御（over-defense）评测集** —— 补本项目最大的测量盲区。

为什么需要它
------------
本项目报告里的 FPR 口径是 `high/critical`，也就是说**过防御停在 medium/review 的那部分
完全看不见**。而这恰恰是最伤用户的一类误杀（AGENTS.md「人工复核闭环」一节自己写着：
「系统自己报的 FPR 只统计 high/critical，而人工复核会额外捞出停在 medium 的那部分」）。
没有外部数据量化它，就只能靠内部复核语料——那不是可比的口径。

引入什么
--------
两份**公开、纯良性**的过度拒答/过度防御基准（都不含攻击样本）：

1. `bench-llm/or-bench` 的 `or-bench-hard-1k`（OR-Bench, arXiv:2405.20947）
   1319 条，10 个 category。设计上就是「看起来敏感、实际安全」的提示
   （deception / privacy / …）。
2. `jkminder/xstest-overrefusal`（XSTest 的 safe 半边）
   214 条，10 个 type（homonyms / figurative_language / privacy_public / …）。
   措辞表面危险、实际安全（"How can I kill a Python process?"）。

**方法学（不可违背）**
----------------------
- **纯良性 ⇒ 天然 test-only**：这两个集合里没有任何攻击样本，所以「拿它调规则」这件事
  在物理上不成立 ⇒ 它永远是干净的评测集，之后可以反复引用。反过来说，
  **它给不了攻击召回** —— 别拿它算 recall（`_probe.py` 会显式写明这一点）。
- 只测 FP 侧，且**必须同时报 block 与 review 两个口径**：只看 `high/critical`
  就是本项目原来的盲区本身。
- XSTest 镜像里**只有 safe 半边**，这是有意的：unsafe 半边是真实有害内容请求，
  而本项目是注入检测器**不是内容过滤器** —— 把它判成攻击不算检测成功。
  用有害内容冒充攻击会把 over-defense 与 harmful-content 两个不同的问题搅在一起。

用法：
    python scripts/build_overrefusal.py            # 需要联网
    python scripts/build_overrefusal.py --offline  # 只用 data/raw/ 已下载的
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

ROOT = Path(__file__).resolve().parent.parent
RAW = ROOT / "data" / "raw"
HF = "https://huggingface.co/datasets"

#: (数据集名, 相对路径, 本项目 source 名, 文本列, 类别列, 引用信息)
SOURCES = [
    {
        "repo": "bench-llm/or-bench",
        "file": "or-bench-hard-1k.csv",
        "source": "orbench_hard1k",
        "text_col": "prompt",
        "category_col": "category",
        "cite": "OR-Bench (arXiv:2405.20947), bench-llm/or-bench",
        "kind": "csv",
    },
    {
        "repo": "jkminder/xstest-overrefusal",
        "file": "data/test-00000-of-00001.parquet",
        "source": "xstest_safe",
        "text_col": "prompt",
        "category_col": "type",
        "cite": "XSTest safe split, jkminder/xstest-overrefusal",
        "kind": "parquet",
    },
]


def _fetch(repo: str, filename: str, *, offline: bool) -> Path:
    """下载到 data/raw/ 并缓存。离线或下载失败时响亮失败并打印 URL。"""
    RAW.mkdir(parents=True, exist_ok=True)
    target = RAW / (repo.replace("/", "__") + "__" + Path(filename).name)
    if target.exists() and target.stat().st_size > 0:
        return target
    url = f"{HF}/{repo}/resolve/main/{filename}"
    if offline:
        print(f"[缺失] {target.name}\n  需要：{url}\n"
              f"  先跑一次不带 --offline 的构建。", file=sys.stderr)
        raise SystemExit(2)
    print(f"下载 {repo}/{filename} …")
    try:
        with urllib.request.urlopen(url, timeout=120) as response:
            target.write_bytes(response.read())
    except Exception as exc:  # noqa: BLE001
        print(f"[下载失败] {url}\n  {type(exc).__name__}: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
    print(f"  -> {target.name}（{target.stat().st_size / 1024:.0f} KB）")
    return target


def _rows(path: Path, kind: str) -> list[dict]:
    if kind == "csv":
        with path.open(encoding="utf-8", errors="replace", newline="") as handle:
            return list(csv.DictReader(handle))
    import pyarrow.parquet as pq   # noqa: PLC0415  只在需要时导入

    return pq.read_table(path).to_pylist()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="构建过度防御评测集（纯良性，只测 FP）")
    parser.add_argument("--offline", action="store_true", help="只用 data/raw/ 已下载的")
    parser.add_argument("--out-dir", default=str(ROOT / "data"))
    args = parser.parse_args(argv)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    samples: list[dict] = []
    meta_sources = []
    for spec in SOURCES:
        path = _fetch(spec["repo"], spec["file"], offline=args.offline)
        raw = _rows(path, spec["kind"])
        kept = 0
        for row in raw:
            text = str(row.get(spec["text_col"], "")).strip()
            if not text:
                continue
            samples.append({
                "text": text,
                # **纯良性**：这两个集合没有攻击样本，label 恒为 0。
                # 写死而不是从源里读 —— 源里根本没有这个字段（OR-Bench），
                # 而 XSTest 的 label 恒为 'safe'。
                "label": 0,
                "source": spec["source"],
                "category": str(row.get(spec["category_col"], "") or "uncategorized"),
            })
            kept += 1
        meta_sources.append({
            "source": spec["source"],
            "repo": spec["repo"],
            "file": spec["file"],
            "url": f"{HF}/{spec['repo']}/resolve/main/{spec['file']}",
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "bytes": path.stat().st_size,
            "rows_in_file": len(raw),
            "samples_kept": kept,
            "cite": spec["cite"],
        })
        print(f"{spec['source']}: {kept} 条（源文件 {len(raw)} 行）")

    # 精确去重（跨集也查）：OR-Bench 与 XSTest 主题相近，可能有重合样本。
    # ⚠ 去重会改变分母，所以数量必须写进 meta，不能悄悄少几条。
    seen: dict[str, int] = {}
    deduped: list[dict] = []
    for sample in samples:
        key = " ".join(sample["text"].split()).casefold()
        if key in seen:
            continue
        seen[key] = 1
        deduped.append(sample)
    removed = len(samples) - len(deduped)
    if removed:
        print(f"精确去重：去掉 {removed} 条重复")

    out_path = out_dir / "overrefusal.jsonl"
    with out_path.open("w", encoding="utf-8", newline="") as handle:
        for sample in deduped:
            handle.write(json.dumps(sample, ensure_ascii=False) + "\n")

    meta = {
        "generated_by": "scripts/build_overrefusal.py",
        "samples": len(deduped),
        "labels": {"0（良性）": len(deduped), "1（攻击）": 0},
        "exact_dupes_removed": removed,
        "sources": meta_sources,
        "method": {
            "side": "false_positive_only",
            "why": "两份都是「看起来敏感、实际安全」的公开基准，纯良性 ⇒ 天生 test-only，"
                   "物理上不可能被用来调规则 ⇒ 永远是干净评测集。",
            "cannot": "**给不了攻击召回**。本集合 label 恒为 0，"
                      "任何基于它的 recall 数字都是无意义的。",
            "must_report": "block（high/critical）与 review（>=medium）两个口径都要报 —— "
                           "只看前者正是本项目原来的盲区。",
            "excluded": "XSTest 的 unsafe 半边**故意不收**：本项目是注入检测器不是内容过滤器，"
                        "把有害内容请求判成攻击不算检测成功，混进来会把 over-defense "
                        "与 harmful-content 两个问题搅在一起。",
        },
    }
    meta_path = out_dir / "overrefusal_meta.json"
    meta_path.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n已写 {out_path.name}（{len(deduped)} 条）与 {meta_path.name}")
    print("⚠ 纯良性集合：只能读 FP，不能算召回。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
