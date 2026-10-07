"""把公开数据集转成项目内部的 JSONL 格式。

数据源：
  1. deepset/prompt-injections  —— 人工标注的真实样本（662 条），字段 text/label
  2. NVIDIA/garak               —— 攻击 payload 生成器（模板 × rogue string × 混淆技巧）
                                   外加它自带的良性任务提示

产出：
  data/public_deepset.jsonl     公开集 · deepset
  data/public_garak.jsonl       公开集 · garak 生成
  data/public_combined.jsonl    两者合并
  data/full.jsonl               再叠加内置种子集（评测默认用这个）

用法：
    python scripts/build_dataset.py
    python scripts/build_dataset.py --garak-variants 2
"""
from __future__ import annotations

import argparse
import ast
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from prompt_ids.eval.datasets import BENIGN, INJECTION, Sample

ROOT = Path(__file__).resolve().parent.parent
RAW = ROOT / "data" / "raw"
OUT = ROOT / "data"

GARAK_PLACEHOLDER = "{REPLACE_rogue_string}"


# ---------------------------------------------------------------- garak
def load_garak_module():
    """直接执行 garak 的数据模块拿到字典，不需要安装 garak 本体。"""
    path = RAW / "garak_prompt_data.py"
    if not path.exists():
        raise FileNotFoundError(f"缺少 {path}，请重新运行下载")
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    namespace: dict = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            name = node.targets[0]
            if isinstance(name, ast.Name):
                try:
                    namespace[name.id] = ast.literal_eval(node.value)
                except ValueError:
                    pass  # 含非常量表达式的字典跳过
    return namespace


def _clean_instruction(text: str) -> str:
    return text.replace("\\n", "\n").strip()


def _attack(text: str, category: str, source: str) -> Sample:
    text = text.strip()
    if not text:
        return None
    return Sample(text=text, label=INJECTION, category=category, source=source)


def gen_garak(variants: int) -> list[Sample]:
    data = load_garak_module()
    hijacks = data.get("goal_hikacking_attacks", {})
    leaks = data.get("prompt_leaking_attacks", {})
    rogues = data.get("rogue_strings", {})
    escapes = data.get("escape_chars", {})
    delimiters = data.get("delimiter_chars", {})
    playground = data.get("openai_playground_prompts", {})

    rows: list[Sample] = []
    seen: set[str] = set()

    def add(sample: Sample | None) -> None:
        if sample is None or sample.text in seen:
            return
        seen.add(sample.text)
        rows.append(sample)

    # 1) 目标劫持：模板 × rogue string
    for key, spec in hijacks.items():
        instruction = _clean_instruction(spec.get("instruction", ""))
        if GARAK_PLACEHOLDER in instruction:
            for rname, rogue in rogues.items():
                add(_attack(instruction.replace(GARAK_PLACEHOLDER, rogue),
                            f"garak_hijack:{key}", "garak"))
        else:
            add(_attack(instruction, f"garak_hijack:{key}", "garak"))

    # 2) 混淆变体：前置转义符 / 分隔符包裹，考验归一化与解码层
    base_rows = [r for r in rows if r.category.startswith("garak_hijack")]
    for row in base_rows[:6]:
        for ename, ech in list(escapes.items())[:variants]:
            add(_attack(f"{ech}{row.text}", "garak_hijack:escaped", "garak"))
        for dname, dch in list(delimiters.items())[:variants]:
            add(_attack(f"{dch * 12} start {row.text} {dch * 12}",
                        "garak_hijack:delimited", "garak"))

    # 3) 提示泄露类攻击
    for key, spec in leaks.items():
        add(_attack(_clean_instruction(spec.get("instruction", "")),
                    f"garak_leak:{key}", "garak"))

    # 4) 良性任务提示（garak 自带，用作正常语料）
    benign_count = 0
    for key, spec in playground.items():
        instruction = _clean_instruction(spec.get("instruction", ""))
        if len(instruction) < 12 or GARAK_PLACEHOLDER in instruction:
            continue
        # n-shot 样例很长，截短以免样本长度失衡
        sample = Sample(text=instruction[:400], label=BENIGN, category="garak_benign", source="garak")
        if sample.text not in seen:
            seen.add(sample.text)
            rows.append(sample)
            benign_count += 1
        if benign_count >= 40:
            break
    return rows


# ---------------------------------------------------------------- deepset
def load_deepset() -> list[Sample]:
    import pandas as pd

    frames = []
    for name in ("deepset_train.parquet", "deepset_test.parquet"):
        path = RAW / name
        if path.exists():
            frame = pd.read_parquet(path)
            frame["__src"] = name
            frames.append(frame)
    if not frames:
        raise FileNotFoundError(f"{RAW} 下没有 deepset parquet，请先下载")
    table = pd.concat(frames, ignore_index=True)

    rows: list[Sample] = []
    seen: set[str] = set()
    # train / test 的划分必须保留：规则迭代只碰 train，最终指标看 test
    for record in table.to_dict("records"):
        # pandas 的 itertuples 会重命名 __src 这类列，这里用 dict 访问稳妥
        raw_source = str(record.get("__src", "") or "")
        split = "test" if "test" in raw_source else "train"
        text = str(record.get("text", "") or "").strip()
        label = int(record.get("label", 0))
        if not text or text in seen:
            continue
        seen.add(text)
        suffix = "injection" if label == 1 else "benign"
        rows.append(
            Sample(
                text=text,
                label=INJECTION if label == 1 else BENIGN,
                category=f"deepset_{suffix}",
                source=f"deepset_{split}",
            )
        )
    return rows


# ---------------------------------------------------------------- 输出
def write_jsonl(samples: list[Sample], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    rows = []
    for s in samples:
        rows.append({"text": s.text, "label": s.label, "category": s.category, "source": s.source})
    path.write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in rows) + "\n", encoding="utf-8")


def summary(name: str, samples: list[Sample]) -> None:
    attacks = sum(1 for s in samples if s.label == INJECTION)
    print(f"{name:<26} {len(samples):>5} 条   攻击 {attacks:>4} / 正常 {len(samples) - attacks:>4}")


def main() -> int:
    parser = argparse.ArgumentParser(description="构建公开数据集")
    parser.add_argument("--garak-variants", type=int, default=2, help="每种混淆技巧生成几组变体")
    args = parser.parse_args()

    deepset = load_deepset()
    garak = gen_garak(args.garak_variants)

    seen: set[str] = set()
    combined = []
    for s in deepset + garak:
        if s.text in seen:
            continue
        seen.add(s.text)
        combined.append(s)

    write_jsonl(deepset, OUT / "public_deepset.jsonl")
    write_jsonl(garak, OUT / "public_garak.jsonl")
    write_jsonl(combined, OUT / "public_combined.jsonl")

    builtin = __import__("prompt_ids.eval.datasets", fromlist=["BUILTIN"]).BUILTIN
    full = combined + [s for s in builtin if s.text not in seen]
    write_jsonl(list(full), OUT / "full.jsonl")

    print("\n数据源：deepset/prompt-injections（HF）+ NVIDIA/garak（GitHub）\n")
    summary("public_deepset.jsonl", deepset)
    summary("public_garak.jsonl", garak)
    summary("public_combined.jsonl", combined)
    summary("full.jsonl（含内置种子）", list(full))
    print("\n评测用法：")
    print("  python scripts/eval_semantic.py --dataset data/public_combined.jsonl --only")
    print("  python scripts/eval_semantic.py --dataset data/full.jsonl --only")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
