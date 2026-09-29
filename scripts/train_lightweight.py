"""训练轻量语义模型（TF-IDF + 逻辑回归）。

这个模型的定位是「永远能跑的基线与对照组」：不依赖 torch、毫秒级、离线可用。
要拿更强的效果请直接用 DeBERTa 后端；要更好的统计显著性请换更大的公开数据集。

## 为什么默认排除留出集（重要）

此前脚本默认在**全量数据**（含 deepset_test）上训练，然后拿同一批数据算指标，
得出"轻量模型 F1=0.9x"这类数字 —— 那是背答案，不是泛化。规则层的老毛病
（自建集 0.72 vs 公开集 0.100）在这里换了个形式复发。

现在默认 `--holdout deepset_test`：训练集里剔除留出集，指标分三档报告

  1. 交叉验证            —— 训练集内部，可信
  2. 留出集（未参与训练）  —— **唯一的泛化数字**
  3. 污染对照            —— 故意用含留出集的全量数据训练，量化"背答案"能虚高多少

用法：
    python scripts/train_lightweight.py
    python scripts/train_lightweight.py --dataset data/full.jsonl --only
    python scripts/train_lightweight.py --holdout deepset_test          # 默认
    python scripts/train_lightweight.py --holdout ""                    # 明确不隔离（仅做对照）
"""
from __future__ import annotations

import argparse
import json
import statistics
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from prompt_ids.eval.datasets import BUILTIN, Dataset  # noqa: E402
from prompt_ids.eval.metrics import Confusion, markdown_table  # noqa: E402

DEFAULT_OUT = Path(__file__).resolve().parent.parent / "models" / "lightweight.joblib"
REPORT_DIR = Path(__file__).resolve().parent.parent / "reports"
DEFAULT_HOLDOUT = "deepset_test"


def load_dataset(args: argparse.Namespace) -> Dataset:
    data = Dataset(()) if (args.only and args.dataset) else BUILTIN
    for spec in args.dataset or []:
        path = Path(spec)
        extra = Dataset.from_jsonl(path) if path.suffix == ".jsonl" else Dataset.from_csv(path)
        data = data.concat(extra)
        print(f"载入外部数据 {path.name}: {len(extra)} 条")
    return data


def build_pipeline():
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import Pipeline

    return Pipeline(
        [
            (
                "tfidf",
                TfidfVectorizer(
                    # char_wb 对中英混合、变形拼写、片段编码更鲁棒
                    analyzer="char_wb",
                    ngram_range=(2, 5),
                    min_df=1,
                    sublinear_tf=True,
                    lowercase=True,
                ),
            ),
            (
                "clf",
                LogisticRegression(
                    max_iter=2000,
                    C=8.0,
                    class_weight="balanced",
                    solver="liblinear",
                ),
            ),
        ]
    )


def fit_and_score(dataset: Dataset):
    """在给定数据上训练并返回 (model, 训练集上的拟合混淆矩阵)。"""
    model = build_pipeline()
    model.fit(dataset.texts, dataset.labels)
    proba = model.predict_proba(dataset.texts)[:, 1]
    preds = [int(p >= 0.5) for p in proba]
    return model, Confusion.from_pairs(dataset.labels, preds), proba


def score_on(model, dataset: Dataset) -> Confusion:
    if not len(dataset):
        return Confusion.from_pairs([], [])
    proba = model.predict_proba(dataset.texts)[:, 1]
    return Confusion.from_pairs(dataset.labels, [int(p >= 0.5) for p in proba])


def cross_validate(dataset: Dataset, folds: int) -> Confusion:
    from sklearn.model_selection import StratifiedKFold

    texts, labels = dataset.texts, dataset.labels
    positives = sum(labels)
    usable = min(folds, positives, len(labels) - positives)
    if usable < 2:
        return Confusion.from_pairs([], [])
    skf = StratifiedKFold(n_splits=usable, shuffle=True, random_state=42)
    y_true: list[int] = []
    y_pred: list[int] = []
    for train_idx, test_idx in skf.split(texts, labels):
        fold_model = build_pipeline()
        fold_model.fit([texts[i] for i in train_idx], [labels[i] for i in train_idx])
        y_true.extend(labels[i] for i in test_idx)
        y_pred.extend(int(p) for p in fold_model.predict([texts[i] for i in test_idx]))
    return Confusion.from_pairs(y_true, y_pred)


def _row(name: str, confusion: Confusion) -> list[str]:
    row = confusion.as_row()
    return [
        name,
        str(confusion.total),
        f"{row['precision']:.4f}",
        f"{row['recall']:.4f}",
        f"{row['f1']:.4f}",
        f"{row['false_positive_rate']:.4f}",
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description="训练轻量语义模型")
    parser.add_argument("--dataset", nargs="*", help="外部数据集（.jsonl 或 .csv）")
    parser.add_argument("--only", action="store_true", help="只用外部数据集，不拼接内置种子集")
    parser.add_argument("--holdout", default=DEFAULT_HOLDOUT,
                        help=f"不参与训练的 source（逗号分隔），默认 {DEFAULT_HOLDOUT}；传空串关闭隔离")
    parser.add_argument("--out", default=str(DEFAULT_OUT), help="模型输出路径")
    parser.add_argument("--report", default=str(REPORT_DIR / "lightweight.json"))
    parser.add_argument("--cv", type=int, default=5, help="交叉验证折数")
    parser.add_argument("--no-cv", action="store_true", help="跳过交叉验证")
    args = parser.parse_args()

    try:
        import joblib  # noqa: F401
        import sklearn  # noqa: F401
    except ImportError:
        print("缺少 scikit-learn/joblib，请先 pip install scikit-learn", file=sys.stderr)
        return 1

    data = load_dataset(args)
    counts = data.counts()
    print(f"数据池：{counts['total']} 条（攻击 {counts['attack']} / 正常 {counts['benign']}）")
    print(f"来源分布：{data.sources()}\n")

    holdout_sources = tuple(s.strip() for s in (args.holdout or "").split(",") if s.strip())
    train_ds = data.filter_sources(exclude=holdout_sources) if holdout_sources else data
    holdout_ds = data.filter_sources(include=holdout_sources) if holdout_sources else Dataset(())

    if holdout_sources:
        print(f"留出集（不参与训练）：{holdout_sources} -> {len(holdout_ds)} 条")
        print(f"训练集：{len(train_ds)} 条"
              f"（攻击 {train_ds.counts()['attack']} / 正常 {train_ds.counts()['benign']}）\n")
        missing = [s for s in holdout_sources if s not in data.sources()]
        if missing:
            print(f"注意：数据池里没有这些来源，留出集为空 —— {missing}\n")
    else:
        print("警告：已关闭留出集隔离，下面所有数字都含训练样本，**不能作为泛化结论**。\n")

    if not len(train_ds):
        print("训练集为空，无法训练", file=sys.stderr)
        return 1

    report: dict = {
        "holdout": list(holdout_sources),
        "pool": counts,
        "sources": data.sources(),
        "train": train_ds.counts(),
        "holdout_n": len(holdout_ds),
    }

    # ---------- 交叉验证（训练集内部） ----------
    if not args.no_cv:
        cv = cross_validate(train_ds, args.cv)
        if cv.total:
            print("交叉验证（训练集内部，可信）：")
            print(markdown_table(
                ["配置", "样本数", "Precision", "Recall", "F1", "误报率"],
                [_row(f"{args.cv} 折 CV", cv)], aligns="lrrrrr"))
            report["cross_validation"] = cv.as_row()
            report["cross_validation"]["total"] = cv.total
            print()

    # ---------- 正式训练 ----------
    model, fit_confusion, _ = fit_and_score(train_ds)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    import joblib

    joblib.dump(model, out)

    rows = [_row("训练集拟合", fit_confusion)]
    report["train_fit"] = fit_confusion.as_row()
    report["train_fit"]["total"] = fit_confusion.total

    # ---------- 留出集：唯一的泛化数字 ----------
    if len(holdout_ds):
        held = score_on(model, holdout_ds)
        rows.append(_row("留出集（泛化）", held))
        report["holdout"] = held.as_row()
        report["holdout"]["total"] = held.total

        # 污染对照：故意在含留出集的全部数据上训练，量化"背答案"虚高多少
        contaminated, _, _ = fit_and_score(data)
        dirty = score_on(contaminated, holdout_ds)
        rows.append(_row("留出集（污染对照）", dirty))
        report["holdout_contaminated"] = dirty.as_row()
        report["holdout_contaminated"]["total"] = dirty.total

    print(markdown_table(
        ["配置", "样本数", "Precision", "Recall", "F1", "误报率"], rows, aligns="lrrrrr"))

    if len(holdout_ds):
        clean, dirty = report["holdout"], report["holdout_contaminated"]
        print()
        print("结论：")
        print(f"  · 留出集 F1 = {clean['f1']:.4f}  <- 引用这个数")
        print(f"  · 污染对照 F1 = {dirty['f1']:.4f}  <- 用含留出集的数据训练后在同一批上测")
        gap = dirty["f1"] - clean["f1"]
        if gap > 0.01:
            print(f"  · 虚高 {gap:+.4f}：这就是把评测集混进训练集带来的水份，"
                  f"此前脚本默认这么干")
        else:
            print("  · 两者接近：本数据集上背答案的收益有限，但仍应以留出集数字为准")
        print(f"  · 训练集拟合 F1 = {report['train_fit']['f1']:.4f} 永远不作结论")

    print(f"\n模型已保存 -> {out}")
    wrong = [
        (s.text[:44], 0)
        for i, s in enumerate(train_ds.samples)
        if int(model.predict_proba([s.text])[0][1] >= 0.5) != s.label
    ]
    if wrong:
        print(f"训练集拟合不一致 {len(wrong)} 条（阈值 0.5），可用于检查标注歧义：")
        for text, _ in wrong[:10]:
            print(f"  {text}")
    print(f"训练集均值维度：{statistics.mean([len(t) for t in train_ds.texts]):.0f} 字符")

    report_path = Path(args.report)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"评测报告已保存 -> {report_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
