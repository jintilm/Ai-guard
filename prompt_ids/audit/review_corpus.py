"""复核语料：把「人看过并定性」的原文单独落一份，供规则迭代取用。

为什么需要它：审计层**只存指纹**（刻意的隐私约定），所以从审计日志里永远拼不出
「这条误报当时那段文本长什么样」。而规则迭代要的就是原文 —— 没有它，复核闭环
只能产出一个数字，改不了规则。

所以这里单独开一份语料文件，并且：

- **必须显式配置路径才写**（`--review-corpus` / `ApiContext(review_corpus=...)`），
  默认不写。不配就等于没有这个数据面，不会偷偷落盘。
- 落盘的是**原文**，这是它与审计层的本质区别。因此：文件头部由
  `ReviewCorpus.header()` 写明用途；建议加进 `.gitignore`；不进任何报表。
- 写盘失败要响：复核本身已经成功（结论落审计、记忆层已吸收），但语料没写成，
  悄悄吞掉会让「反哺」这条链看起来是通的。
"""
from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path
from typing import Any

HEADER = {
    "type": "prompt-ids-review-corpus",
    "version": 1,
    "warning": "本文件含人工复核文本的**原文**。审计日志只存指纹，这里是刻意例外；"
               "请勿提交到版本库，用于规则迭代与过防御取证。",
}


class ReviewCorpus:
    """追加写 JSONL 的复核语料库。写失败不抛，但会记账（`errors`）。"""

    def __init__(self, path: str | Path | None = None, *, header: bool = True):
        self.path = Path(path) if path else None
        self.lock = threading.Lock()
        self.written = 0
        self.errors: list[str] = []
        if self.path and header and not self.path.exists():
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._append_line(json.dumps(HEADER, ensure_ascii=False) + "\n")

    @property
    def enabled(self) -> bool:
        return self.path is not None

    def add(self, *, text: str, is_attack: bool, fp: str, patterns: tuple[str, ...] = (),
            top_pattern: str = "", level: str = "", score: float = 0.0,
            reviewer: str = "", note: str = "") -> bool:
        """记一条。返回是否真的写进去了（调用方要能看到 False）。"""
        if self.path is None:
            return False
        row: dict[str, Any] = {
            "ts": round(time.time(), 3),
            "text": text,
            "label": 1 if is_attack else 0,
            "fp": fp,
            "level": level,
            "score": score,
            "patterns": list(patterns),
            "top_pattern": top_pattern,
            "reviewer": reviewer,
            "source": "review",
            "category": f"review:{top_pattern}" if top_pattern else "review:unknown",
            "note": note,
        }
        try:
            with self.lock:
                self._append_line(json.dumps(row, ensure_ascii=False) + "\n")
                self.written += 1
            return True
        except OSError as exc:  # 旁路写盘：记录并继续，绝不拖垮复核
            with self.lock:
                self.errors.append(f"{type(exc).__name__}: {exc}")
            return False

    def _append_line(self, line: str) -> None:
        assert self.path is not None
        with open(self.path, "a", encoding="utf-8", newline="") as fh:
            fh.write(line)

    def stats(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "path": str(self.path) if self.path else "",
            "written": self.written,
            "errors": self.errors[-3:],
        }


def add_to_gitignore(path: str | Path) -> bool:
    """把语料路径写进 .gitignore。**只加精确路径**，不用通配符 ——
    通配符会顺手盖掉别的数据文件，那是不可逆的副作用。"""
    target = Path(path)
    root = Path(__file__).resolve().parents[2]
    try:
        relative = target.resolve().relative_to(root)
    except ValueError:
        return False
    ignore = root / ".gitignore"
    line = str(relative).replace(os.sep, "/")
    if ignore.exists() and line in ignore.read_text(encoding="utf-8").splitlines():
        return False
    with open(ignore, "a", encoding="utf-8") as fh:
        if not ignore.read_text(encoding="utf-8").endswith("\n"):
            fh.write("\n")
        fh.write(f"{line}\n# 复核语料含原文，刻意不入库\n")
    return True
