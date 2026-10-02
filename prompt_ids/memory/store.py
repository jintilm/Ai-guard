"""向量记忆库存储层。

FAISS 做精确内积检索（向量已归一化，内积即余弦相似度）；
装不上 FAISS 时退回 numpy 暴力检索 —— 几千条规模下两者性能差别不大，
重要的是主链路不能因为一个可选依赖而断掉。
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, asdict
from pathlib import Path

import numpy as np

try:  # 可选依赖
    import faiss

    _FAISS_OK = True
except Exception:  # pragma: no cover - 未安装时走 numpy 分支
    faiss = None
    _FAISS_OK = False

ATTACK = 1
FALSE_POSITIVE = 0


@dataclass(frozen=True, slots=True)
class MemoryItem:
    """记忆条目。刻意不存原文，只存指纹与元信息。"""

    fp: str
    label: int
    source: str = "auto"
    ts: float = 0.0
    note: str = ""

    def to_line(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False)

    @classmethod
    def from_line(cls, line: str) -> "MemoryItem":
        return cls(**json.loads(line))


@dataclass(frozen=True, slots=True)
class SearchHit:
    similarity: float
    item: MemoryItem


class VectorStore:
    def __init__(self, dim: int, use_faiss: bool = True, backend: str = "auto"):
        self.dim = dim
        self.backend = "faiss" if (use_faiss and _FAISS_OK) else "numpy"
        self._index = faiss.IndexFlatIP(dim) if self.backend == "faiss" else None
        self._matrix = np.zeros((0, dim), dtype=np.float32)
        self.items: list[MemoryItem] = []

    # ---------- 写入 ----------
    def add(self, vector: np.ndarray, item: MemoryItem) -> bool:
        vec = np.asarray(vector, dtype=np.float32).reshape(1, -1)
        if vec.shape[1] != self.dim:
            raise ValueError(f"向量维度 {vec.shape[1]} 与索引 {self.dim} 不符")
        norm = float(np.linalg.norm(vec))
        if norm > 0:
            vec = vec / norm
        if self._index is not None:
            self._index.add(vec)
        else:
            self._matrix = np.vstack([self._matrix, vec]) if len(self._matrix) else vec
        self.items.append(item)
        return True

    # ---------- 检索 ----------
    def search(self, vector: np.ndarray, k: int = 5) -> list[SearchHit]:
        if not self.items:
            return []
        vec = np.asarray(vector, dtype=np.float32).reshape(1, -1)
        norm = float(np.linalg.norm(vec))
        if norm > 0:
            vec = vec / norm
        k = min(k, len(self.items))

        if self._index is not None:
            scores, indices = self._index.search(vec, k)
            pairs = [(float(scores[0][i]), int(indices[0][i])) for i in range(k)]
        else:
            sims = (self._matrix @ vec[0]).astype(np.float32)
            top = np.argsort(-sims)[:k]
            pairs = [(float(sims[i]), int(i)) for i in top]

        hits = []
        for score, idx in pairs:
            if idx < 0 or idx >= len(self.items):
                continue
            hits.append(SearchHit(similarity=score, item=self.items[idx]))
        return hits

    # ---------- 维护 ----------
    def __len__(self) -> int:
        return len(self.items)

    def clear(self) -> None:
        if self._index is not None:
            self._index.reset()
        self._matrix = np.zeros((0, self.dim), dtype=np.float32)
        self.items.clear()

    def counts(self) -> dict[str, int]:
        attacks = sum(1 for i in self.items if i.label == ATTACK)
        return {"total": len(self.items), "attack": attacks, "false_positive": len(self.items) - attacks}

    def stats(self) -> dict:
        counts = self.counts()
        counts["backend"] = self.backend
        counts["dim"] = self.dim
        return counts

    # ---------- 持久化 ----------
    def save(self, directory: str | Path) -> Path:
        path = Path(directory)
        path.mkdir(parents=True, exist_ok=True)
        if self._index is not None:
            faiss.write_index(self._index, str(path / "index.faiss"))
        else:
            np.save(path / "vectors.npy", self._matrix)
        with (path / "items.jsonl").open("w", encoding="utf-8") as fh:
            for item in self.items:
                fh.write(item.to_line() + "\n")
        return path

    @classmethod
    def load(cls, directory: str | Path, dim: int | None = None) -> "VectorStore":
        path = Path(directory)
        index_file = path / "index.faiss"
        if index_file.exists() and _FAISS_OK:
            index = faiss.read_index(str(index_file))
            dim = index.d
        elif (path / "vectors.npy").exists():
            matrix = np.load(path / "vectors.npy")
            dim = matrix.shape[1] if dim is None else dim
        elif dim is None:
            raise FileNotFoundError(f"{path} 中没有可用的索引文件")

        store = cls(dim=dim, use_faiss=True)
        if index_file.exists() and _FAISS_OK:
            store._index = index
        else:
            store._matrix = np.load(path / "vectors.npy")

        items_file = path / "items.jsonl"
        if items_file.exists():
            store.items = [
                MemoryItem.from_line(line)
                for line in items_file.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
        return store


def make_item(text: str, label: int, source: str = "auto", note: str = "") -> MemoryItem:
    from prompt_ids.preprocess.guard import fingerprint

    return MemoryItem(
        fp=fingerprint(text),
        label=label,
        source=source,
        ts=round(time.time(), 3),
        note=note,
    )


def faiss_available() -> bool:
    return _FAISS_OK
