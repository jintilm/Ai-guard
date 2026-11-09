"""向量记忆库存储层。

FAISS 做精确内积检索（向量已归一化，内积即余弦相似度）；
装不上 FAISS 时退回 numpy 暴力检索 —— 几千条规模下两者性能差别不大，
重要的是主链路不能因为一个可选依赖而断掉。
"""
from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass
from pathlib import Path

import numpy as np

try:  # 可选依赖
    import faiss

    _FAISS_OK = True
except Exception:  # noqa: BLE001  # pragma: no cover - 未安装时走 numpy 分支
    faiss = None
    _FAISS_OK = False

ATTACK = 1
FALSE_POSITIVE = 0

#: numpy 后端的最小预分配容量。容量按**翻倍**增长，所以 n 次写入的总拷贝量
#: 是 O(n) 而不是 O(n²)（见 `VectorStore._append` 的注释）。
_MIN_CAPACITY = 64


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
    def from_line(cls, line: str) -> MemoryItem:
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
        # `_matrix` 是**预分配缓冲**，只有前 `_n` 行有效；尾部是未使用的空位。
        # ⚠ 任何遍历/保存/检索都必须切到 `[:_n]`，否则会把空行当成真条目。
        self._matrix = np.zeros((0, dim), dtype=np.float32)
        self._n = 0
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
            self._append(vec)
        self.items.append(item)
        return True

    def _append(self, vec: np.ndarray) -> None:
        """往 numpy 缓冲尾部写一行，容量不够时翻倍。

        原来是 `np.vstack([self._matrix, vec])` —— 每次写入都新建一个
        (n+1, dim) 数组并把已有的 n 行拷过去，于是 n 次写入是 O(n²)。
        实测（dim=768，float32）：5k 条 7.25s、10k 条 29.74s、20k 条 119.84s，
        单条摊薄成本 0.22ms → 2.4ms。而 `Pipeline.scan()` 在结尾是**同步**
        调 `learn()` 的，这份成本直接摊到每一个触发学习的请求上。
        """
        capacity = self._matrix.shape[0]
        if self._n >= capacity:
            grown = np.zeros((max(_MIN_CAPACITY, capacity * 2), self.dim), dtype=np.float32)
            if self._n:
                grown[: self._n] = self._matrix[: self._n]
            self._matrix = grown
        self._matrix[self._n] = vec[0]
        self._n += 1

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
            # 只算有效行。带着预分配的空行一起算的话，那些向量是全零 ⇒
            # 相似度 0.0，会**压过**真实的负相关条目挤进 top-k。
            sims = (self._matrix[: self._n] @ vec[0]).astype(np.float32)
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
        self._n = 0
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
            # 只存有效行。把预分配的空行一起写进 .npy，下次 load 就会多出
            # 一堆零向量（它们会参与检索，见 search 里的注释）。
            np.save(path / "vectors.npy", self._matrix[: self._n])
        with (path / "items.jsonl").open("w", encoding="utf-8") as fh:
            for item in self.items:
                fh.write(item.to_line() + "\n")
        return path

    @classmethod
    def load(cls, directory: str | Path, dim: int | None = None) -> VectorStore:
        path = Path(directory)
        index_file = path / "index.faiss"
        matrix = None
        if index_file.exists() and _FAISS_OK:
            index = faiss.read_index(str(index_file))
            dim = index.d
        elif (path / "vectors.npy").exists():
            matrix = np.load(path / "vectors.npy")
            dim = matrix.shape[1] if dim is None else dim
        elif dim is None or index_file.exists():
            # 第二个条件：存档是 FAISS 索引但本机没装 faiss —— 别报「文件不存在」，
            # 那会把「缺可选依赖」误诊成「路径写错了」。
            raise FileNotFoundError(
                f"{path} 中没有可用的索引文件"
                + ("（index.faiss 存在但未安装 faiss，请 pip install 'prompt-ids[memory]'）"
                   if index_file.exists() else ""))

        store = cls(dim=dim, use_faiss=True)
        if index_file.exists() and _FAISS_OK:
            store._index = index
        else:
            store._matrix = matrix
            store._n = len(matrix)
            # 从 numpy 存档恢复时必须**清掉**构造函数顺手建的空 FAISS 索引：
            # 留着它的话 search()/add() 全走索引分支，而索引里一条都没有 ⇒
            # 「装了 faiss 的机器加载 numpy 存档」会得到一个看起来空空的记忆库。
            store._index = None
            store.backend = "numpy"

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
