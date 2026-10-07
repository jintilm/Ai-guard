"""句向量编码 —— 记忆库的底座。

三档策略，缺什么就往下降，主链路永不因为编码器不可用而中断：

    deberta  → 复用 L3 语义模型取 CLS 向量（768 维，语义鲁棒）
    hashing  → char n-gram 哈希（零依赖，256 维，纯词形相似）
    none     → 装不上 numpy 时彻底关闭，由上层降级

用 `deberta` 时**不额外加载模型**：直接复用 L3 已加载的 backend。
"""
from __future__ import annotations

from abc import ABC, abstractmethod

import numpy as np


def _numpy_ready() -> bool:
    """numpy 是本模块的**硬依赖**（顶层就 import 了），所以这里恒为 True。

    ⚠ **这个函数与其下面的 `if not _numpy_ready(): return NullEncoder()`
    是不可达的死代码**（2026-10 发现并记录在此）。原因：
    numpy 在 `pyproject.toml` 的 `[project].dependencies` 里而不是某个 extra
    —— 2026-10 专门修过一次「numpy 只声明在 `[memory]` extra 导致
    `pip install .` 连纯规则层都起不来」的问题。
    于是 numpy 缺失时**本模块根本 import 不了**，`_numpy_ready()` 无从调用。

    保留它而不是删掉：将来若真要把 numpy 变回可选依赖，这里就是那个开关。
    但**现在不要根据它的返回值写新逻辑** —— 它不反映任何真实状态。

    （刻意**不用** `_importable()`：那是为了 transformers/torch/sklearn 这类
    真正可选的依赖设计的，而 numpy 不是可选项。）
    """
    return True


class TextEncoder(ABC):
    kind: str = "abstract"
    dim: int = 0

    @abstractmethod
    def encode(self, texts: list[str]) -> np.ndarray:
        """返回 (n, dim) 且已 L2 归一化的矩阵。"""

    def encode_one(self, text: str) -> np.ndarray:
        return self.encode([text])[0]

    @property
    def available(self) -> bool:
        return True


class HashingEncoder(TextEncoder):
    """char n-gram 哈希向量：零依赖、毫秒级，对措辞变体有一定鲁棒性。"""

    kind = "hashing"

    def __init__(self, dim: int = 256, ngram: tuple[int, ...] = (3, 4, 5)):
        self.dim = dim
        self.ngram = tuple(ngram)

    def _grams(self, text: str):
        padded = " " + text.lower() + " "
        for n in self.ngram:
            for i in range(max(0, len(padded) - n + 1)):
                yield padded[i:i + n]

    def encode(self, texts: list[str]) -> np.ndarray:
        import zlib

        out = np.zeros((len(texts), self.dim), dtype=np.float32)
        for row, text in enumerate(texts):
            for gram in self._grams(text or ""):
                out[row, zlib.crc32(gram.encode("utf-8")) % self.dim] += 1.0
        norms = np.linalg.norm(out, axis=1, keepdims=True)
        out = out / np.clip(norms, 1e-12, None)
        return out


class DebertaEncoder(TextEncoder):
    """复用 L3 本地模型取 CLS 向量。语义相似度最强，但依赖 transformers。"""

    kind = "deberta"
    dim = 768

    def __init__(self, backend=None):
        self._backend = backend
        self.dim = 768

    def _resolve(self):
        if self._backend is not None:
            return self._backend
        try:
            from prompt_ids.detectors.semantic.local import LocalModelBackend
        # 说明（抑制见下一行行尾的 noqa）：没装 transformers/torch 时退回别的后端，
        # 不该让整个记忆层不可用。
        except Exception:  # noqa: BLE001
            return None
        return LocalModelBackend()

    def encode(self, texts: list[str]) -> np.ndarray:
        backend = self._resolve()
        if backend is None or not backend.is_available():
            raise RuntimeError("DeBERTa 编码器不可用")
        vectors = backend.encode(list(texts))
        if vectors is None:
            raise RuntimeError("DeBERTa 编码失败")
        self.dim = vectors.shape[1]
        return vectors.astype(np.float32)

    @property
    def available(self) -> bool:
        backend = self._resolve()
        return bool(backend and backend.is_available())


class NullEncoder(TextEncoder):
    kind = "none"

    def encode(self, texts: list[str]) -> np.ndarray:
        raise RuntimeError("编码器不可用")

    @property
    def available(self) -> bool:
        return False


def build_encoder(kind: str = "auto", backend=None, dim: int = 256) -> TextEncoder:
    """auto：能用 DeBERTa 就用，否则退回 hashing。"""
    if not _numpy_ready():
        return NullEncoder()
    key = (kind or "auto").lower()
    if key in ("hashing", "hash"):
        return HashingEncoder(dim=dim)
    if key in ("deberta", "local", "transformer"):
        return DebertaEncoder(backend=backend)
    if key == "none":
        return NullEncoder()
    # auto
    deberta = DebertaEncoder(backend=backend)
    return deberta if deberta.available else HashingEncoder(dim=dim)
