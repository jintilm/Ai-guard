"""记忆检测器 + 自进化闭环。

自进化不是"把什么都记住"，而是有准入条件的：

    1. 只有当判定足够确定时才自动入库（等级达标 + 至少一条强证据）
    2. 库里已有高度相似的向量则不再重复插入
    3. 人工反馈（误报标记）会写入 label=0 的记忆，
       下次同样的文本再来时，记忆层会把分数往下压 —— 这是"记住自己犯过错"

双向记忆（记住攻击 + 记住误报）才让"进化"这个词站得住，
否则只是个会无限膨胀的样本仓库。
"""
from __future__ import annotations

import threading
import time
from typing import Any

from prompt_ids.core.types import DETECTOR_MEMORY, Finding
from prompt_ids.detectors.base import Detector, DetectorContext
from prompt_ids.memory.encoder import TextEncoder, build_encoder
from prompt_ids.memory.store import (
    ATTACK,
    FALSE_POSITIVE,
    MemoryItem,
    VectorStore,
    make_item,
)
from prompt_ids.preprocess.normalizer import Normalizer

# 自动入库的等级门槛
AUTO_LEARN_LEVELS = frozenset({"high", "critical"})
# 达到即视为"强证据"：规则权重或语义概率
STRONG_RULE_WEIGHT = 8.0
STRONG_SEMANTIC_PROB = 0.90


class MemoryDetector(Detector):
    layer = 4
    name = "memory"

    def __init__(
        self,
        store: VectorStore | None = None,
        encoder: TextEncoder | None = None,
        encoder_kind: str = "auto",
        backend=None,
        threshold: float = 0.86,
        top_k: int = 5,
        auto_learn: bool = True,
        dedup_threshold: float = 1.0,
        max_items: int = 20_000,
        enabled: bool = True,
    ):
        super().__init__(enabled=enabled)
        self.threshold = threshold
        self.top_k = top_k
        self.auto_learn = auto_learn
        # dedup_threshold 是可选的"近重复"闸门，默认 1.0 即关闭（只按规范指纹去重）。
        # 不要改回 0.97：L3 的 DeBERTa 取的是分类头上一层 CLS，
        # 同类样本在这个空间里高度压缩 —— 实测英文攻击与中文攻击 cos=0.993、
        # 越狱与提权 cos=0.999，而正常样本最高只有 0.738。
        # 0.97 的去重线落在攻击簇内部，会把真正不同的攻击当重复丢掉，
        # 自进化库因此只攒得下一两个样本。规范指纹（NFKC + 同形字折叠 +
        # 不可见字符剥离 + 空白折叠）本身已经吸收了最常见的变体花招。
        self.dedup_threshold = dedup_threshold
        self.max_items = max_items

        # backend：复用 L3 已加载的模型句柄。不传的话 build_encoder("auto")
        # 会自己 new 一个 LocalModelBackend，白吃一份 700MB 权重，
        # 而且 warmup 只预热得到语义层那一份，记忆层仍要付冷启动
        self.encoder = encoder or build_encoder(encoder_kind, backend=backend)
        dim = getattr(self.encoder, "dim", 256) or 256
        self.store = store or VectorStore(dim=dim)
        # 索引维度与编码器不一致（换了编码器 / 加载了旧库）时，检索会直接
        # 抛维度错误把整条流水线带崩。宁可把本层降级关掉并留痕。
        self.dim_mismatch: tuple[int, int] | None = None
        if self.store.dim != dim:
            self.dim_mismatch = (self.store.dim, dim)
            self.enabled = False
        # 写入与检索必须走同一套归一化，否则永远对不上：
        # 全角逗号「，」被 NFKC 转成半角就让 DeBERTa 相似度从 0.99 掉到 0.57
        self.normalizer = Normalizer()

        self.last_hits: list = []
        self.learned = 0
        self.deduped = 0
        self.rejected = 0
        self.queries = 0
        # 每次成功写入后递增，供流水线判断缓存是否过期
        self.version = 0
        # learn 是「先查重再写入」的 check-then-act，并发下会重复插入
        self._lock = threading.Lock()
        # 已入库的规范指纹，用于 O(1) 判重（见 _known_fps 的自愈逻辑）
        self._fp_set: set[str] = set()

    def _normalize(self, text: str) -> str:
        return self.normalizer.canonical(text or "").strip()

    def _known_fps(self) -> set[str]:
        """已入库指纹集合。

        与库容量不一致时重建：外部可能直接 store.clear() 或换过 store，
        与其在每个调用点手动同步，不如让这里自愈。
        """
        if len(self._fp_set) != len(self.store):
            self._fp_set = {item.fp for item in self.store.items}
        return self._fp_set

    # ---------- 生命周期 ----------
    def warmup(self) -> None:
        """预加载编码器后端。

        记忆层本身没有独立模型，但复用 L3 后端时首次编码会触发权重加载；
        没有这一步，`Pipeline.warmup()` 就只预热了语义层，记忆层那份
        冷启动仍要落在首个真实请求上，把预算顶穿。
        """
        backend = getattr(self.encoder, "_backend", None)
        warm = getattr(backend, "warmup", None)
        if not callable(warm):
            return
        try:
            warm()
        except Exception:
            # 预加载失败不回滚：运行期 encode 会失败并让本层静默降级
            pass

    # ---------- 能力判定 ----------
    @property
    def available(self) -> bool:
        return bool(self.encoder and self.encoder.available)

    # ---------- 检测 ----------
    def detect(self, ctx: DetectorContext) -> list[Finding]:
        if not self.enabled or not self.available or len(self.store) == 0:
            self.last_hits = []
            return []
        text = self._normalize(ctx.canonical or ctx.raw or "")
        if not text:
            return []

        try:
            vector = self.encoder.encode_one(text)
        except Exception:
            self.last_hits = []
            return []

        self.queries += 1
        hits = self.store.search(vector, k=self.top_k)
        self.last_hits = hits
        if not hits:
            return []

        best = max(hits, key=lambda h: h.similarity)
        if best.similarity < self.threshold:
            return []

        if best.item.label == FALSE_POSITIVE:
            # 记住了"这条曾误判"，不产生命中项，由 contribution 把总分压下去
            return []

        # 已知攻击：相似度越高、原样本证据越强，权重越高
        weight = min(9.0, 6.0 + best.similarity * 3.0)
        return [
            Finding(
                detector=DETECTOR_MEMORY,
                pattern_id="ME-001",
                category="memory",
                weight=round(weight, 2),
                evidence=f"与已知攻击样本 {best.item.fp[:12]} 相似度 {best.similarity:.3f}",
                confidence=round(min(best.similarity, 1.0), 4),
                variant="memory",
                note=f"记忆库命中（来源 {best.item.source}）",
            )
        ]

    def subscore(self, findings: list[Finding]) -> float:
        if not findings:
            return 0.0
        return round(min(100.0, max(f.confidence for f in findings) * 100.0), 2)

    def contribution(self) -> float | None:
        """供决策层做乘性调节：

        - 命中已知攻击 → 高分（把总分往上带）
        - 命中已知误报 → 低分（把总分往下压）
        - 没命中 → None（不参与）
        """
        if not self.last_hits:
            return None
        best = max(self.last_hits, key=lambda h: h.similarity)
        if best.similarity < self.threshold:
            return None
        if best.item.label == FALSE_POSITIVE:
            return round(max(0.0, (1.0 - best.similarity) * 20.0), 2)
        return round(min(100.0, best.similarity * 100.0), 2)

    # ---------- 自进化 ----------
    def should_learn(self, result) -> bool:
        """自动入库的准入条件：等级达标，且至少有一条强证据。"""
        if not self.auto_learn or not self.enabled:
            return False
        if result.level.value not in AUTO_LEARN_LEVELS:
            return False
        strong = any(
            (f.weight >= STRONG_RULE_WEIGHT and f.confidence >= 0.85)
            or (f.detector == "semantic" and f.confidence >= STRONG_SEMANTIC_PROB)
            for f in result.findings
        )
        return strong

    def learn(self, text: str, result=None, label: int = ATTACK, source: str = "auto") -> bool:
        """写入记忆。返回是否真的入库。

        result 为 None 时表示外部（人工反馈/评测集）直接灌入，跳过准入判断。
        整体加锁：查重与写入之间不能有其他线程插入，否则去重失效。
        """
        with self._lock:
            return self._learn_locked(text, result, label, source)

    def _learn_locked(self, text: str, result, label: int, source: str) -> bool:
        if not self.enabled or not self.available:
            return False
        if result is not None and not self.should_learn(result):
            self.rejected += 1
            return False
        if len(self.store) >= self.max_items:
            self.rejected += 1
            return False

        text = self._normalize(text)
        if not text:
            return False

        item = make_item(text, label=label, source=source)
        # 判重按规范指纹走：_normalize 已经吸收了大写、空白、全角、同形字、
        # 零宽字符这些廉价花招，所以同一个样本换个写法也认得出是同一个；
        # 而真·不同攻击的指纹必然不同，不会被误伤（嵌入相似度会）。
        if item.fp in self._known_fps():
            self.deduped += 1
            return False

        try:
            vector = self.encoder.encode_one(text)
        except Exception:
            return False

        # 可选的近重复闸门（默认 1.0 关闭，理由见 __init__ 的说明）
        if self.dedup_threshold < 1.0:
            existing = self.store.search(vector, k=1)
            if existing and existing[0].similarity >= self.dedup_threshold:
                self.deduped += 1
                return False

        note = ""
        if result is not None:
            note = f"auto level={result.level.value} score={result.score:.1f}"
        if note:
            item = make_item(text, label=label, source=source, note=note)
        self.store.add(vector, item)
        self._known_fps().add(item.fp)
        self.learned += 1
        self.version += 1  # 记忆变了，流水线里的缓存必须失效
        return True

    def learn_many(self, texts: list[str], label: int = ATTACK,
                   source: str = "bulk") -> int:
        """批量灌入（评测集/历史样本），不受等级准入限制。"""
        ok = 0
        for text in texts:
            ok += self.learn(text, label=label, source=source)
        return ok

    def feedback(self, text: str, is_attack: bool, note: str = "") -> bool:
        """人工反馈接口：误报标记会写成 label=0 的记忆，用于后续降噪。"""
        return self.learn(
            text,
            label=ATTACK if is_attack else FALSE_POSITIVE,
            source="feedback",
        )

    # ---------- 运维 ----------
    def stats(self) -> dict[str, Any]:
        data = self.store.stats()
        data.update({
            "encoder": self.encoder.kind if self.encoder else "none",
            "available": self.available,
            "threshold": self.threshold,
            "auto_learn": self.auto_learn,
            "dedup_threshold": self.dedup_threshold,
            "dedup_mode": "fingerprint" if self.dedup_threshold >= 1.0 else "fingerprint+vector",
            "queries": self.queries,
            "learned": self.learned,
            "deduped": self.deduped,
            "rejected": self.rejected,
        })
        if self.dim_mismatch is not None:
            data["dim_mismatch"] = f"index={self.dim_mismatch[0]} encoder={self.dim_mismatch[1]}"
        return data

    def save(self, directory: str) -> None:
        self.store.save(directory)

    @classmethod
    def load(
        cls,
        directory: str,
        encoder_kind: str = "auto",
        backend=None,
        **kwargs,
    ) -> "MemoryDetector":
        store = VectorStore.load(directory)
        encoder = build_encoder(encoder_kind, backend=backend)
        return cls(store=store, encoder=encoder, **kwargs)
