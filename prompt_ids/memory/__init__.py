"""向量记忆库 —— 记住见过的攻击，也记住自己犯过的错。

自进化闭环：
    检测 → 确认的攻击自动入库 → 下次遇到相似措辞直接认出 → 继续积累
    人工标记误报 → 写入负向记忆 → 同样文本再来时把分数压下去

    deberta 编码器复用 L3 语义模型（不额外占内存），
    装不上 faiss / transformers 时自动降级，主链路不受影响。
"""
from prompt_ids.memory.detector import (
    AUTO_LEARN_LEVELS,
    MemoryDetector,
)
from prompt_ids.memory.encoder import (
    DebertaEncoder,
    HashingEncoder,
    NullEncoder,
    TextEncoder,
    build_encoder,
)
from prompt_ids.memory.store import (
    ATTACK,
    FALSE_POSITIVE,
    MemoryItem,
    SearchHit,
    VectorStore,
    faiss_available,
    make_item,
)

__all__ = [
    "ATTACK",
    "AUTO_LEARN_LEVELS",
    "FALSE_POSITIVE",
    "DebertaEncoder",
    "HashingEncoder",
    "MemoryDetector",
    "MemoryItem",
    "NullEncoder",
    "SearchHit",
    "TextEncoder",
    "VectorStore",
    "build_encoder",
    "faiss_available",
    "make_item",
]
