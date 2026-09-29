"""预处理层出口：一次调用拿到「规范化文本 + 全部解码变体」。"""
from __future__ import annotations

from prompt_ids.core.types import Variant
from prompt_ids.preprocess.decoder import DecodeExpander
from prompt_ids.preprocess.normalizer import Normalizer


class Preprocessor:
    def __init__(
        self,
        normalizer: Normalizer | None = None,
        expander: DecodeExpander | None = None,
    ):
        self.normalizer = normalizer or Normalizer()
        self.expander = expander or DecodeExpander()

    def variants(self, text: str) -> list[Variant]:
        """变体列表：首项为原文规范形式，其后为「解码 × 挤压」组合。"""
        base_variants = self.normalizer.variants(text)
        # 变体优先级：原样 > 单字符重组 > 挤压
        root_labels = ["original", "reglued", "squeezed"]
        root_kinds = [
            root_labels[i] if i < len(root_labels) else f"norm{i}"
            for i in range(len(base_variants))
        ]

        out: list[Variant] = []
        seen: set[str] = set()
        for root_text, kind in zip(base_variants, root_kinds):
            for child in self.expander.expand(root_text):
                child_kind = kind if child.kind == "original" else f"{kind}+{child.kind}"
                key = child.text
                if key in seen:
                    continue
                seen.add(key)
                out.append(Variant(kind=child_kind, text=child.text, hops=child.hops))
        return out
