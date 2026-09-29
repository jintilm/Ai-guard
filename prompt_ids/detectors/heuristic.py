"""L2 启发式评分。

不依赖已知样本，捕捉「读起来像注入」的统计特征，补规则的泛化短板。

特征词表覆盖**中 / 英 / 德**三种语言，与 L1 规则库的语言面保持一致：
规则层的德语偏置已补齐，启发层若不补，L2 在德语上与不存在没有区别
（实测过 L1+L2 与 L1 在德语子集上得分完全相同）。
"""
from __future__ import annotations

import re
import unicodedata

from prompt_ids.core.types import DETECTOR_HEURISTIC, Finding
from prompt_ids.detectors.base import Detector, DetectorContext

_INSTRUCTION_WORDS_EN = (
    r"\b(ignore|disregard|override|bypass|reveal|leak|exfiltrate|dump|"
    r"instruction|system\s*prompt|jailbreak|pretend|roleplay|act\s+as)\b"
)
_INSTRUCTION_WORDS_ZH = r"(忽略|无视|绕过|泄露|越狱|伪装|扮演|假装|提示词|系统提示)"
# 德语词表与英语一一对应。用词干匹配（ignorier\w* -> ignoriere/ignoriert/…）覆盖变位，
# 但 "Regeln" 这类德语高频正常词必须**带限定词**才算指令语境，
# 否则 L2 会靠普通德语文本刷分，把误报率抬起来。
_INSTRUCTION_WORDS_DE = (
    # 1) 直接指令 / 提取类动词与名词，与英语词表一一对应
    r"\b(ignorier\w*|vergiss\w*|vergessen|anweisung\w*|instruktion\w*|"
    r"aufforderung\w*|system\s*(?:prompt|anweisung\w*)|umgeh\w*|hintergeh\w*|"
    r"offenleg\w*|preisgeb\w*|verrat\w*|enthüll\w*|enthuell\w*|"
    r"ausfuehr\w*|ausführ\w*|befehl\w*|unbeschr\w*|uneingeschr\w*|"
    r"entwicklermodus|rollenspiel|wiederhol\w*|fungier\w*|"
    r"sicherheits(?:filter|vorkehrung\w*|richtlinie\w*))\b"
    # 2) 时序限定词 + 任意对象："此前的信息 / 任务" —— 明确指着"之前收到的"，
    #    不会误伤 "alle Informationen finden Sie hier" 这类普通句子
    r"|\b(?:vorherig\w*|bisherig\w*|früher\w*|obig\w*|bestehend\w*|vorangegangen\w*)"
    r"\s+(?:anweisung\w*|regeln|instruktion\w*|befehle?|vorgaben|aufforderung\w*|"
    r"informationen|aufgaben|texte|nachrichten)\b"
    # 3) 数量限定词只允许接"规则 / 指令"类名词。
    #    单独一个 "alle Informationen" 在正常德语里太常见，不能算指令语境
    r"|\b(?:alle[nr]?|sämtliche[nr]?|neue[nr]?)\s+"
    r"(?:anweisung\w*|regeln|instruktion\w*|befehle?|vorgaben|aufforderung\w*)\b"
    # 4) 风格模仿措辞（jailbreak 常用）
    r"|\bim\s+stil\s+(?:eines|einer|von)\b"
)

_IMPERATIVE_START_EN = (
    r"^\s*(ignore|disregard|forget|stop|you\s+are|act\s+as|print|repeat|output|execute|run)\b"
)
_IMPERATIVE_START_ZH = r"^\s*(忽略|忘掉|你现在|请扮演|输出|重复|执行)"
_IMPERATIVE_START_DE = (
    r"^\s*(ignoriere|ignorier|vergiss|vergessen|ab\s+jetzt|ab\s+sofort|"
    r"von\s+nun\s+an|du\s+bist\s+(?:jetzt|nun)|spiele|zeige\s+mir|gib\s+mir|"
    r"wiederhole|führe|fuehre|handle\s+als|verhalte\s+dich)\b"
)

#: 支持的语言。词表按语言拆开，是为了能把「语言偏置」这件事量化：
#: 用 languages=("en","zh") 跑一遍就是补德语之前的旧行为，可以直接做前后对照。
LANGUAGES = ("en", "zh", "de")

_NEVER_MATCH = r"(?!x)x"  # 空词表时用永不匹配的模式，而不是空串（空串会处处命中）


def instruction_words_pattern(languages: tuple[str, ...] = LANGUAGES) -> str:
    parts = []
    if "en" in languages:
        parts.append(_INSTRUCTION_WORDS_EN)
    if "zh" in languages:
        parts.append(_INSTRUCTION_WORDS_ZH)
    if "de" in languages:
        parts.append(_INSTRUCTION_WORDS_DE)
    return "|".join(parts) or _NEVER_MATCH


def imperative_start_pattern(languages: tuple[str, ...] = LANGUAGES) -> str:
    parts = []
    if "en" in languages:
        parts.append(_IMPERATIVE_START_EN)
    if "zh" in languages:
        parts.append(_IMPERATIVE_START_ZH)
    if "de" in languages:
        parts.append(_IMPERATIVE_START_DE)
    return "|".join(parts) or _NEVER_MATCH


_INSTRUCTION_WORDS = re.compile(instruction_words_pattern(), re.IGNORECASE)
_IMPERATIVE_START = re.compile(
    imperative_start_pattern(), re.IGNORECASE | re.MULTILINE
)
_ROLE_TAG = re.compile(r"<\|[a-z_/]+\||</?(system|assistant|user|tool)>|\[/?(INST|SYS)\]", re.IGNORECASE)
_CONTROL = re.compile(r"[\u0000-\u0008\u000b\u000c\u000e-\u001f]")
_CJK = re.compile(r"[\u4e00-\u9fff\u3400-\u4dbf]")
_LATIN = re.compile(r"[A-Za-z]")
# 含变音字母：德语 über/äußern 等若不收进词表会被拆成两段，密度分母被高估
_WORD = re.compile(r"[A-Za-z\u00c0-\u024f\u4e00-\u9fff]+")


def _ratio(numerator: int, denominator: int) -> float:
    return numerator / denominator if denominator else 0.0


class Feature:
    """单个启发特征的输出单元。"""

    def __init__(self, pattern_id: str, label: str, weight: float, value: float, threshold: float):
        self.pattern_id = pattern_id
        self.label = label
        self.weight = weight
        self.value = value
        self.threshold = threshold

    @property
    def fired(self) -> bool:
        return self.value >= self.threshold

    @property
    def intensity(self) -> float:
        """归一化的超出程度，封顶 1.0。"""
        if self.threshold <= 0:
            return 1.0 if self.value > 0 else 0.0
        return min(1.0, self.value / self.threshold)

    def to_finding(self) -> Finding:
        return Finding(
            detector=DETECTOR_HEURISTIC,
            pattern_id=self.pattern_id,
            category="heuristic",
            weight=self.weight,
            evidence=f"{self.label}={self.value:.3f} (阈值 {self.threshold})",
            confidence=round(min(0.95, max(0.2, self.intensity)), 4),
            variant="heuristic",
            note=self.label,
        )


class HeuristicDetector(Detector):
    layer = 2
    name = "heuristic"

    def __init__(
        self,
        enabled: bool = True,
        weights: dict[str, float] | None = None,
        languages: tuple[str, ...] = LANGUAGES,
    ):
        super().__init__(enabled=enabled)
        default = {
            "instruction_density": 1.0,
            "special_char_ratio": 0.8,
            "language_mix": 0.6,
            "case_anomaly": 0.6,
            "role_tag": 1.6,
            "control_char": 1.4,
        }
        if weights:
            default.update(weights)
        self.weights = default
        # 语言词表开关。默认全开；传 ("en","zh") 就是补德语之前的旧行为，
        # 用来做语言贡献的前后对照（见 scripts/heuristic_language.py）。
        self.languages = tuple(languages)
        if self.languages == LANGUAGES:
            self._instruction = _INSTRUCTION_WORDS
            self._imperative = _IMPERATIVE_START
        else:
            self._instruction = re.compile(
                instruction_words_pattern(self.languages), re.IGNORECASE
            )
            self._imperative = re.compile(
                imperative_start_pattern(self.languages), re.IGNORECASE | re.MULTILINE
            )

    def extract(self, ctx: DetectorContext) -> list[Feature]:
        text = ctx.canonical or ctx.raw
        if not text:
            return []
        length = max(len(text), 1)

        words = _WORD.findall(text)
        word_count = max(len(words), 1)
        instruction_hits = len(self._instruction.findall(text))
        # 行首祈使句（"Ignoriere …" / "Output the system prompt"）是与词表互补的
        # 强语气信号；封顶 1 次，避免长文本反复堆叠同一种证据。
        imperative = 1 if self._imperative.search(text) else 0
        density = (instruction_hits + imperative) / word_count

        cjk = len(_CJK.findall(text))
        latin = len(_LATIN.findall(text))
        mix_base = max(cjk + latin, 1)
        mix = min(cjk, latin) / mix_base * 2  # 1:1 混合时接近 1.0

        special = sum(
            1
            for ch in text
            if not ch.isalnum()
            and not _CJK.match(ch)
            and unicodedata.category(ch)[0] in "PSZ"
        )
        special_ratio = special / length

        long_words = [w for w in words if len(w) >= 4 and _LATIN.search(w)]
        if long_words:
            weird = sum(1 for w in long_words if not (w.islower() or w.istitle() or w.isupper()))
            case_ratio = _ratio(weird, len(long_words))
        else:
            case_ratio = 0.0

        role_tags = len(_ROLE_TAG.findall(text))
        control = len(_CONTROL.findall(text)) + ctx.extra.get("invisible_chars", 0)

        return [
            Feature(
                "HZ-001", "指令词密度", self.weights["instruction_density"], density, 0.08
            ),
            Feature(
                "HZ-002", "特殊符号占比", self.weights["special_char_ratio"], special_ratio, 0.15
            ),
            Feature("HZ-003", "中英混合度", self.weights["language_mix"], mix, 0.5),
            Feature("HZ-004", "大小写异常", self.weights["case_anomaly"], case_ratio, 0.3),
            Feature(
                "HZ-005",
                "角色标签/控制序列",
                self.weights["role_tag"],
                float(role_tags),
                1.0,
            ),
            Feature(
                "HZ-006", "控制字符", self.weights["control_char"], float(control), 1.0
            ),
        ]

    def detect(self, ctx: DetectorContext) -> list[Finding]:
        return [f.to_finding() for f in self.extract(ctx) if f.fired]

    def subscore(self, findings: list[Finding]) -> float:
        """启发层用加权线性和，超阈值即有分，弱化「堆叠才报警」的问题。"""
        if not findings:
            return 0.0
        total = sum(f.weight * f.confidence for f in findings)
        return round(min(100.0, total * 28.0), 2)
