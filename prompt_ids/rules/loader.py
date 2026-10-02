"""YAML 规则加载器。

职责：加载 → 校验 → 预编译 → 按档路由。
同一 pattern_id 只保留一次，否则单次攻击会被重复计分导致分数虚高。
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Iterator, Sequence

import yaml

from prompt_ids.rules import engine as _engine
from prompt_ids.rules.validators import get_validator, names

DEFAULT_RULES_DIR = Path(__file__).parent
TIER_ORDER = ("critical", "high", "medium")
_REQUIRED_FIELDS = ("id", "category", "weight", "pattern")


class RuleLoaderError(Exception):
    pass


@dataclass(frozen=True, slots=True)
class Rule:
    id: str
    category: str
    tier: str
    weight: float
    confidence: float
    description: str
    pattern: str
    source: str = ""
    # 命中后的二次校验函数名与实现（见 validators.py）。
    # 正则负责线性定位候选，特征判定交给 Python 做一次。
    validator_name: str = ""
    validator: Any = None
    compiled: Any = None  # re.Pattern 或 regex.Pattern，由 engine 决定

    def match(self, text: str) -> Any:
        """返回第一个通过二次校验的命中。

        带校验器时不能用 `search`：它只取最左命中，而最左候选很可能不合格
        （比如整段 run 不含数字），必须逐个试到通过为止，否则会漏掉后面的真候选。
        """
        if self.validator is None:
            return self.compiled.search(text)
        for found in self.compiled.finditer(text):
            if self.validator(found.group(0)):
                return found
        return None


class RuleSet:
    def __init__(self, rules: Sequence[Rule]):
        self._rules: tuple[Rule, ...] = tuple(rules)
        self._by_id: dict[str, Rule] = {r.id: r for r in self._rules}
        if len(self._by_id) != len(self._rules):
            dupes = sorted({r.id for r in self._rules if
                            sum(1 for x in self._rules if x.id == r.id) > 1})
            raise RuleLoaderError(f"规则 ID 重复：{dupes}")
        self._by_tier: dict[str, list[Rule]] = {t: [] for t in TIER_ORDER}
        for rule in self._rules:
            self._by_tier.setdefault(rule.tier, []).append(rule)

    def __len__(self) -> int:
        return len(self._rules)

    def __iter__(self) -> Iterator[Rule]:
        return iter(self._rules)

    @property
    def ids(self) -> list[str]:
        return [r.id for r in self._rules]

    def get(self, rule_id: str) -> Rule | None:
        return self._by_id.get(rule_id)

    def for_tiers(self, tiers: Iterable[str]) -> list[Rule]:
        wanted = tuple(tiers)
        out: list[Rule] = []
        for tier in TIER_ORDER:
            if tier in wanted:
                out.extend(self._by_tier.get(tier, []))
        # 未登记的 tier 兜底追加，避免自定义档被丢掉
        for tier, rules in self._by_tier.items():
            if tier not in TIER_ORDER and tier in wanted:
                out.extend(rules)
        return out

    def categories(self) -> dict[str, int]:
        acc: dict[str, int] = {}
        for rule in self._rules:
            acc[rule.category] = acc.get(rule.category, 0) + 1
        return dict(sorted(acc.items(), key=lambda kv: -kv[1]))


def _compile(pattern: str, rule_id: str) -> Any:
    try:
        # 走 engine：优先 regex（字面量前缀定位，实测 1.3-4.3×），缺失则退回 re
        return _engine.compile_pattern(pattern)
    except _engine.errors() as exc:
        raise RuleLoaderError(f"规则 {rule_id} 正则编译失败：{exc}") from exc


def load_rule_file(path: Path) -> list[Rule]:
    if not path.exists():
        raise RuleLoaderError(f"规则文件不存在：{path}")
    with path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    if not isinstance(data, dict) or "rules" not in data:
        raise RuleLoaderError(f"{path} 格式错误：缺少 rules 字段")

    tier = str(data.get("tier") or path.stem).lower()
    if tier not in TIER_ORDER:
        raise RuleLoaderError(f"{path} 未知档位 tier={tier}")

    rules: list[Rule] = []
    for raw in data.get("rules") or []:
        if not isinstance(raw, dict):
            raise RuleLoaderError(f"{path}: 规则条目必须是映射，实际为 {type(raw).__name__}")
        missing = [f for f in _REQUIRED_FIELDS if f not in raw]
        if missing:
            raise RuleLoaderError(f"{path}: 规则缺少必填字段 {missing}")
        rule_id = str(raw["id"])
        pattern = str(raw["pattern"])
        weight = float(raw["weight"])
        if not 1.0 <= weight <= 9.0:
            raise RuleLoaderError(f"{path}: 规则 {rule_id} 权重 {weight} 超出 1-9 范围")
        confidence = float(raw.get("confidence", 1.0))
        if not 0.0 < confidence <= 1.0:
            raise RuleLoaderError(f"{path}: 规则 {rule_id} confidence 必须在 (0,1]")
        validator_name = str(raw.get("validate") or "").strip()
        validator = None
        if validator_name:
            try:
                validator = get_validator(validator_name)
            except KeyError:
                raise RuleLoaderError(
                    f"{path}: 规则 {rule_id} 引用了不存在的校验器 {validator_name}，"
                    f"可用：{names()}"
                ) from None
        rules.append(
            Rule(
                id=rule_id,
                category=str(raw.get("category", "uncategorized")),
                tier=tier,
                weight=weight,
                confidence=confidence,
                description=str(raw.get("description", "")).strip(),
                pattern=pattern,
                source=path.name,
                validator_name=validator_name,
                validator=validator,
                compiled=_compile(pattern, rule_id),
            )
        )
    return rules


def load_rules(
    directory: str | Path | None = None,
    tiers: Iterable[str] = TIER_ORDER,
    files: Iterable[str] | None = None,
) -> RuleSet:
    """从目录加载规则。files 为空时按 tier 自动取 <tier>.yaml。"""
    base = Path(directory) if directory else DEFAULT_RULES_DIR
    wanted = tuple(tiers)
    names = list(files) if files else [f"{t}.yaml" for t in wanted]
    collected: list[Rule] = []
    for name in names:
        collected.extend(load_rule_file(base / name))
    return RuleSet(collected)


class RuleBook:
    """带 mtime 感知的规则薄，支持热加载。"""

    def __init__(self, directory: str | Path | None = None, tiers: Iterable[str] = TIER_ORDER):
        self.directory = Path(directory) if directory else DEFAULT_RULES_DIR
        self.tiers = tuple(tiers)
        self._ruleset: RuleSet | None = None
        self._mtimes: dict[str, float] = {}

    @property
    def ruleset(self) -> RuleSet:
        if self._ruleset is None:
            self._ruleset = load_rules(self.directory, self.tiers)
            self._snapshot_mtimes()
        return self._ruleset

    def _snapshot_mtimes(self) -> None:
        self._mtimes = {}
        for name in self._file_names():
            path = self.directory / name
            if path.exists():
                self._mtimes[name] = path.stat().st_mtime

    def _file_names(self) -> list[str]:
        return [f"{t}.yaml" for t in self.tiers]

    def reload_if_stale(self) -> bool:
        """文件变更则重新加载，返回是否实际重载。"""
        changed = False
        for name in self._file_names():
            path = self.directory / name
            mtime = path.stat().st_mtime if path.exists() else -1.0
            if self._mtimes.get(name) != mtime:
                changed = True
                break
        if changed or self._ruleset is None:
            self._ruleset = load_rules(self.directory, self.tiers)
            self._snapshot_mtimes()
            return True
        return False

    def stats(self) -> dict[str, object]:
        rs = self.ruleset
        data: dict[str, object] = {
            "total": len(rs),
            "tiers": {t: len(rs.for_tiers([t])) for t in TIER_ORDER},
            "categories": rs.categories(),
        }
        # 引擎信息必须可见：装了 regex 却因为环境变量退回 re，
        # 会让"延迟怎么变慢了"变成一个查不出来的问题
        data.update(_engine.info())
        return data
