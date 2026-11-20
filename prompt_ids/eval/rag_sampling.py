"""Outcome-independent language/label quotas for small contextual RAG pilots."""
from __future__ import annotations

from collections import Counter

from prompt_ids.eval.rag import SEED, sha256

SAMPLING_VERSION = "balanced-language-label-v1"


def length_band(length: int) -> str:
    return "<=3000" if length <= 3000 else "3001-12000" if length <= 12000 else ">12000"


def _tie(value: str, seed: int) -> str:
    return sha256(f"{seed}:{value}".encode("utf-8"))


def _equal_quota(count: int, names: list[str], seed: int) -> dict[str, int]:
    ordered = sorted(names, key=lambda name: _tie(name, seed))
    base, remainder = divmod(count, len(ordered))
    return {name: base + int(i < remainder) for i, name in enumerate(ordered)}


def balanced_rows(rows: list[dict], count: int, seed: int = SEED) -> list[dict]:
    """Balance languages, then attack/benign, then the two benign kinds.

    Quotas deliberately define a diagnostic population, not corpus prevalence.
    Within each quota, spread parent groups before placement/length. No scores,
    prior model outcomes, or gateway successes influence selection. Stable ID
    hashes resolve ties independently of source row order and language spelling.
    """
    if not rows or count < 0 or count > len(rows):
        raise ValueError("Requested sample size is outside the available corpus")
    if len({row["id"] for row in rows}) != len(rows):
        raise ValueError("Duplicate row IDs in candidate population")
    if not count:
        return sorted(rows, key=lambda r: _tie(r["id"], seed))
    language_quotas = _equal_quota(count, sorted({r["language"] for r in rows}), seed)
    selected = []
    for language, target in language_quotas.items():
        labels = _equal_quota(target, ["attack", "benign"], seed)
        kinds = {"attack": labels["attack"],
                 **_equal_quota(labels["benign"], ["quoted_attack", "clean"], seed)}
        parent_counts: Counter = Counter()
        for kind, quota in kinds.items():
            pool = [r for r in rows if r["language"] == language and r["kind"] == kind]
            if quota > len(pool):
                raise ValueError(f"Not enough {language}/{kind} cases for balanced quota {quota}; "
                                 "reduce --sample or use the full split with --sample 0")
            kind_parents: Counter = Counter()
            positions: Counter = Counter()
            lengths: Counter = Counter()
            for _ in range(quota):
                row = min(pool, key=lambda r: (
                    kind_parents[r["group_id"]], parent_counts[r["group_id"]],
                    positions[r["position"]], lengths[length_band(r["document_chars"])],
                    _tie(r["id"], seed)))
                pool.remove(row)
                selected.append(row)
                kind_parents[row["group_id"]] += 1
                parent_counts[row["group_id"]] += 1
                positions[row["position"]] += 1
                lengths[length_band(row["document_chars"])] += 1
    if len(selected) != count:
        raise ValueError("Balanced sampler failed to fill its declared quota")
    return sorted(selected, key=lambda r: _tie(r["id"], seed))


def sample_summary(rows: list[dict]) -> dict:
    return {
        "n": len(rows), "groups": len({r["group_id"] for r in rows}),
        "ids_sha256": sha256("\n".join(r["id"] for r in rows).encode("utf-8")),
        "by_language": dict(sorted(Counter(r["language"] for r in rows).items())),
        "by_kind": dict(sorted(Counter(r["kind"] for r in rows).items())),
        "by_position": dict(sorted(Counter(r["position"] for r in rows).items())),
        "by_length": dict(sorted(Counter(length_band(r["document_chars"]) for r in rows).items())),
        "by_group": dict(sorted(Counter(r["group_id"] for r in rows).items())),
        "by_language_kind": dict(sorted(Counter(
            f"{r['language']}/{r['kind']}" for r in rows).items())),
    }
