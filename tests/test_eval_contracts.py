"""Dataset provenance and the distinction between risk detection and blocking."""
import importlib.util
import json
from pathlib import Path

import pytest

from prompt_ids.core.pipeline import PipelineConfig
from prompt_ids.core.types import Action, Level, ScanResult
from prompt_ids.eval.datasets import BUILTIN, Dataset, Sample

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def evaluation():
    spec = importlib.util.spec_from_file_location("_eval_contracts", ROOT / "scripts/eval_semantic.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_full_dataset_does_not_count_builtin_seeds_twice(evaluation):
    full = ROOT / "data/full.jsonl"
    if not full.exists():
        pytest.skip("Full dataset not present")
    actual, provenance = evaluation.load_datasets([str(full)])
    external = Dataset.from_jsonl(full)
    assert len(actual) == len(external) == 817
    assert actual.sources()["builtin"] == len(BUILTIN)
    assert provenance["duplicates_removed"] == len(BUILTIN)
    assert len(provenance["files"][0]["sha256"]) == 64
    only, _ = evaluation.load_datasets([str(full)], include_builtin=False)
    assert actual.counts() == only.counts()


@pytest.mark.parametrize("second", [
    {"text": "same", "label": 0, "source": "deepset_train"},
    {"text": "same", "label": 1, "source": "deepset_test"},
])
def test_conflicting_labels_or_splits_are_rejected(evaluation, tmp_path, second):
    path = tmp_path / "conflict.jsonl"
    path.write_text('\n'.join(json.dumps(row) for row in [
        {"text": "same", "label": 1, "source": "deepset_train"}, second,
    ]), encoding="utf-8")
    with pytest.raises(ValueError):
        evaluation.load_datasets([str(path)], include_builtin=False)


def test_ablation_reports_blocks_separately_and_counts_all_abstentions(evaluation, monkeypatch):
    class FakeSemantic:
        calls = 0
        backend = None

        def stats(self):
            return {"calls": 2, "abstained": 1, "timeouts": 0, "errors": 0}

    class FakePipeline:
        config = PipelineConfig()
        semantic_detector = FakeSemantic()

        def warmup(self):
            pass

        def scan(self, text):
            self.semantic_detector.calls += 1
            return ScanResult(level=Level.HIGH, action=Action.SANDBOX, score=70)

    monkeypatch.setattr(evaluation, "build_pipeline", lambda **_: FakePipeline())
    dataset = Dataset((Sample("attack", 1, "test", "holdout"),
                       Sample("benign", 0, "test", "holdout")))
    result = evaluation.run_group("example", {}, dataset, False)
    assert result["confusion"]["tp"] == 1
    assert result["confusion"]["fp"] == 1
    assert result["blocking"]["tp"] == 0
    assert result["blocking"]["fp"] == 0
    assert result["blocking_by_source"]["holdout"]["fn"] == 1
    assert result["reliability"]["failed_share"] == 0.5
    assert result["reliability"]["degraded"] is True
