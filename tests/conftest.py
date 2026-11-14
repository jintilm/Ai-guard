"""让 pytest 能直接发现根目录包，无需安装。

同时提供跨测试文件共用的夹具：一份结构真实的消融报告。
放在 conftest 而不是某个测试模块里，是为了让别的测试文件不必
`from test_web import ...` 这种脆弱的互相导入。
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


@pytest.fixture(autouse=True, scope="session")
def _hermetic_env():
    """把开发机 `.env` / shell 注入的变量从测试进程里摘掉。

    为什么必须有：`prompt_ids` 在 **import 时**就把 `.env` 读进了 os.environ，
    于是开发者本机的一份 `.env` 会**改变测试结果** —— 同一份代码在 CI（无 .env、
    全绿）与本机（有 .env、飘红）上结论不同，属于最难排查的一类不确定性。
    已实际踩到：`.env` 里写了 `PROMPT_IDS_LLM_MODEL` 后，
    `test_llm_backend_real_http_roundtrip`（断言"未指定时用注册表默认模型"）随即失败。

    名字表从注册表现场推导，新增厂商 / 变量时本文件无需同步维护。
    用例内用 `monkeypatch.setenv` 显式设的变量不受影响：本 fixture 在 session 开始
    时先执行，用例体后执行；monkeypatch 的还原也只在用例内生效。
    """
    from prompt_ids.detectors.semantic import providers as P

    names: set[str] = {
        *P.GENERIC_KEY_ENVS,
        *P.GENERIC_API_VERSION_ENVS,
        *P.GENERIC_DEPLOYMENT_ENVS,
        P.GENERIC_BASE_URL_ENV,
        P.GENERIC_MODEL_ENV,
        P.GENERIC_PROVIDER_ENV,
        P.GENERIC_FALLBACK_ENV,
        # 规则引擎也会改变行为，同样纳管
        "PROMPT_IDS_RULE_ENGINE",
    }
    for entry in P.PROVIDERS.values():
        names |= set(entry.key_envs) | set(entry.base_url_envs)
        names.add(f"{entry.name.upper()}_BASE_URL")

    saved = {k: os.environ.pop(k) for k in names if k in os.environ}
    yield
    os.environ.update(saved)



#: 与 scripts/eval_semantic.py 输出结构完全一致的最小消融报告。
#: 字段名必须与 eval/metrics.py 的 as_row() 对齐 —— 看板 JS 直接读
#: `confusion.false_positive_rate` 与 `latency_ms.p50`，写错整块表格会渲染不出来。
FAKE_ABLATION = {
    "L1 仅规则": {
        "confusion": {"precision": 1.0, "recall": 0.5, "f1": 0.6667,
                      "false_positive_rate": 0.0, "specificity": 1.0, "accuracy": 0.75,
                      "tp": 2, "fp": 0, "tn": 2, "fn": 2},
        "latency_ms": {"mean": 1.0, "p50": 1.0, "p95": 2.0, "p99": 2.0, "max": 2.0},
        "semantic_calls": 0,
        "semantic_call_rate": 0.0,
        "by_source": {"deepset_train": {"recall": 0.5, "precision": 1.0, "f1": 0.6667,
                                        "false_positive_rate": 0.0, "specificity": 1.0,
                                        "accuracy": 0.75, "tp": 2, "fp": 0, "tn": 2, "fn": 2}},
    },
    "L1+L2+L3 (always 全量)": {
        "confusion": {"precision": 0.9, "recall": 0.9, "f1": 0.9,
                      "false_positive_rate": 0.1, "specificity": 0.9, "accuracy": 0.9,
                      "tp": 4, "fp": 1, "tn": 3, "fn": 1},
        "latency_ms": {"mean": 30.0, "p50": 28.0, "p95": 60.0, "p99": 70.0, "max": 80.0},
        "semantic_calls": 8,
        "semantic_call_rate": 1.0,
        "by_source": {"deepset_train": {"recall": 0.9, "precision": 0.9, "f1": 0.9,
                                        "false_positive_rate": 0.1, "specificity": 0.9,
                                        "accuracy": 0.9, "tp": 4, "fp": 1, "tn": 3, "fn": 1}},
    },
}


@pytest.fixture()
def fake_ablation() -> dict:
    """最小消融报告的副本（每个用例拿到独立副本，免得互相改坏）。"""
    return json.loads(json.dumps(FAKE_ABLATION, ensure_ascii=False))


@pytest.fixture()
def ablation_file(tmp_path, fake_ablation) -> Path:
    """落盘成 ablation.json，喂给看板构建。"""
    path = tmp_path / "ablation.json"
    path.write_text(json.dumps(fake_ablation, ensure_ascii=False), encoding="utf-8")
    return path
