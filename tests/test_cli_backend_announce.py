"""CLI 必须说清「语义层实际跑的是哪个后端」（2026-10 新增）。

背景：`auto` 改成云端优先之后，「配了 Key 但跑在本地模型上」与
「没配 Key 却以为在用云端」这两类错觉都需要一行字来消除。
更关键的是**降级**：网关挂着时 L3 持续弃权，而分数看起来仍然正常
（只是悄悄退回规则层）—— 这类静默失效必须在 CLI 上直接喊出来。
"""
from __future__ import annotations

import io
import json
import os
import subprocess
import sys
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _run(args: list[str], env_extra: dict | None = None) -> tuple[int, str, str]:
    """在子进程里跑 CLI，分别抓 stdout / stderr。

    必须在子进程里跑：`.env` 是在 **import 期**读进 os.environ 的，
    同进程内 monkeypatch 变量改变不了 provider 的解析结果。
    """
    env = dict(os.environ)
    for name in ("PROMPT_IDS_LLM_API_KEY", "PROMPT_IDS_LLM_BASE_URL",
                 "PROMPT_IDS_LLM_PROVIDER", "PROMPT_IDS_LLM_MODEL",
                 "PROMPT_IDS_LLM_MAX_TOKENS"):
        env.pop(name, None)
    env.update(env_extra or {})
    env["PYTHONPATH"] = str(ROOT)
    # 两端都钉 UTF-8：父进程按本机代码页解码会让 stdout 变 None，
    # 报出与真实原因无关的 TypeError（tests/test_core_units.py 的同款地雷）
    env["PYTHONIOENCODING"] = "utf-8"
    proc = subprocess.run(
        [sys.executable, "-m", "prompt_ids.cli", *args],
        capture_output=True, encoding="utf-8", errors="replace",
        cwd=str(ROOT), env=env, timeout=600)
    return proc.returncode, proc.stdout, proc.stderr


def test_scan_output_names_the_backend_in_use():
    """人读输出里必须出现「后端 <名字>」—— 不知道在用谁就谈不上排查。"""
    code, out, _err = _run(["--semantic", "--semantic-backend", "null", "你好"])
    assert code == 0
    assert "后端" in out, f"没说清楚用的哪个后端：{out!r}"


def test_announcement_goes_to_stdout_not_stderr():
    """Windows PowerShell 把 stderr 渲染成红色错误行，看着像崩了。"""
    _code, out, err = _run(["--semantic", "--semantic-backend", "null", "你好"])
    assert "语义层" in out, "信息行应走 stdout"
    assert "语义层" not in err, "信息行不该走 stderr"


def test_json_output_is_not_polluted_by_the_announcement():
    """`--json` 的消费方按行 json.loads，多一行说明就解析失败。"""
    code, out, err = _run(["--semantic", "--semantic-backend", "null", "--json", "你好"])
    assert code == 0
    json.loads(out)          # stdout 必须是纯 JSON
    assert "语义层" in err, "机器输出时说明应改走 stderr"


def test_quiet_suppresses_info_but_not_alarms():
    """`--quiet` 抑制的是信息不是警报：降级告警必须仍然出现。"""
    _code, out, _err = _run(["--semantic", "--semantic-backend", "null", "--quiet", "你好"])
    assert "语义层" not in out, "quiet 下不该有信息行"


def test_degraded_backend_is_announced_loudly(capsys):
    """全弃权时必须喊出来：分数看起来仍然「正常」，只是悄悄退回规则层。"""
    from prompt_ids.cli import _announce_semantic_backend
    from prompt_ids.core.pipeline import Pipeline, PipelineConfig
    from prompt_ids.detectors.semantic.base import Prediction, SemanticBackend

    class DeadGateway(SemanticBackend):
        name = "llm_judge"
        provider = "custom"
        default_timeout_s = 1.0

        def is_available(self) -> bool:
            return True

        def predict(self, text: str) -> Prediction:
            return Prediction(0.0, "LLM 裁判调用失败：503", self.name, 5.0, ok=False)

    from prompt_ids.detectors.semantic.detector import SemanticDetector

    det = SemanticDetector(enabled=True, backend=DeadGateway(), mode="always")
    # semantic_detector 是从注册表派生的只读属性：换掉注册表里那一个，
    # 而不是再注册一个（重名会被注册表拒掉）。
    pipeline = Pipeline(config=PipelineConfig(semantic_enabled=True))
    pipeline.registry.unregister("semantic")
    pipeline.registry.register(det)
    assert pipeline.semantic_detector is det
    try:
        for _ in range(4):
            det.predict("x")
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            _announce_semantic_backend(pipeline, machine_output=False)
        text = out.getvalue() + err.getvalue()
        assert "降级" in text, f"全弃权却没告警：{text!r}"
        assert "4/4" in text or "4/4" in text.replace(" ", ""), text
    finally:
        pipeline.close()
