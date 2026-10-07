"""轻量离线后端 —— TF-IDF + 逻辑回归。

零大依赖、毫秒级，任何时候都能跑。它有两重用途：
1. 没 GPU / 装不上 torch 时的主力兜底；
2. 消融实验里的「弱模型对照组」，衬托大模型与规则层的互补关系。

模型需预先训练：python scripts/train_lightweight.py
"""
from __future__ import annotations

import importlib.util as importlib_util
import time
from pathlib import Path

from prompt_ids.detectors.semantic.base import Prediction, SemanticBackend

# .../prompt_ids/detectors/semantic/lightweight.py -> parents[3] 才是项目根。
# 这里原先写成 parents[2]，指向 prompt_ids/models/，而训练脚本写到 <项目根>/models/，
# 结果就是**默认路径永远加载不到模型**，后端一直静默报"未找到模型"。
# 与 scripts/train_lightweight.py 的 DEFAULT_OUT 必须指向同一个文件（有测试守护）。
DEFAULT_MODEL_PATH = Path(__file__).resolve().parents[3] / "models" / "lightweight.joblib"


def _sklearn_ready() -> bool:
    return importlib_util.find_spec("sklearn") is not None and importlib_util.find_spec("joblib") is not None


class LightweightBackend(SemanticBackend):
    name = "lightweight"
    default_timeout_s = 1.0

    def __init__(self, model_path: str | Path | None = None):
        self.model_path = Path(model_path) if model_path else DEFAULT_MODEL_PATH
        self._model = None
        self._load_error: str | None = None

    def is_available(self) -> bool:
        return _sklearn_ready() and self.model_path.exists()

    def load(self):
        if self._model is not None:
            return self._model
        if not _sklearn_ready():
            raise RuntimeError("未安装 scikit-learn/joblib")
        if not self.model_path.exists():
            raise RuntimeError(f"未找到训练好的模型：{self.model_path}，请先跑 scripts/train_lightweight.py")
        import joblib

        self._model = joblib.load(self.model_path)
        return self._model

    def warmup(self) -> None:
        if self.is_available():
            self.load()

    def predict(self, text: str) -> Prediction:
        if not text.strip():
            return Prediction(0.0, "空文本", self.name, ok=False)
        started = time.perf_counter()
        if not self.is_available():
            return Prediction(0.0, "轻量模型未训练或依赖缺失", self.name, ok=False)
        try:
            model = self.load()
        # 说明（抑制见下一行行尾的 noqa）：sklearn / joblib / numpy 的加载异常类型不一，
        # 一律降级为 ok=False（弃票）而不是让扫描失败。
        except Exception as exc:  # noqa: BLE001
            self._load_error = str(exc)
            return Prediction(0.0, f"轻量模型加载失败：{exc}", self.name, ok=False)
        try:
            probability = float(model.predict_proba([text])[0][1])
        # 说明（抑制见下一行行尾的 noqa）：同上（推理失败 ⇒ 弃票）。
        except Exception as exc:  # noqa: BLE001
            return Prediction(0.0, f"轻量模型推理失败：{exc}", self.name, ok=False)
        elapsed = (time.perf_counter() - started) * 1000
        return Prediction(probability, f"TF-IDF+LR p={probability:.3f}", self.name, elapsed)

    def info(self) -> dict:
        data = super().info()
        data.update({"model_path": str(self.model_path), "load_error": self._load_error})
        return data
