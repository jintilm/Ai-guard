"""本地 transformers 后端 —— DeBERTa 为主力。

protectai/deberta-v3-base-prompt-injection-v2 约 700MB，CPU 单次推理 50-200ms。
懒加载 + 线程锁，避免多线程重复加载把内存吃爆。
"""
from __future__ import annotations

# ⚠ 用 `importlib` 而不是 `importlib.util`：下面要的是
#   `import_module()`（真 import），`importlib.util` 别名里没有它。
import importlib
import os
import threading
import time

from prompt_ids.detectors.semantic.base import Prediction, SemanticBackend

DEFAULT_MODEL = "protectai/deberta-v3-base-prompt-injection-v2"
# 网络不通时切 https://hf-mirror.com；也可设 HF_ENDPOINT 环境变量覆盖
DEFAULT_ENDPOINT = "https://hf-mirror.com"

# 模型输出的标签名在不同版本间不一致，做一次通用映射
INJECTION_LABELS = frozenset({"INJECTION", "INJECT", "1", "LABEL_1", "MALICIOUS", "POSITIVE"})


def _importable(name: str) -> bool:
    """这个可选依赖**能不能真的 import**。

    ⚠ **刻意不用 `importlib.util.find_spec()`**（2026-10 在 CI 上被抓到崩）：
    `find_spec` 内部会遍历 `sys.meta_path`，**任何 finder 抛出的异常都会向上
    传播**（标准库文档明确列了这点）。于是一个损坏的 `.pth`、打包不完整的
    dist、或用户自装的 import hook，就能把「依赖没装」变成
    「异常一路抛到 CLI 顶层」⇒ 退出码 1，**而且是在做任何判定之前**。

    `find_spec` 还有第二个问题：它只证明「包目录存在」，不证明「能加载」——
    装了一半（缺 .so、缺子模块）会被判成可用，炸在运行时。

    真正的 import 同时解决两点：判据更严，且异常被就地吞掉。
    语义与项目其它地方一致 —— **可选依赖缺失永远只是降级，不是失败**。
    """
    try:
        importlib.import_module(name)
    except BaseException:  # noqa: BLE001 - 含 ImportError/AttributeError 等
        # 刻意捕获 BaseException：这里的用途是「这个依赖能不能用」，
        # 任何失败（含 SyntaxError、SystemExit）都等价于「不能用」。
        return False
    return True


def _transformers_ready() -> bool:
    return _importable("transformers") and _importable("torch")


class LocalModelBackend(SemanticBackend):
    name = "local_model"
    default_timeout_s = 10.0

    def __init__(
        self,
        model_name: str = DEFAULT_MODEL,
        device: int | None = None,  # -1=CPU, 0=cuda:0，None 自动
        max_length: int = 512,
        endpoint: str | None = None,
    ):
        self.model_name = model_name
        self.max_length = max_length
        self.endpoint = endpoint or os.environ.get("HF_ENDPOINT") or DEFAULT_ENDPOINT
        self._device = device
        self._pipeline = None
        self._lock = threading.Lock()
        self._load_error: str | None = None

    # ---------- 生命周期 ----------
    def is_available(self) -> bool:
        return _transformers_ready()

    def _resolve_device(self) -> int:
        if self._device is not None:
            return self._device
        try:
            import torch
        # 说明（抑制见下一行行尾的 noqa）：torch 缺失/装坏/版本不兼容都可能抛不同类型，
        # 而「拿不到 GPU」只是一个降级结果，不该让整个层起不来。
        except Exception:  # noqa: BLE001
            return -1
        if getattr(torch, "cuda", None) and torch.cuda.is_available():
            return 0
        return -1

    def load(self):
        """线程安全地加载 pipeline。失败会被记住，不会反复重试拖垮吞吐。"""
        if self._pipeline is not None:
            return self._pipeline
        with self._lock:
            if self._pipeline is not None:
                return self._pipeline
            if self._load_error:
                raise RuntimeError(self._load_error)
            os.environ.setdefault("HF_ENDPOINT", self.endpoint)
            # 进度条与权重日志会污染 JSON/管道输出，这里一并压掉
            os.environ.setdefault("HF_HUB_DISABLE_PROGRESS_BARS", "1")
            os.environ.setdefault("TRANSFORMERS_VERBOSITY", "error")
            from transformers import pipeline  # 局部导入：依赖未装时不污染包级命名空间
            from transformers.utils import logging as transformers_logging

            transformers_logging.set_verbosity_error()

            try:
                self._pipeline = pipeline(
                    "text-classification",
                    model=self.model_name,
                    device=self._resolve_device(),
                    truncation=True,
                    max_length=self.max_length,
                )
            except Exception as exc:  # 权重缺失/显存不足/网络失败都走这里
                self._load_error = f"本地模型加载失败：{exc}"
                raise RuntimeError(self._load_error) from exc
            return self._pipeline

    def warmup(self) -> None:
        self.load()

    def close(self) -> None:
        self._pipeline = None
        try:
            import torch
        except Exception:  # noqa: BLE001
            return
        if getattr(torch, "cuda", None) and torch.cuda.is_available():
            torch.cuda.empty_cache()

    # ---------- 推理 ----------
    def _score_one(self, text: str) -> tuple[float, str]:
        clf = self.load()
        outputs = clf(text[: self.max_length * 4], truncation=True, max_length=self.max_length)
        if isinstance(outputs, dict):
            outputs = [outputs]
        # 取注入类别的概率；多分类时按最高分项换算
        best_prob, best_label = 0.0, ""
        for item in outputs:
            label = str(item.get("label", "")).upper()
            score = float(item.get("score", 0.0))
            if label in INJECTION_LABELS:
                best_prob = max(best_prob, score)
            elif score > best_prob and best_label != "SAFE":
                best_prob = max(best_prob, score if label not in ("SAFE", "BENIGN", "0", "LABEL_0") else 1.0 - score)
            best_label = label
        return best_prob, best_label

    def encode(self, texts: list[str], normalize: bool = True):
        """取 CLS 句向量，供向量记忆库复用 —— 不额外占一份模型内存。

        返回 numpy 二维数组；依赖未就绪时返回 None，由调用方降级。
        """
        if not self.is_available():
            return None
        import numpy as np
        import torch

        clf = self.load()
        model = clf.model
        tokenizer = clf.tokenizer
        device = next(model.parameters()).device
        try:
            batch = tokenizer(
                list(texts), return_tensors="pt", truncation=True,
                max_length=self.max_length, padding=True,
            ).to(device)
            with torch.no_grad():
                outputs = model(**batch, output_hidden_states=True)
            hidden = outputs.hidden_states[-1]
            vectors = hidden[:, 0, :].float().cpu().numpy()  # CLS
        # 说明（抑制见下一行行尾的 noqa）：编码失败 ⇒ 记忆层降级到 numpy 暴力检索
        # （AGENTS.md「faiss 未装是预期状态不是 bug」）。
        except Exception:  # noqa: BLE001
            return None
        if normalize:
            norms = np.linalg.norm(vectors, axis=1, keepdims=True)
            vectors = vectors / np.clip(norms, 1e-12, None)
        return vectors

    def predict(self, text: str) -> Prediction:
        if not text.strip():
            return Prediction(0.0, "空文本", self.name, ok=False)
        if not self.is_available():
            return Prediction(0.0, "未安装 transformers/torch", self.name, ok=False)
        started = time.perf_counter()
        try:
            probability, label = self._score_one(text)
        # 说明（抑制见下一行行尾的 noqa）：torch 推理抛的异常类型随输入/版本而变，
        # 而本层必须**弃票**（ok=False）而不是把异常抛给主链路
        # —— 否则一个后端故障会变成整条扫描失败。
        except Exception as exc:  # noqa: BLE001
            return Prediction(
                0.0, f"本地推理失败：{exc}", self.name,
                (time.perf_counter() - started) * 1000, ok=False,
            )
        elapsed = (time.perf_counter() - started) * 1000
        rationale = f"{self.model_name} 判定 label={label} p={probability:.3f}"
        return Prediction(probability, rationale, self.name, elapsed)

    def info(self) -> dict:
        data = super().info()
        data.update(
            {
                "model": self.model_name,
                "endpoint": self.endpoint,
                "loaded": self._pipeline is not None,
                "load_error": self._load_error,
            }
        )
        return data
