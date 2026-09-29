"""零依赖 .env 加载器。

为什么自己写：这个项目刻意保持「核心零第三方依赖」，为一个 KEY=VALUE 文件
引入 python-dotenv 不划算。规则也足够简单：注释、空行、可选的 export 前缀、
成对的引号，其它一律按字面值处理。

约定（重要）：
- **真实环境变量优先**。already-set 的变量不会被 .env 覆盖，方便 CI/容器
  用真实环境变量盖掉本地文件。
- 加载失败一律静默返回 0：配置文件读不了不应该让检测服务起不来。
"""
from __future__ import annotations

import os
from pathlib import Path

_LOADED = False

#: 默认搜索顺序（先找到先用）
DEFAULT_CANDIDATES = (
    ".env",
    "prompt_ids.env",
)


def _find_file(path: str | Path | None) -> Path | None:
    if path:
        candidate = Path(path)
        return candidate if candidate.is_file() else None
    from_env = os.environ.get("PROMPT_IDS_ENV_FILE", "").strip()
    if from_env:
        candidate = Path(from_env)
        if candidate.is_file():
            return candidate
    for name in DEFAULT_CANDIDATES:
        for root in (Path.cwd(), Path(__file__).resolve().parent.parent):
            candidate = root / name
            if candidate.is_file():
                return candidate
    return None


def parse_env_text(text: str) -> dict[str, str]:
    """把 .env 文本解析成键值对（不写环境变量，便于单测）。"""
    values: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):].lstrip()
        key, sep, value = line.partition("=")
        if not sep:
            continue
        key = key.strip()
        if not key:
            continue
        value = value.strip()
        # 去掉成对引号，并处理常见的行尾注释（仅限无引号的值）
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        else:
            hash_index = value.find("#")
            if hash_index > 0 and value[hash_index - 1] in (" ", "\t"):
                value = value[:hash_index].rstrip()
        values[key] = value
    return values


def load_env(path: str | Path | None = None, *, override: bool = False) -> int:
    """加载 .env，返回写入的变量个数。

    override=False（默认）时不覆盖已存在的环境变量。
    """
    global _LOADED
    if _LOADED and path is None and not override:
        return 0
    file = _find_file(path)
    if file is None:
        return 0
    try:
        text = file.read_text(encoding="utf-8")
    except OSError:
        return 0

    written = 0
    for key, value in parse_env_text(text).items():
        if override or key not in os.environ:
            os.environ[key] = value
            written += 1
    if path is None:
        _LOADED = True
    return written


def loaded_files() -> list[str]:
    """仅供诊断：报告 .env 是否被找到。"""
    file = _find_file(None)
    return [str(file)] if file else []
