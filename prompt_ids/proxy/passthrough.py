"""直通路径（`/v1/embeddings` 等）里**要扫的文本字段**。

## 为什么这些路径也要扫（威胁模型与聊天端点不同）

聊天端点的威胁是「注入进这一次调用」；而 `embeddings` 这类端点的威胁是
**污染向量库 / 语料**：写进去的文本几乎一定会被某次检索捞出来，拼进**另一个**
prompt —— 那正是本项目已经在代理检测面覆盖的 RAG 间接注入路径。
换句话说：`/v1/embeddings` 是那条链的**入口**，只在 `/v1/chat/completions`
上检测，等于在链条开头就放行。

这些端点**自己**没有 system prompt，所以「注入」对这一次调用没有意义；
有意义的是「这段文本会不会日后被当成可信内容捞出来」。

## 为什么不写第二套检测逻辑

本模块只负责**提取文本**（把各种载荷形状摊平成 `Segment`），
判定仍然交给 `proxy.server.scan_segments` + `decide` —— 与聊天路径同一套。

## 覆盖不到的形态（必须说清，别让人以为「都扫了」）

- `/v1/audio/transcriptions`、`/v1/audio/translations`：输入是**音频字节**
  （multipart），没有文本可扫。转写出来的文字是在**响应**里，要扫得走
  出站路径 —— 当前未覆盖。
- 数组形态的 token id（`input: [1, 2, 3]`）：不是文本，跳过（记在 note 里）。
- 字段名不在下表里的直通端点：照旧直通（现在会显式报「未覆盖」而不是静默）。
"""
from __future__ import annotations

from typing import Any

#: 直通路径 -> 要扫的文本字段（按优先级）。
#:
#: ⚠ 顺序有意义：`/v1/audio/speech` 的 `input` 是**要合成的文本**（TTS 脚本），
#: 而 `/v1/audio/transcriptions` 的 `input` 是音频字节 —— 后者不在表里。
PASSTHROUGH_TEXT_FIELDS: dict[str, tuple[str, ...]] = {
    "/v1/embeddings": ("input",),
    "/v1/moderations": ("input",),
    "/v1/images/generations": ("prompt",),
    "/v1/images/edits": ("prompt",),
    "/v1/audio/speech": ("input",),
}

#: 明确**扫不到**的直通端点，以及原因。写进审计 note ——
#: 「没扫」和「扫了没命中」在日志里长得一样是本项目反复在修的那类问题。
PASSTHROUGH_NO_TEXT: dict[str, str] = {
    "/v1/audio/transcriptions": "输入是音频字节（无文本可扫；转写文本在响应侧，未覆盖）",
    "/v1/audio/translations": "输入是音频字节（无文本可扫；译文在响应侧，未覆盖）",
}

#: 多模态分段里的角色名。**刻意复用**代理对话分段的命名，
#: 让审计里 `input#0` 这种标注读起来是同一套语言。
_ROLE_INPUT = "input"
_ROLE_PROMPT = "prompt"


def _walk(value: Any, out: list[str], *, depth: int = 0) -> None:
    """把各种载荷形状摊平成文本片段列表。

    支持：`str` / `list[str]` / `list[int]`（token id，跳过）/
    `list[list[int]]`（跳过）/ `[{"type": "text", "text": "..."}]`（Responses 形态）/
    `[{"content": "..."}]`（v2 嵌入形态）。
    """
    if depth > 4:                      # 防止自引用结构把递归打爆
        return
    if isinstance(value, str):
        if value.strip():
            out.append(value)
        return
    if isinstance(value, (int, float, bool)) or value is None:
        return                          # token id / 标量参数，不是文本
    if isinstance(value, list):
        for item in value:
            _walk(item, out, depth=depth + 1)
        return
    if isinstance(value, dict):
        # 文本载荷的常见容器：{"text": ...} / {"content": ...} / {"input_text": ...}
        for key in ("text", "content", "input_text"):
            inner = value.get(key)
            if isinstance(inner, (str, list)):
                _walk(inner, out, depth=depth + 1)
                return
    # 其余形状（数字数组、对象数组里没有文本字段）不当作文本


def extract_passthrough_segments(path: str, payload: dict[str, Any]) -> tuple[list, list[str], str]:
    """返回 (segments, 字段名列表, 说明)。

    `segments` 为空表示**这个请求没有可扫的文本** —— 调用方必须把这件事
    写进审计（note），而不是静默直通。
    """
    from prompt_ids.proxy.server import PASSTHROUGH_PATHS  # 避免循环导入

    if path not in PASSTHROUGH_PATHS:
        return [], [], ""
    if path in PASSTHROUGH_NO_TEXT:
        return [], [], PASSTHROUGH_NO_TEXT[path]

    fields = PASSTHROUGH_TEXT_FIELDS.get(path)
    if not fields:
        return [], [], f"{path} 未登记要扫的文本字段（当前不过检测）"

    from prompt_ids.proxy.server import Segment

    segments = []
    used: list[str] = []
    for name in fields:
        if name not in payload:
            continue
        pieces: list[str] = []
        _walk(payload.get(name), pieces)
        if not pieces:
            continue
        used.append(name)
        role = _ROLE_INPUT if name == "input" else _ROLE_PROMPT
        for index, text in enumerate(pieces):
            segments.append(Segment(role=role, index=index, text=text))
    if not segments:
        return [], used, f"{path} 的 {fields} 里没有可扫的文本（如仅 token id）"
    note = f"扫 {path} 的 {'/'.join(used)}：{len(segments)} 段"
    return segments, used, note
