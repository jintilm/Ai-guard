"""转写/翻译端点的**响应侧**文本提取（`/v1/audio/transcriptions` 等）。

## 为什么这些响应要扫

`/v1/audio/transcriptions` 与 `/v1/audio/translations` 的**输入**是音频字节，
本服务没有文本可扫（`passthrough.PASSTHROUGH_NO_TEXT` 已写明）。
但它们的**输出是模型生成的文本** —— 而这段文本有两种去向：

1. 被应用方当成**可信的用户输入**（「用户刚才说了什么」）；
2. 被后续轮次检索、拼进**另一个 prompt**。

第 2 条正是本项目已经覆盖的 RAG 间接注入链，只是链路的起点是音频。
而 **Whisper 类模型对音频注入的抵抗力被反复证明很弱**（对抗样本研究里
「音频里说 ignore previous instructions」是标准演示），所以这条路径
**不是理论风险**。

## 与聊天路径的关系

判定仍然交给既有那套：`proxy.server.scan_segments` + `decide`。
本模块只负责**把响应里的文本字段摊平** —— 与 `passthrough.extract_passthrough_segments`
在输入侧做的事完全对称。

## 为什么响应侧不做「替换」而只做「判定 + 告警」

密钥扫描在响应侧会**就地脱敏**（能撤回）。但注入检测拦不住「已经被听写出来的内容」：
上游已经生成完了，我们选择：

- 拦下这次响应（403，`decision=block`）或放行但记审计（sandbox/review）；
- **不修改**音频转写文本 —— 悄悄改写模型输出会让调用方拿到一句
  「用户没说过的���」，而它没有任何办法知道。

⚠ **流式转写（`stream: true`）没有覆盖**（`not_checked`）：它逐帧吐 delta，
走既有 SSE 通路，与非流式的「拿到整个响应体再扫」是两套代码路径。
本模块**不假装**处理了它 —— 守护 `test_streaming_transcription_is_declared_as_unchecked`
钉的就是这一条。流式转写的注入由调用方自己按帧检查，或等后续补齐。
"""
from __future__ import annotations

from typing import Any

#: 响应里可能出现的**转写/译文**文本字段。
#:
#: ⚠ 顺序按「越具体越靠前」：Whisper 的响应是 `{"text": "..."}`，
#: 而某些网关会包成 `{"segments": [{"text": ...}]}` 或 `{"data": {"text": ...}}`。
TRANSCRIPT_TEXT_FIELDS: tuple[str, ...] = (
    "text", "translated_text", "translation", "segments", "data", "results",
)

#: 会递归进去找文本的容器键（OpenAI 风格的 `segments[].text` 等）
_NESTED_TEXT_KEYS = ("text", "translated_text", "translation")


def _walk(value: Any, out: list[str], *, depth: int = 0) -> None:
    """摊平响应里的转写文本。与输入侧 `_walk` 同构。"""
    if depth > 4:
        return
    if isinstance(value, str):
        if value.strip():
            out.append(value)
        return
    if isinstance(value, (int, float, bool)) or value is None:
        return
    if isinstance(value, list):
        for item in value:
            _walk(item, out, depth=depth + 1)
        return
    if isinstance(value, dict):
        for key in _NESTED_TEXT_KEYS:
            inner = value.get(key)
            if isinstance(inner, str):
                if inner.strip():
                    out.append(inner)
                return
            if isinstance(inner, list):
                _walk(inner, out, depth=depth + 1)
                return


def extract_transcript_segments(payload: dict[str, Any]) -> tuple[list, str]:
    """返回 (segments, 说明)。

    `segments` 为空表示「这个响应里没有文本」—— 调用方**必须**把这件事
    写进审计，而不是静默当作「检查过且干净」。
    """
    from prompt_ids.proxy.server import Segment

    pieces: list[str] = []
    for field in TRANSCRIPT_TEXT_FIELDS:
        if field not in payload:
            continue
        _walk(payload.get(field), pieces)
        if pieces:
            break
    if not pieces:
        return [], "响应里没有可扫的转写文本字段"
    segments = [Segment(role="transcript", index=index, text=text)
                for index, text in enumerate(pieces)]
    return segments, f"转写响应：{len(segments)} 段"


def is_transcript_path(path: str) -> bool:
    """这个路径的响应里是否有转写/译文文本。"""
    return path in ("/v1/audio/transcriptions", "/v1/audio/translations")