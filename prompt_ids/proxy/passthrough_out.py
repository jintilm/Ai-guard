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

import json
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


# ---------------------------------------------------------------- 流式转写
#: 转写流里常见的结束标记。⚠ 必须**在发出去之前**判断：OpenAI / Anthropic 的
#: 官方 SDK 与任何合规 SSE 解析器读到 `[DONE]` 就停止消费，
#: 追加在它后面的帧会被丢弃 —— 也就是「最常见的用法收不到告警」。
STREAM_DONE = b"data: [DONE]"


class StreamTranscriptScanner:
    """逐帧累积转写文本，**跨帧拼接**后在收尾时一次性检测。

    ## 为什么「收尾才检测」而不是「每帧检测」

    因为流式的处置只能是**告警**（内容已发出、无法撤回）。既然必须等到最后才能
    定性，那就没有必要每帧都跑一次规则 —— 而每帧跑一次会把
    「一半文字」当独立文本判定，**必然误报**（"ignore all previous" 单独看是
    正常英文）。

    ## 为什么必须跨帧拼接

    逐帧取内容再拼接，与出站密钥扫描是**同一条纪律**（见 `output/secrets.py`）：
    帧与帧之间隔着 `}\n\ndata: {`，线上根本不存在连续的注入串，
    逐帧扫必然漏掉「拆成两个 delta 发出来」的载荷。
    ⚠ 拼接时**不能加任何分隔符** —— 加了就等于自己把它拆断。

    ## 累积必须有上限

    `timeout_s` 是每次 socket 操作的超时，一个稳定吐数据的长音频流**永远不会
    超时** ⇒ 无界累积就是内存无界增长。超限后停止累积（仍照常转发，
    只是不再扫尾部）并如实记账 —— 「扫了前 200KB、后面没看」必须说出来。
    """

    def __init__(self, *, budget_chars: int = 200_000) -> None:
        self.budget_chars = max(0, int(budget_chars))
        self._chunks: list[str] = []
        self._chars = 0
        self.capped = False
        self.frames = 0
        self.done_seen = False

    def feed_frame(self, frame: bytes) -> None:
        """喂一帧**完整的** SSE 帧（含 `data: ` 前缀与结尾空行）。"""
        self.frames += 1
        if STREAM_DONE in frame:
            self.done_seen = True
        for line in frame.split(b"\n"):
            line = line.strip()
            if not line.startswith(b"data:"):
                continue
            body = line[5:].strip()
            if not body or body == b"[DONE]":
                continue
            try:
                obj = json.loads(body.decode("utf-8", "replace"))
            except ValueError:
                continue        # 非 JSON 的帧（注释/心跳）不参与文本累积
            pieces: list[str] = []
            _walk_stream(obj, pieces)
            for piece in pieces:
                self._add(piece)

    def _add(self, text: str) -> None:
        if not text or self.capped:
            return
        room = self.budget_chars - self._chars
        if room <= 0:
            self.capped = True
            return
        if len(text) > room:
            self._chunks.append(text[:room])
            self._chars = self.budget_chars
            self.capped = True
            return
        self._chunks.append(text)
        self._chars += len(text)

    @property
    def text(self) -> str:
        """累积到的转写文本（**无分隔符**拼接）。"""
        return "".join(self._chunks)

    def account(self) -> dict[str, Any]:
        """审计用的覆盖账：扫了多少、有没有被截断、有没有看到结束标记。"""
        return {
            "streamed": True,
            "frames": self.frames,
            "checked_chars": self._chars,
            "capped": self.capped,
            "done_seen": self.done_seen,
            "budget_chars": self.budget_chars,
        }


def _walk_stream(obj: Any, out: list[str]) -> None:
    """从一帧 JSON 里取文本增量。

    Whisper 的流式形态是 `{"type": "transcript.text.delta", "delta": "..."}`，
    也有网关直接发 `{"text": "..."}`。两种都收，**逐帧追加、不覆盖**。
    """
    if not isinstance(obj, dict):
        return
    for key in ("delta", "text", "transcript"):
        value = obj.get(key)
        if isinstance(value, str) and value.strip():
            out.append(value)
            return
    for key in ("choices", "segments", "data"):
        inner = obj.get(key)
        if isinstance(inner, (dict, list)):
            _walk_stream(inner, out) if isinstance(inner, dict) else [
                _walk_stream(item, out) for item in inner if isinstance(item, dict)]