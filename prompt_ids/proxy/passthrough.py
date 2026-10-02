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
#:
#: ⚠ 措辞里**不能**留「未覆盖」这种半承诺 —— 要么说清「为什么扫不到」，
#: 要么给出替代动作。转写/译文的响应侧已在 `output_transcript.py` 覆盖，
#: 所以这里改成陈述已完成的配套动作。
PASSTHROUGH_NO_TEXT: dict[str, str] = {
    "/v1/audio/transcriptions":
        "输入是音频字节，无文本可扫；转写文本已由响应侧检查"
        "（output.transcript_scan）覆盖",
    "/v1/audio/translations":
        "输入是音频字节，无文本可扫；译文已由响应侧检查"
        "（output.transcript_scan）覆盖",
}

#: 输入**不是文本**的形态码（进审计的 `input_kind`）。
#:
#: 为什么单独记：token id 形态的 `input`（`[1, 2, 3]`）扫不了 —— 规则层匹配的是
#: 字符，不是 token。但「扫不了」必须**可查**，否则与「扫了没命中」无法区分：
#: 运维看到「没有注入命中」会以为那段文本干净，而真实情况是**根本没看**。
INPUT_KIND_TEXT = "text"
INPUT_KIND_TOKEN_IDS = "token_ids"
INPUT_KIND_MIXED = "text+token_ids"
INPUT_KIND_EMPTY = "empty"
INPUT_KIND_NO_TEXT_FIELD = "no_text_field"

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


def classify_input(value: Any) -> str:
    """判断这个 `input` 值的形态，供审计记录（`extra["input_kind"]`）。

    为什么要单独一个函数而不是看 `segments` 是否为空反推：
    - `segments` 空有**三种**原因（全是 token id / 字段缺失 / 值本身是空串），
      它们对运维的意义完全不同 —— 「字段没给」是调用方的问题，
      「全是 token id」是**本服务看不到这段内容**，而后者必须能被查出来。
    - 而「mixed」（既有文本又有 token id）需要**单独标出来**：
      那意味着**只有一部分内容被检测了**，说成「扫过了」是误导。
    """
    if value is None:
        return INPUT_KIND_NO_TEXT_FIELD
    # 文本判定复用 `_walk`（与实际提取**同一套**逻辑）—— 不另写一份判断，
    # 否则两者哪天不一致，「扫到了几段」与「形态是 text」就会自相矛盾。
    pieces: list[str] = []
    _walk(value, pieces)
    has_text = any(piece.strip() for piece in pieces)
    has_tokens = _has_token_ids(value)
    if has_text and has_tokens:
        return INPUT_KIND_MIXED
    if has_text:
        return INPUT_KIND_TEXT
    if has_tokens:
        return INPUT_KIND_TOKEN_IDS
    return INPUT_KIND_EMPTY


def _has_token_ids(value: Any, depth: int = 0) -> bool:
    """值里是否含 token id 形态（非字符串的标量/数组）。

    ⚠ 不把 `bool` 当 token id：`True`/`False` 是参数开关（moderations 的
    `input` 旁边就有），算成 token id 会让「mixed」这个结论到处误报。
    """
    if depth > 4:
        return False
    if isinstance(value, bool) or value is None:
        return False
    if isinstance(value, (int, float)):
        return True
    if isinstance(value, str):
        return False
    if isinstance(value, list):
        return any(_has_token_ids(item, depth + 1) for item in value)
    if isinstance(value, dict):
        for key in ("text", "content", "input_text"):
            inner = value.get(key)
            if isinstance(inner, (str, list)):
                return _has_token_ids(inner, depth + 1)
    return False


def extract_passthrough_segments(path: str, payload: dict[str, Any],
                                ) -> tuple[list, list[str], str, str]:
    """返回 (segments, 字段名列表, 说明, 输入形态)。

    `segments` 为空表示**这个请求没有可扫的文本** —— 调用方必须把这件事
    写进审计（note + `input_kind`），而不是静默直通。

    ⚠ 第四项（`input_kind`）是本轮新增：它让「没扫到」这件事**可查**。
    以前只有一句 note，而 note 是自由文本、会被截断、也没法聚合 ——
    于是「全是 token id 所以没扫」与「扫了没命中」在统计上长得一样。
    """
    from prompt_ids.proxy.server import PASSTHROUGH_PATHS  # 避免循环导入

    if path not in PASSTHROUGH_PATHS:
        return [], [], "", INPUT_KIND_NO_TEXT_FIELD
    if path in PASSTHROUGH_NO_TEXT:
        # 输入是音频字节：连「文本形态」都不成立，形态记成 no_text_field
        return [], [], PASSTHROUGH_NO_TEXT[path], INPUT_KIND_NO_TEXT_FIELD

    fields = PASSTHROUGH_TEXT_FIELDS.get(path)
    if not fields:
        return ([], [], f"{path} 未登记要扫的文本字段（当前不过检测）",
                INPUT_KIND_NO_TEXT_FIELD)

    from prompt_ids.proxy.server import Segment

    segments = []
    used: list[str] = []
    kinds: set[str] = set()
    for name in fields:
        if name not in payload:
            continue
        pieces: list[str] = []
        _walk(payload.get(name), pieces)
        kind = classify_input(payload.get(name))
        kinds.add(kind)
        if not pieces:
            continue
        used.append(name)
        role = _ROLE_INPUT if name == "input" else _ROLE_PROMPT
        for index, text in enumerate(pieces):
            segments.append(Segment(role=role, index=index, text=text))
    # 多个字段时取最「弱」的那个：mixed > token_ids > empty > text
    order = [INPUT_KIND_MIXED, INPUT_KIND_TOKEN_IDS, INPUT_KIND_EMPTY,
             INPUT_KIND_NO_TEXT_FIELD, INPUT_KIND_TEXT]
    kind = next((k for k in order if k in kinds), INPUT_KIND_NO_TEXT_FIELD)
    if not segments:
        if kind == INPUT_KIND_TOKEN_IDS:
            note = (f"{path} 的 {'/'.join(used) or '/'.join(fields)} 是 token id "
                    f"而非文本，规则层扫不了（**未检测**）；要在这一面检测请让调用方"
                    f"同时发送文本字段")
        elif kind == INPUT_KIND_MIXED:
            note = (f"{path} 的 {'/'.join(used)} 混有文本与 token id，"
                    f"只有文本部分被检测（**部分覆盖**）")
        else:
            note = f"{path} 的 {fields} 里没有可扫的文本"
        return [], used, note, kind
    if kind == INPUT_KIND_MIXED:
        note = (f"扫 {path} 的 {'/'.join(used)}：{len(segments)} 段"
                f"（⚠ 同一字段里混有 token id，**只有文本部分被检测**）")
    else:
        note = f"扫 {path} 的 {'/'.join(used)}：{len(segments)} 段"
    return segments, used, note, kind
