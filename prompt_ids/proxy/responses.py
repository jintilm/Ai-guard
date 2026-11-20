"""Responses API text adapter; detection stays in the shared segment pipeline.

Only explicit text history and application-run function tools are supported.
Remote conversation references, stored prompts, hosted tools and nontext inputs
are rejected before forwarding: their contents are invisible to this proxy.
"""
from __future__ import annotations

import json
import posixpath
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any
from urllib.parse import unquote

if TYPE_CHECKING:
    from prompt_ids.proxy.server import ProxyConfig, Segment

RESPONSE_PATHS = ("/v1/responses", "/responses")
# Alphabetic marker survives Canary normalization, unlike whitespace alone.
OUTPUT_GAP = "\n[separate output field]\n"


def is_response_resource(path: str) -> bool:
    # Match the decoded path the upstream routes, including its /v1 folding.
    path = "/" + posixpath.normpath(unquote(path)).lstrip("/")
    while path.startswith("/v1/"):
        path = path[3:]
    return path == "/responses" or path.startswith("/responses/")


class ResponsesInputError(ValueError):
    def __init__(self, field: str, *, unsupported: bool = False):
        self.status = 501 if unsupported else 400
        self.code = "responses_scan_unsupported" if unsupported else "invalid_responses_input"
        self.field = field
        message = ("Responses 检测仅支持显式文本历史与应用执行的 function 工具；"
                   "请将历史和工具结果作为文本 input 提交" if unsupported else
                   "Responses 输入格式错误；请检查文本、消息角色与工具结果字段")
        super().__init__(message)


@dataclass(frozen=True, slots=True)
class ResponsesInput:
    segments: list[Segment]
    omitted_tools: int
    ignored_model_items: int
    input_items: int

    def account(self) -> dict:
        return {"protocol": "responses", "input_mode": "explicit_text_history",
                "input_items": self.input_items, "ignored_model_items": self.ignored_model_items,
                "omitted_tool_outputs": self.omitted_tools}


def _text(content: Any, field: str, *, assistant: bool = False) -> str:
    if isinstance(content, str):
        return content
    if not isinstance(content, list):
        raise ResponsesInputError(field)
    parts = []
    for i, part in enumerate(content):
        location = f"{field}[{i}]"
        if not isinstance(part, dict):
            raise ResponsesInputError(location)
        kind = part.get("type")
        allowed = ("input_text", "output_text", "refusal") if assistant else ("input_text",)
        if kind not in allowed:
            raise ResponsesInputError(location, unsupported=True)
        key = "refusal" if kind == "refusal" else "text"
        if not isinstance(part.get(key), str):
            raise ResponsesInputError(location + "." + key)
        parts.append(part[key])
    return "\n".join(parts)


def extract_responses(payload: dict, config: ProxyConfig) -> ResponsesInput:
    from prompt_ids.proxy.server import Segment, clip_segment

    for field in ("previous_response_id", "conversation", "prompt"):
        if payload.get(field) is not None:
            raise ResponsesInputError(field, unsupported=True)
    for field in ("stream", "background"):
        if field in payload and type(payload[field]) is not bool:
            raise ResponsesInputError(field)
    if payload.get("background"):
        raise ResponsesInputError("background", unsupported=True)
    instructions = payload.get("instructions")
    if instructions is not None and not isinstance(instructions, str):
        raise ResponsesInputError("instructions")
    system = [instructions] if instructions and instructions.strip() else []
    tools = payload.get("tools", [])
    if tools is None:
        tools = []
    if not isinstance(tools, list):
        raise ResponsesInputError("tools")
    for i, tool in enumerate(tools):
        if not isinstance(tool, dict):
            raise ResponsesInputError(f"tools[{i}]")
        if tool.get("type") != "function":
            raise ResponsesInputError(f"tools[{i}]", unsupported=True)
        # Declarations are application instructions, not tool results. Scan
        # their descriptions/schema with the same policy as system messages.
        system.append(json.dumps(tool, ensure_ascii=False))

    value = payload.get("input")
    if isinstance(value, str):
        items = [{"role": "user", "content": value}]
    elif isinstance(value, list):
        items = value
    else:
        raise ResponsesInputError("input")
    if not items:
        raise ResponsesInputError("input")

    authors, segments = [], []
    omitted = ignored = tool_count = 0
    for index, item in enumerate(items):
        field = f"input[{index}]"
        if not isinstance(item, dict):
            raise ResponsesInputError(field)
        kind = item.get("type", "message")
        if kind == "message":
            role = item.get("role")
            if role not in ("user", "system", "developer", "assistant"):
                raise ResponsesInputError(field + ".role")
            text = _text(item.get("content"), field + ".content", assistant=role == "assistant")
            if role == "assistant":
                ignored += 1
            elif text.strip():
                (authors if role == "user" else system).append(text)
        elif kind == "function_call_output":
            if not isinstance(item.get("call_id"), str) or not item["call_id"]:
                raise ResponsesInputError(field + ".call_id")
            text = _text(item.get("output"), field + ".output")
            if not text.strip():
                continue
            tool_count += 1
            if not config.scan_tool_messages or tool_count > config.max_tool_segments:
                omitted += 1
                continue
            clipped, cut = clip_segment(text, config.max_segment_chars)
            segments.append(Segment("function", index, clipped, cut))
        elif kind in ("function_call", "reasoning"):
            # Model-generated history follows the existing assistant exclusion.
            ignored += 1
        else:
            raise ResponsesInputError(field, unsupported=True)
    for role, parts in reversed((("system", system), ("author", authors))):
        if parts:
            clipped, cut = clip_segment("\n".join(parts), config.max_segment_chars)
            segments.insert(0, Segment(role, -1, clipped, cut,
                                      rules_only=role == "system" and not config.semantic_system))
    if not segments and not ignored and not omitted:
        raise ResponsesInputError("input")
    return ResponsesInput(segments, omitted, ignored, len(items))


def output_fields(item: Any, index: int):
    """Yield independent output fields; never join different tool calls."""
    if not isinstance(item, dict):
        return
    kind = item.get("type")
    if kind == "function_call" and isinstance(item.get("arguments"), str):
        yield (index, 0, "arguments"), item["arguments"]
    elif kind in ("message", "reasoning"):
        parts = item.get("content" if kind == "message" else "summary")
        if not isinstance(parts, list):
            return
        for position, part in enumerate(parts):
            if not isinstance(part, dict):
                continue
            field = "refusal" if part.get("type") == "refusal" else "text"
            if isinstance(part.get(field), str):
                yield (index, position, field), part[field]


def output_text(response: dict) -> str:
    items = response.get("output")
    if not isinstance(items, list):
        return ""
    return OUTPUT_GAP.join(text for i, item in enumerate(items) for _, text in output_fields(item, i))


class ResponsesOutput:
    """Bounded text assembly for SSE, including interleaved function arguments.

    Delta fragments share a field key, snapshots only fill fields with no deltas.
    This avoids duplicate secret counts when the terminal response repeats text.
    """
    TERMINAL = ("response.completed", "response.failed", "response.incomplete", "error")
    DELTAS = {"response.output_text.delta": "text", "response.refusal.delta": "refusal",
              "response.function_call_arguments.delta": "arguments"}
    DONE = {"response.output_text.done": "text", "response.refusal.done": "refusal",
            "response.function_call_arguments.done": "arguments"}

    def __init__(self, budget: int):
        self.budget = budget
        self.chars = 0
        self.capped = False
        self.parts: dict[tuple, list[str]] = {}

    def _add(self, key: tuple, text: Any, *, delta: bool = False):
        if not isinstance(text, str) or not text:
            return
        if not delta and key in self.parts:
            return
        separators = max(0, len(self.parts) - 1) + int(bool(self.parts) and key not in self.parts)
        room = max(0, self.budget - self.chars - separators * len(OUTPUT_GAP))
        chosen = text[:room]
        if chosen:
            self.parts.setdefault(key, []).append(chosen)
            self.chars += len(chosen)
        if len(chosen) < len(text):
            self.capped = True

    def feed(self, frame: bytes) -> bool:
        lines = frame.decode("utf-8", "replace").splitlines()
        data = "\n".join(line[5:].lstrip(" ") for line in lines if line.startswith("data:"))
        if data.strip() == "[DONE]":
            return True
        if not data:
            return False
        try:
            event = json.loads(data)
        except (json.JSONDecodeError, RecursionError):
            self.capped = True
            return False
        if not isinstance(event, dict):
            self.capped = True
            return False
        kind = event.get("type") or next((line[6:].strip() for line in lines if line.startswith("event:")), "")
        if not isinstance(kind, str):
            self.capped = True
            return False
        index, position = event.get("output_index", 0), event.get("content_index", 0)
        if type(index) is not int or type(position) is not int or index < 0 or position < 0:
            self.capped = True
            return kind in self.TERMINAL
        if kind in self.DELTAS:
            self._add((index, position, self.DELTAS[kind]), event.get("delta"), delta=True)
        elif kind in self.DONE:
            field = self.DONE[kind]
            self._add((index, position, field), event.get(field))
        elif kind == "response.output_item.done":
            for key, value in output_fields(event.get("item"), index):
                self._add(key, value)
        elif kind in self.TERMINAL:
            response = event.get("response") or {}
            items = response.get("output") if isinstance(response, dict) else None
            if isinstance(items, list):
                for i, item in enumerate(items):
                    for key, value in output_fields(item, i):
                        self._add(key, value)
        return kind in self.TERMINAL

    @property
    def text(self) -> str:
        return OUTPUT_GAP.join("".join(parts) for parts in self.parts.values())


class ResponseFrameTooLarge(ValueError):
    pass


def iter_frames(chunks, max_bytes: int):
    """Preserve SSE wire bytes, accept LF/CRLF, and bound an unfinished frame."""
    import re

    boundary = re.compile(rb"\r?\n\r?\n")
    pending = bytearray()
    for chunk in chunks:
        start = max(0, len(pending) - 3)
        pending.extend(chunk)
        while True:
            match = boundary.search(pending, start)
            if match is None:
                if len(pending) > max_bytes:
                    raise ResponseFrameTooLarge()
                break
            if match.end() > max_bytes:
                raise ResponseFrameTooLarge()
            yield bytes(pending[:match.end()])
            del pending[:match.end()]
            start = 0
    if pending:
        yield bytes(pending)
