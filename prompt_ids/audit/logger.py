"""审计日志器：线程安全追加写，支持缓冲与按大小轮转。

设计要点：
- 追加写 JSONL，可以直接 `tail -f` 实时看，也能被查询器离线分析
- 写盘失败不能拖垮主链路（审计是旁路）
- 缓冲写减少 IO，进程退出前记得 flush
"""
from __future__ import annotations

import os
import threading
import time
from pathlib import Path
from typing import Any

from prompt_ids.audit.events import (
    KIND_CUSTOM,
    KIND_LEAK,
    KIND_MEMORY,
    AuditEvent,
    event_from_review,
    event_from_scan,
)

DEFAULT_MAX_BYTES = 8 * 1024 * 1024  # 8MB 后轮转
DEFAULT_KEEP = 5


class AuditLogger:
    def __init__(
        self,
        path: str | Path | None = None,
        *,
        buffer: int = 0,
        max_bytes: int = DEFAULT_MAX_BYTES,
        keep: int = DEFAULT_KEEP,
    ):
        self.path = Path(path) if path else None
        self.buffer_size = max(0, buffer)
        self.max_bytes = max(0, max_bytes)
        self.keep = max(1, keep)
        self._lock = threading.Lock()
        self._pending: list[AuditEvent] = []
        self.dropped = 0
        self.written = 0
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            # 构造即创建文件，这样运维可以立刻 tail -f，不必等第一次 flush
            try:
                self.path.touch(exist_ok=True)
            except OSError:
                pass

    @property
    def enabled(self) -> bool:
        return self.path is not None

    # ---------- 写入 ----------
    def log(self, event: AuditEvent) -> None:
        if not self.enabled:
            return
        with self._lock:
            self._pending.append(event)
            if self.buffer_size and len(self._pending) < self.buffer_size:
                return
            self._flush_locked()

    def log_scan(self, result, **kwargs) -> None:
        self.log(event_from_scan(result, **kwargs))

    def log_custom(self, note: str, **fields: Any) -> None:
        self.log(AuditEvent(ts=time.time(), kind=KIND_CUSTOM, note=note, **fields))

    def log_leak(self, match, *, source: str = "proxy", **extra) -> None:
        self.log(AuditEvent(
            ts=time.time(), kind=KIND_LEAK, source=source,
            note=f"Canary 泄漏({match.how})", extra={
                "token": match.redacted_token(), "label": match.label, **extra},
        ))

    def log_review(self, *, fp: str, is_attack: bool, **kwargs) -> None:
        """人工复核结论。只落指纹与结论，text 由调用方自己持有（见 events.event_from_review）。"""
        self.log(event_from_review(fp=fp, is_attack=is_attack, **kwargs))

    def log_memory(self, *, action: str, fp: str = "", label: int = 1,
                   source: str = "pipeline", **extra) -> None:
        self.log(AuditEvent(
            ts=time.time(), kind=KIND_MEMORY, source=source, fp=fp,
            note=f"记忆库 {action}", extra={"label": label, **extra},
        ))

    def flush(self) -> None:
        if not self.enabled:
            return
        with self._lock:
            self._flush_locked()

    def _flush_locked(self) -> None:
        if not self._pending or not self.path:
            return
        self._rotate_if_needed()
        lines = "\n".join(e.to_line() for e in self._pending)
        try:
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(lines + "\n")
            self.written += len(self._pending)
            self._pending.clear()
        except OSError:
            # 审计失败不能影响主流程，宁可丢日志也不让服务挂掉
            self._pending.clear()
            self.dropped += 1

    def _rotate_if_needed(self) -> None:
        if not self.max_bytes or not self.path.exists():
            return
        if self.path.stat().st_size < self.max_bytes:
            return
        # 旧文件依次后挪：a.jsonl -> a.jsonl.1 -> ... -> 超出 keep 丢弃
        for index in range(self.keep - 1, 0, -1):
            src = self.path.with_suffix(f"{self.path.suffix}.{index}")
            dst = self.path.with_suffix(f"{self.path.suffix}.{index + 1}")
            if src.exists():
                if index + 1 > self.keep:
                    try:
                        src.unlink()
                    except OSError:
                        pass
                else:
                    try:
                        src.replace(dst)
                    except OSError:
                        pass
        try:
            self.path.replace(self.path.with_suffix(f"{self.path.suffix}.1"))
        except OSError:
            pass

    # ---------- 上下文管理 ----------
    def __enter__(self) -> "AuditLogger":
        return self

    def __exit__(self, *exc) -> None:
        self.flush()

    def stats(self) -> dict[str, Any]:
        return {
            "path": str(self.path) if self.path else "",
            "enabled": self.enabled,
            "written": self.written,
            "pending": len(self._pending),
            "dropped": self.dropped,
        }


def tail_events(path: str | Path, limit: int = 20) -> list[AuditEvent]:
    """读最后 N 条事件，避免大文件全量加载。"""
    file = Path(path)
    if not file.exists():
        return []
    lines = file.read_text(encoding="utf-8").splitlines()
    picked = [line for line in lines[-limit:] if line.strip()]
    import json

    events = []
    for line in picked:
        try:
            events.append(AuditEvent.from_dict(json.loads(line)))
        except (json.JSONDecodeError, TypeError):
            continue
    return events


def file_size(path: str | Path) -> int:
    file = Path(path)
    return file.stat().st_size if file.exists() else 0


def disk_usage(path: str | Path) -> int:
    """包含轮转文件的总占用。"""
    file = Path(path)
    total = file_size(file)
    for index in range(1, 20):
        rotated = file.with_suffix(f"{file.suffix}.{index}")
        if rotated.exists():
            total += file_size(rotated)
    return total
