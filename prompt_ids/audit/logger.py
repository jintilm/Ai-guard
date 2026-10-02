"""审计日志器：线程安全追加写，支持缓冲与按大小轮转。

设计要点：
- 追加写 JSONL，可以直接 `tail -f` 实时看，也能被查询器离线分析
- 写盘失败不能拖垮主链路（审计是旁路）
- 缓冲写减少 IO，进程退出前记得 flush
"""
from __future__ import annotations

import io
import threading
import time
from pathlib import Path
from typing import Any

from prompt_ids.audit.events import (
    KIND_CANARY,
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

    def log_canary_issue(self, token, *, source: str = "api", **extra) -> None:
        """Canary 令牌**签发**留痕。

        为什么签发也要落审计：这个端点**明文返回完整令牌**，而此前它不留任何记录
        —— 于是「谁签了多少、什么时候签的」在日志里完全不存在，出了泄漏只能靠
        猜。⚠ 只落**脱敏**令牌（首 4 尾 2），绝不落完整值：审计文件本身
        不能成为第二个泄露源（与 `log_leak` 同一纪律）。
        """
        from prompt_ids.canary.tokens import mask_token

        self.log(AuditEvent(
            ts=time.time(), kind=KIND_CANARY, source=source,
            note=f"Canary 签发({token.label or '未命名'})",
            extra={"token": mask_token(token.value), "label": token.label, **extra},
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
    """读最后 N 条事件。

    **真的只读尾部**：从文件末尾分块往前扫，凑够 N 行就停。
    原来的实现是 `read_text().splitlines()[-limit:]` —— docstring 写着
    「避免大文件全量加载」，实际把整个文件读进内存。实测 19.1MB 审计文件
    `limit=20` 也要读满 19.1MB / 42.5ms；而 `/v1/review/patterns` 默认无鉴权、
    无默认限流，一次 GET 就是一次全文件读。
    """
    file = Path(path)
    if not file.exists() or limit <= 0:
        return []
    import json

    picked: list[bytes] = []      # **新 → 旧**（从文件尾往前扫）
    with file.open("rb") as handle:
        handle.seek(0, io.SEEK_END)
        position = handle.tell()
        tail = b""
        while position > 0 and len(picked) < limit:
            step = min(65536, position)
            position -= step
            handle.seek(position)
            tail = handle.read(step) + tail
            lines = tail.split(b"\n")
            tail = lines[0]           # 第一行可能被块边界截断，留到下一轮
            # 本块整体比已收集的更早；块内是文件顺序 → 反转后接到尾部（更新的一端）。
            picked.extend(reversed([line for line in lines[1:] if line.strip()]))
            del picked[limit:]
    if tail.strip():
        # 已经读到文件头，剩下这段是一整行（不是被截断的碎片）——
        # 它是最早的一行，在「新→旧」顺序里排最后。
        picked.append(tail)
        del picked[limit:]
    picked.reverse()

    events = []
    for line in picked:
        try:
            events.append(AuditEvent.from_dict(json.loads(line.decode("utf-8", "replace"))))
        except (json.JSONDecodeError, TypeError, UnicodeDecodeError):
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
