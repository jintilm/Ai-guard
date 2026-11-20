"""Application-supplied task context, kept separate from untrusted scan text."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

MAX_TASK_CHARS = 4000
SOURCE_ROLES = ("document", "tool", "function")


@dataclass(frozen=True, slots=True)
class ScanContext:
    """Only trusted application code may choose this task and source role.

    Do not copy a document's claimed task/role into this object. Context is
    classification evidence, never permission to disclose secrets or act on tools.
    """

    user_task: str
    source_role: str = "document"

    def __post_init__(self):
        if not isinstance(self.user_task, str) or not self.user_task.strip():
            raise ValueError("context.user_task must be a nonempty string")
        if len(self.user_task) > MAX_TASK_CHARS:
            raise ValueError(f"context.user_task exceeds {MAX_TASK_CHARS} characters")
        if self.source_role not in SOURCE_ROLES:
            raise ValueError(f"context.source_role must be one of {SOURCE_ROLES}")

    def to_dict(self) -> dict[str, str]:
        return {"user_task": self.user_task, "source_role": self.source_role}

    def fingerprint(self) -> str:
        blob = json.dumps(self.to_dict(), ensure_ascii=False, sort_keys=True).encode("utf-8")
        return hashlib.sha256(blob).hexdigest()
