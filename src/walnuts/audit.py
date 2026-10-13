"""Small append-only JSONL audit sink with a deliberately narrow schema."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
import re


_SAFE_CODE = re.compile(r"^[a-z][a-z0-9_]{0,63}$", re.IGNORECASE)
_SAFE_ID = re.compile(r"^[a-zA-Z0-9_.-]{1,64}$")


@dataclass(frozen=True, slots=True)
class AuditRecord:
    occurred_at: datetime
    action: str
    subject_id: str
    outcome: str
    reason: str

    @classmethod
    def now(cls, action: str, subject_id: str, outcome: str, reason: str) -> "AuditRecord":
        return cls(datetime.now(timezone.utc), action, subject_id, outcome, reason)

    def to_json(self) -> str:
        if self.occurred_at.tzinfo is None:
            raise ValueError("audit timestamp must include a timezone")
        for name in ("action", "outcome", "reason"):
            if not _SAFE_CODE.fullmatch(getattr(self, name)):
                raise ValueError(f"audit {name} must be a short code, not free text")
        if not _SAFE_ID.fullmatch(self.subject_id):
            raise ValueError("audit subject_id must be a bounded identifier")
        row = asdict(self)
        row["occurred_at"] = self.occurred_at.astimezone(timezone.utc).isoformat()
        return json.dumps(row, sort_keys=True, separators=(",", ":"))


class JsonlAuditLog:
    """Append validated decision metadata; credentials and arbitrary details have no field."""

    def __init__(self, path: str | Path):
        self.path = Path(path)

    def append(self, record: AuditRecord) -> None:
        line = record.to_json() + "\n"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8", newline="\n") as stream:
            stream.write(line)
