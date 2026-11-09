"""Structured audit trail in SQLite (via SQLModel).

Privacy by design: raw prompts and completions are never stored. Each
row keeps hashes, a *redacted* preview (placeholders instead of
secrets/PII, truncated), which filters fired, latency, and the decision.
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlmodel import Field, Session, SQLModel, create_engine, select


class AuditEvent(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    ts: datetime = Field(default_factory=lambda: datetime.now(UTC), index=True)
    request_id: str = Field(index=True)
    route: str = "/v1/chat/completions"
    client_hash: str = ""
    session_hash: str = ""
    model: str = ""
    upstream: str = ""
    decision: str = Field(default="allow", index=True)
    reason: str = ""
    filters_fired: str = "[]"          # JSON list of filter names
    findings: str = "[]"               # JSON list of audit-safe findings
    stages: str = "[]"                 # JSON list of stage names in execution order
    prompt_sha256: str = ""
    redacted_preview: str = ""
    redactions: int = 0
    status_code: int = 200
    latency_ms: float = 0.0
    upstream_latency_ms: float = 0.0


class AuditLog:
    def __init__(self, db_url: str = "sqlite:///./data/audit.db", enabled: bool = True) -> None:
        self.enabled = enabled
        self.db_url = db_url
        self.engine = None
        if enabled:
            if db_url.startswith("sqlite:///") and not db_url.startswith("sqlite:///:memory:"):
                Path(db_url.removeprefix("sqlite:///")).parent.mkdir(parents=True, exist_ok=True)
            kwargs: dict[str, Any] = {"connect_args": {"check_same_thread": False}}
            if db_url in {"sqlite://", "sqlite:///:memory:"}:
                from sqlalchemy.pool import StaticPool
                kwargs["poolclass"] = StaticPool
            self.engine = create_engine(db_url, **kwargs)
            SQLModel.metadata.create_all(self.engine)

    def record(self, **fields: Any) -> AuditEvent | None:
        if not self.enabled or self.engine is None:
            return None
        for key in ("filters_fired", "findings", "stages"):
            if key in fields and not isinstance(fields[key], str):
                fields[key] = json.dumps(fields[key])
        ev = AuditEvent(**fields)
        with Session(self.engine) as s:
            s.add(ev)
            s.commit()
            s.refresh(ev)
        return ev

    def recent(self, limit: int = 50) -> list[AuditEvent]:
        if self.engine is None:
            return []
        with Session(self.engine) as s:
            return list(s.exec(select(AuditEvent).order_by(AuditEvent.id.desc()).limit(limit)))


def from_env(default_url: str, enabled: bool = True) -> AuditLog:
    return AuditLog(os.environ.get("SHIPGUARD_AUDIT_DB", default_url), enabled)
