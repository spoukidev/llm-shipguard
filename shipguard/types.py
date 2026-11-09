"""Shared data types used by filters, the pipeline, and the audit log."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class Decision(StrEnum):
    """Final verdict for one request, ordered from least to most severe."""

    ALLOW = "allow"          # nothing fired
    WARN = "warn"            # something suspicious, request passed unchanged
    MODIFY = "modify"        # passed, but content was redacted / quarantined / tools dropped
    BLOCK = "block"          # request or response refused

    @property
    def severity(self) -> int:
        return ["allow", "warn", "modify", "block"].index(self.value)

    @staticmethod
    def worst(a: Decision, b: Decision) -> Decision:
        return a if a.severity >= b.severity else b


@dataclass
class Finding:
    """One detection produced by a filter.

    ``value`` is the matched text. It is kept in memory only for the
    duration of a request (for redaction / restore) and is never written
    to the audit log.
    """

    filter: str              # e.g. "secrets", "pii", "injection"
    kind: str                # e.g. "AWS_ACCESS_KEY", "EMAIL", "override_instructions"
    start: int = -1
    end: int = -1
    value: str = ""
    score: float = 1.0
    where: str = ""          # e.g. "messages[1]", "document[0]", "completion"
    detail: str = ""

    def public(self) -> dict[str, Any]:
        """Audit-safe view (no raw matched value)."""
        return {
            "filter": self.filter,
            "kind": self.kind,
            "score": round(self.score, 3),
            "where": self.where,
            "detail": self.detail,
        }


@dataclass
class StageResult:
    """What one pipeline stage did."""

    stage: str
    decision: Decision = Decision.ALLOW
    findings: list[Finding] = field(default_factory=list)
    reason: str = ""
