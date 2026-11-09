"""Consistent placeholder tokens for bidirectional redaction.

The same raw value always maps to the same placeholder within one
request (``[[EMAIL_1]]`` stays ``[[EMAIL_1]]`` in every message), so the
model can still reason about "the email address" without seeing it. On
the way back the gateway can restore placeholders for categories the
policy allows (e.g. restore PII to the user who typed it, but never
restore secrets).
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field

from shipguard.types import Finding

PLACEHOLDER_RE = re.compile(r"\[\[([A-Z][A-Z0-9_]*?)_(\d+)\]\]")


def sha256_short(value: str, n: int = 12) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:n]


@dataclass
class Vault:
    """Per-request mapping placeholder <-> original value."""

    by_value: dict[str, str] = field(default_factory=dict)
    by_token: dict[str, tuple[str, str]] = field(default_factory=dict)   # token -> (value, filter)
    counters: dict[str, int] = field(default_factory=dict)

    def token_for(self, value: str, kind: str, filter_name: str) -> str:
        if value in self.by_value:
            return self.by_value[value]
        n = self.counters.get(kind, 0) + 1
        self.counters[kind] = n
        token = f"[[{kind}_{n}]]"
        self.by_value[value] = token
        self.by_token[token] = (value, filter_name)
        return token

    def redact(self, text: str, findings: list[Finding]) -> str:
        """Replace finding spans (which must be non-overlapping) with placeholders."""
        if not findings:
            return text
        parts: list[str] = []
        cursor = 0
        for f in sorted(findings, key=lambda f: f.start):
            if f.start < cursor:
                continue
            parts.append(text[cursor:f.start])
            parts.append(self.token_for(f.value, f.kind, f.filter))
            cursor = f.end
        parts.append(text[cursor:])
        return "".join(parts)

    def restore(self, text: str, allow_filters: set[str]) -> tuple[str, int]:
        count = 0

        def sub(m: re.Match[str]) -> str:
            nonlocal count
            tok = m.group(0)
            if tok in self.by_token and self.by_token[tok][1] in allow_filters:
                count += 1
                return self.by_token[tok][0]
            return tok

        return PLACEHOLDER_RE.sub(sub, text), count

    def __len__(self) -> int:
        return len(self.by_token)
