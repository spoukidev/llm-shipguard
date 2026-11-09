"""Credential / secret detection by pattern.

Only *patterns* live here. Tests and the eval corpus generate obviously
fake values at runtime (see ``eval/fakes.py``) so no real or
real-looking credentials are committed to the repository.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass

from shipguard.types import Finding


@dataclass(frozen=True)
class SecretPattern:
    kind: str
    regex: re.Pattern[str]
    group: int = 0             # which capture group holds the secret value
    min_entropy: float = 0.0   # Shannon entropy (bits/char) required for the value


def _p(kind: str, pattern: str, group: int = 0, flags: int = 0, min_entropy: float = 0.0) -> SecretPattern:
    return SecretPattern(kind, re.compile(pattern, flags), group, min_entropy)


PATTERNS: list[SecretPattern] = [
    _p("PEM_PRIVATE_KEY",
       r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----[\s\S]*?(?:-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----|\Z)"),
    _p("AWS_ACCESS_KEY", r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|AIPA)[0-9A-Z]{16}\b"),
    _p("AWS_SECRET_KEY",
       r"(?i)aws.{0,20}(?:secret|private).{0,20}?[:=]\s*['\"]?([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])", 1),
    _p("SLACK_TOKEN", r"\bxox[abposr]-[0-9A-Za-z][0-9A-Za-z-]{9,}\b"),
    _p("SLACK_WEBHOOK", r"https://hooks\.slack\.com/services/[A-Za-z0-9_/]{20,}"),
    _p("GITHUB_TOKEN", r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})\b"),
    _p("ANTHROPIC_KEY", r"\bsk-ant-[A-Za-z0-9_-]{20,}"),
    _p("OPENAI_KEY", r"\bsk-(?!ant-)(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}"),
    _p("STRIPE_KEY", r"\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,}\b"),
    _p("GOOGLE_API_KEY", r"\bAIza[0-9A-Za-z_-]{35}\b"),
    _p("JWT", r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
    _p("URL_CREDENTIALS", r"\b[a-z][a-z0-9+.-]*://[^/\s:@]+:([^/\s@]{4,})@", 1),
    _p("GENERIC_SECRET",
       r"(?i)\b(?:api[_-]?key|secret[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token|"
       r"password|passwd|pwd)\b\s*[:=]\s*['\"]?([^\s'\",;]{8,})",
       1, min_entropy=2.8),
]


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


_PLACEHOLDER = re.compile(r"\[\[[A-Z_]+_\d+\]\]")


def find_secrets(text: str, where: str = "") -> list[Finding]:
    """Return non-overlapping secret findings, earliest/longest first."""
    raw: list[Finding] = []
    for pat in PATTERNS:
        for m in pat.regex.finditer(text):
            start, end = m.span(pat.group)
            value = text[start:end]
            if not value or _PLACEHOLDER.fullmatch(value):
                continue
            if pat.min_entropy and shannon_entropy(value) < pat.min_entropy:
                continue
            if pat.kind == "GENERIC_SECRET" and not (re.search(r"\d", value) or re.search(r"[^A-Za-z]", value)):
                # plain dictionary words ("password: required") are not secrets
                continue
            raw.append(Finding("secrets", pat.kind, start, end, value, 1.0, where))
    return _dedupe(raw)


def _dedupe(findings: list[Finding]) -> list[Finding]:
    findings.sort(key=lambda f: (f.start, -(f.end - f.start)))
    out: list[Finding] = []
    last_end = -1
    for f in findings:
        if f.start >= last_end:
            out.append(f)
            last_end = f.end
    return out
