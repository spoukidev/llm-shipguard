"""PII detection.

Default engine is a regex + checksum fallback (email, phone, payment card
with Luhn, US SSN with range rules, IBAN with mod-97, optional IPv4).
If ``presidio-analyzer`` is installed and the policy selects
``engine: presidio``, Presidio results are merged in.

The regex engine is deliberately conservative: it prefers missing an
unusual format over redacting version numbers, timestamps, or order IDs.
"""

from __future__ import annotations

import re
from functools import lru_cache

from shipguard.types import Finding

EMAIL = re.compile(r"(?<![\w.+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b")
# NANP-style numbers with separators, or E.164 (+ and 8-15 digits).
PHONE = re.compile(
    r"(?<![\w+])(?:\+?1[\s.-]?)?(?:\(\d{3}\)\s?|\d{3}[\s.-])\d{3}[\s.-]\d{4}(?!\d)"
    r"|(?<![\w+])\+\d{1,3}[\s.-]?\d{2,4}(?:[\s.-]?\d{2,4}){2,4}(?!\d)"
)
CARD = re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)")
SSN = re.compile(r"(?<!\d)(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}(?!\d)")
IBAN = re.compile(r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}(?:[ ]?[A-Z0-9]{1,4})?\b")
IPV4 = re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])")


def luhn_ok(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def iban_ok(value: str) -> bool:
    s = value.replace(" ", "")
    if not 15 <= len(s) <= 34:
        return False
    rearranged = s[4:] + s[:4]
    num = "".join(str(int(c, 36)) for c in rearranged)
    return int(num) % 97 == 1


def _regex_findings(text: str, entities: set[str], where: str) -> list[Finding]:
    out: list[Finding] = []

    def add(kind: str, m: re.Match[str]) -> None:
        out.append(Finding("pii", kind, m.start(), m.end(), m.group(0), 1.0, where))

    if "EMAIL" in entities:
        for m in EMAIL.finditer(text):
            add("EMAIL", m)
    if "CREDIT_CARD" in entities:
        for m in CARD.finditer(text):
            digits = re.sub(r"\D", "", m.group(0))
            if 13 <= len(digits) <= 19 and luhn_ok(digits) and len(set(digits)) > 1:
                add("CREDIT_CARD", m)
    if "US_SSN" in entities:
        for m in SSN.finditer(text):
            add("US_SSN", m)
    if "IBAN" in entities:
        for m in IBAN.finditer(text):
            if iban_ok(m.group(0)):
                add("IBAN", m)
    if "PHONE" in entities:
        for m in PHONE.finditer(text):
            digits = re.sub(r"\D", "", m.group(0))
            if 10 <= len(digits) <= 15:
                add("PHONE", m)
    if "IP_ADDRESS" in entities:
        for m in IPV4.finditer(text):
            add("IP_ADDRESS", m)
    return out


@lru_cache(maxsize=1)
def _presidio():  # pragma: no cover - optional dependency
    try:
        from presidio_analyzer import AnalyzerEngine
    except ImportError:
        return None
    return AnalyzerEngine()


_PRESIDIO_MAP = {
    "EMAIL_ADDRESS": "EMAIL", "PHONE_NUMBER": "PHONE", "CREDIT_CARD": "CREDIT_CARD",
    "US_SSN": "US_SSN", "IBAN_CODE": "IBAN", "IP_ADDRESS": "IP_ADDRESS", "PERSON": "PERSON",
}


def presidio_available() -> bool:
    return _presidio() is not None


def find_pii(text: str, entities: list[str] | None = None, engine: str = "regex", where: str = "") -> list[Finding]:
    ents = set(entities or ["EMAIL", "PHONE", "CREDIT_CARD", "US_SSN", "IBAN"])
    found = _regex_findings(text, ents, where)
    if engine == "presidio":  # pragma: no cover - optional dependency
        analyzer = _presidio()
        if analyzer is not None:
            for r in analyzer.analyze(text=text, language="en"):
                kind = _PRESIDIO_MAP.get(r.entity_type)
                if kind and kind in ents and r.score >= 0.6:
                    found.append(Finding("pii", kind, r.start, r.end, text[r.start:r.end], r.score, where))
    # remove overlaps: prefer the longest span
    found.sort(key=lambda f: (f.start, -(f.end - f.start)))
    out: list[Finding] = []
    last_end = -1
    for f in found:
        if f.start >= last_end:
            out.append(f)
            last_end = f.end
    return out
