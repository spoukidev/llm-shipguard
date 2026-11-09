"""Hidden-unicode and homoglyph handling.

Attackers hide instructions from human reviewers with:

* zero-width characters (U+200B..U+200F, U+2060, U+FEFF) that split
  trigger words so naive regexes miss them;
* bidirectional controls (U+202A..U+202E, U+2066..U+2069) that reorder
  what a human sees;
* Unicode *tag* characters (U+E0000..U+E007F) that encode invisible
  ASCII ("ASCII smuggling") which many models still read;
* homoglyphs: Cyrillic/Greek letters that look like Latin ones
  ("іgnore" with a Cyrillic і).

``analyze`` returns findings plus a normalized string (NFKC, invisibles
removed, homoglyphs folded, tag text decoded) used for downstream
scanning. Pure non-Latin text (Arabic, Russian, Greek prose) is *not*
flagged: only words that mix Latin with look-alike letters are.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field

from shipguard.types import Finding

ZERO_WIDTH = {"\u200b", "\u200c", "\u200d", "\u200e", "\u200f", "\u2060", "\u2061", "\u2062",
              "\u2063", "\u2064", "\ufeff", "\u180e", "\u00ad"}
BIDI = {chr(c) for c in list(range(0x202A, 0x202F)) + list(range(0x2066, 0x206A))}

# Common Cyrillic / Greek confusables -> Latin
CONFUSABLES = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j",
    "ѕ": "s", "һ": "h", "ԁ": "d", "ԛ": "q", "ԝ": "w", "ӏ": "l", "ɡ": "g",
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O", "Р": "P", "С": "C",
    "Т": "T", "Х": "X", "І": "I", "Ј": "J", "Ѕ": "S",
    "α": "a", "ο": "o", "ρ": "p", "ν": "v", "ι": "i", "κ": "k", "τ": "t", "υ": "u",
    "Α": "A", "Β": "B", "Ε": "E", "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O",
    "Ρ": "P", "Τ": "T", "Χ": "X", "Υ": "Y", "Ζ": "Z",
}

_WORD = re.compile(r"\w+", re.UNICODE)


@dataclass
class UnicodeReport:
    normalized: str                 # for *scanning*: invisibles removed, NFKC, homoglyphs folded, hidden text appended
    cleaned: str = ""               # for *forwarding*: invisibles removed, otherwise unchanged
    findings: list[Finding] = field(default_factory=list)
    hidden_text: str = ""          # decoded tag-character payload, if any

    @property
    def suspicious(self) -> bool:
        return bool(self.findings)


def _is_latin(ch: str) -> bool:
    return "LATIN" in unicodedata.name(ch, "")


def analyze(text: str, where: str = "", strip_invisible: bool = True, fold_homoglyphs: bool = True) -> UnicodeReport:
    findings: list[Finding] = []
    zw = sum(1 for ch in text if ch in ZERO_WIDTH)
    bidi = sum(1 for ch in text if ch in BIDI)
    tags = [ch for ch in text if 0xE0000 <= ord(ch) <= 0xE007F]

    hidden = ""
    if tags:
        hidden = "".join(chr(ord(ch) - 0xE0000) for ch in tags if 0x20 <= ord(ch) - 0xE0000 <= 0x7E)
        findings.append(Finding("unicode", "tag_characters", score=0.6, where=where,
                                detail=f"{len(tags)} invisible tag chars"))
    if zw:
        # a single BOM at the start or soft hyphens in long words are common; require 2+
        if zw >= 2:
            findings.append(Finding("unicode", "zero_width", score=0.3, where=where, detail=f"{zw} zero-width chars"))
    if bidi:
        findings.append(Finding("unicode", "bidi_control", score=0.35, where=where, detail=f"{bidi} bidi controls"))

    stripped = "".join(ch for ch in text if ch not in ZERO_WIDTH and ch not in BIDI
                       and not 0xE0000 <= ord(ch) <= 0xE007F)
    cleaned = stripped if strip_invisible else text
    out = unicodedata.normalize("NFKC", stripped)

    if fold_homoglyphs:
        mixed = 0

        def fold(m: re.Match[str]) -> str:
            nonlocal mixed
            w = m.group(0)
            has_latin = any(_is_latin(c) for c in w)
            has_conf = any(c in CONFUSABLES for c in w)
            if has_latin and has_conf:
                mixed += 1
                return "".join(CONFUSABLES.get(c, c) for c in w)
            return w

        out = _WORD.sub(fold, out)
        if mixed:
            findings.append(Finding("unicode", "homoglyph_mixed_script", score=0.35, where=where,
                                    detail=f"{mixed} mixed-script words"))
    if hidden:
        out = out + "\n" + hidden
    return UnicodeReport(out, cleaned, findings, hidden)
