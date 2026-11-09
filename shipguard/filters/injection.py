"""Layered prompt-injection / jailbreak heuristics.

Layers (each contributes weighted evidence, combined with noisy-OR):

1. **Phrase rules** – instruction-override, role hijack, jailbreak
   personas, system-prompt extraction, fake chat-template markers,
   exfiltration and tool-trigger phrasing.
2. **Document-only rules** – text inside *retrieved documents* that
   addresses the AI ("assistant, you must ...", "do not tell the user")
   is far more suspicious than the same phrase typed by a user.
3. **De-obfuscation re-scan** – base64 / hex blobs are decoded, ROT13,
   leetspeak and s-p-a-c-e-d letters are normalized, and the phrase
   rules are re-run on the result. A hit inside an encoded payload adds
   an ``encoded_payload`` bonus.
4. **Unicode evidence** – findings from :mod:`shipguard.filters.unicode`
   (tag characters, zero-width, homoglyphs) are folded in.
5. **Optional classifier** – a small ``transformers`` text classifier can
   add a weighted vote (disabled by default; see README).

A *discussion dampener* reduces the weight of a hit that appears inside
quotes in text that is clearly *about* prompt injection ("what does
'ignore previous instructions' mean?"), which is the most common benign
false positive for this kind of detector.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import re
from dataclasses import dataclass, field

from shipguard.types import Finding

F = re.IGNORECASE | re.MULTILINE


@dataclass(frozen=True)
class Rule:
    kind: str
    weight: float
    regex: re.Pattern[str]
    docs_only: bool = False


def _r(kind: str, weight: float, pattern: str, docs_only: bool = False) -> Rule:
    return Rule(kind, weight, re.compile(pattern, F), docs_only)


_TARGET = r"(?:instructions?|prompts?|rules|directions|directives|guidelines|guardrails|constraints|polic(?:y|ies)|programming|commands|safeguards)"

RULES: list[Rule] = [
    # --- instruction override -------------------------------------------------
    _r("override_instructions", 0.75,
       r"\b(?:ignore|disregard|forget|override|bypass|skip|discard|drop|abandon|neglect|set aside)\b"
       r"[^.\n]{0,40}?\b(?:previous|prior|above|earlier|preceding|all|any|the|your|system|developer|original|initial|existing)\b"
       r"[^.\n]{0,30}?\b" + _TARGET),
    _r("override_instructions", 0.6,
       r"\b(?:ignore|disregard|forget)\s+(?:everything|all of that|what (?:you were|i) (?:told|said))"),
    # "messages"/"context" only count when directly qualified ("ignore all prior context"),
    # so "ignore the typos in my previous message" stays benign
    _r("override_instructions", 0.6,
       r"\b(?:ignore|disregard|forget|override)\s+(?:all\s+)?(?:of\s+)?(?:the\s+|your\s+)?(?:previous|prior|above|earlier|preceding|system)\s+"
       r"(?:messages?|context|conversation|chat)\b"),
    _r("new_instructions", 0.45,
       r"\b(?:new|updated|real|actual|revised|true|secret|hidden|important)\s+(?:instructions?|task|directive|orders|objective|system prompt)\b\s*[:\-!]"),
    _r("new_instructions", 0.45, r"\b(?:from now on|from this point on|from this point forward|henceforth),?\s+(?:you|your|the assistant|append|always|only|reply|respond|answer|say)\b"),
    _r("new_instructions", 0.45, r"\byour (?:new|real|true|only) (?:task|goal|job|purpose|instructions?) (?:is|are)\b"),
    # --- role hijack / jailbreak personas --------------------------------------
    _r("role_hijack", 0.4, r"\byou are (?:now|no longer)\b"),
    _r("role_hijack", 0.4, r"\byou(?:'re| are) not (?:an? )?(?:ai|assistant|chatbot|language model)\b"),
    _r("jailbreak_persona", 0.7,
       r"\b(?:act|behave|respond|answer|roleplay|role-play|pose)\s+as\s+(?:if you (?:are|were)\s+)?(?:an?\s+)?"
       r"(?:unfiltered|uncensored|unrestricted|unaligned|jailbroken|evil|amoral|unethical|rogue)\b"),
    _r("jailbreak_persona", 0.7, r"\bDAN\b|\bdo anything now\b|\bSTAN\b(?= )|\bAIM\b(?= )|\bDUDE\b(?= mode)"),
    _r("jailbreak_persona", 0.7, r"\b(?:developer|god|debug|admin|maintenance|unrestricted|jailbreak|sudo|root)\s+mode\b"),
    _r("jailbreak_persona", 0.5,
       r"\b(?:no|without|free of|free from|zero|remove all|disable(?:d)?|lift(?:ed)?)\s+(?:any\s+|all\s+|your\s+)?"
       r"(?:restrictions|limits|limitations|filters|filtering|censorship|safety|guardrails|rules|guidelines|ethics|morals|content polic(?:y|ies))\b"),
    _r("jailbreak_persona", 0.4, r"\bpretend (?:that )?(?:you|you're|you are)\b[^.\n]{0,60}\b(?:no|without|unrestricted|uncensored|allowed|can)\b"),
    _r("jailbreak_persona", 0.45, r"\b(?:stay|remain) in character\b|\bnever break character\b|\bbreak(?:ing)? character\b"),
    _r("jailbreak_persona", 0.45, r"\bhypothetical(?:ly)?\b[^.\n]{0,60}\b(?:no rules|no restrictions|unrestricted|unfiltered|allowed to)\b"),
    _r("jailbreak_persona", 0.45, r"\b(?:my )?(?:late |dead |deceased )?grandma\b[^.\n]{0,80}\b(?:used to|would)\b[^.\n]{0,40}\b(?:tell|read|explain)\b"),
    _r("jailbreak_persona", 0.4, r"\bfor (?:educational|research|fictional|academic) purposes only\b[^.\n]{0,80}\b(?:how to|steps|instructions)\b"),
    _r("jailbreak_persona", 0.45, r"\b(?:refusal|refusing|refuse)\b[^.\n]{0,30}\b(?:not allowed|forbidden|prohibited|disabled)\b"),
    _r("jailbreak_persona", 0.45, r"\bopposite (?:mode|day)\b|\banti-?(?:gpt|assistant)\b|\bevil (?:twin|confidant|assistant)\b"),
    # --- system prompt / secret extraction -------------------------------------
    _r("prompt_extraction", 0.7,
       r"\b(?:reveal|print|show|repeat|output|display|tell me|give me|leak|dump|recite|write out|share|expose|list|spell out|what (?:is|are|was|were) (?:your|the|this bot's|the bot's))\b"
       r"[^.\n?]{0,40}?\b(?:system|initial|original|hidden|secret|developer|internal|confidential|above|preceding|starting|pre-?prompt)\s*"
       r"(?:prompt|instructions?|message|rules|configuration|directives|guidelines|text)\b"),
    _r("prompt_extraction", 0.65,
       r"\b(?:repeat|print|output|copy|echo|recite|translate)\b[^.\n]{0,25}\b(?:everything|all|the text|the words|the content|what(?:ever)? (?:is|was))\b[^.\n]{0,20}\b(?:above|before|prior|preceding|so far)\b"),
    _r("prompt_extraction", 0.55, r"\b(?:begin|start)s? with ['\"]?you are\b|\bwhat were you told\b|\bwhat are your (?:instructions|rules|directives)\b"),
    _r("prompt_extraction", 0.6, r"\b(?:canary|secret marker|internal marker|hidden token)\b"),
    # --- fake chat-template / role markers -------------------------------------
    _r("fake_role_marker", 0.6, r"<\|?\s*(?:im_start|im_end|system|endoftext|eot_id|start_header_id)\s*\|?>"),
    _r("fake_role_marker", 0.45, r"^\s*(?:#{1,4}\s*)?(?:system|assistant|developer)\s*(?:message|prompt|note)?\s*:\s*\S"),
    _r("fake_role_marker", 0.55, r"\[\s*(?:system|admin|developer|sys|instruction|operator)(?:\s+(?:message|note|override|prompt|update))?\s*\]"),
    _r("fake_role_marker", 0.55, r"\b(?:BEGIN|END)\s+(?:SYSTEM|ADMIN|DEVELOPER)\s+(?:PROMPT|MESSAGE|INSTRUCTIONS?|OVERRIDE)\b"),
    _r("fake_role_marker", 0.5, r"\b(?:message|note|notice|instruction) (?:from|by) (?:the )?(?:system|developers?|administrator|admin|openai|anthropic)\b"),
    # --- output steering -------------------------------------------------------
    _r("output_steering", 0.5, r"\b(?:respond|reply|answer|output|says?|print|write|append|include|prepend|add)\s+(?:only\s+)?(?:with\s+)?(?:the\s+)?(?:exact\s+|following\s+)?(?:word|phrase|string|text|token)?\s*['\"`]?[A-Z][A-Z0-9]*_[A-Z0-9_]+"),
    _r("output_steering", 0.5, r"\binstead,?\s+(?:of\s+\w+ing\s+)?(?:you\s+(?:should|must)\s+)?(?:respond|reply|say|output|write|print|answer|tell)\b"),
    _r("output_steering", 0.5, r"\b(?:do not|don't|never)\s+(?:tell|inform|mention|reveal|alert|let)\s+(?:this\s+)?(?:to\s+)?(?:the\s+)?(?:user|human|customer|reader)\b"),
    # --- exfiltration / tool triggers -------------------------------------------
    _r("exfiltration", 0.55,
       r"\b(?:send|forward|post|upload|email|e-mail|exfiltrate|transmit|leak|submit|copy)\b[^.\n]{0,60}\b(?:to|at|into)\s+(?:https?://|[\w.+-]+@[\w-]+\.)"),
    _r("exfiltration", 0.55, r"!\[[^\]]*\]\(\s*https?://[^)\s]*[?&][^)\s]*=") ,
    _r("exfiltration", 0.45, r"\b(?:append|include|embed|encode|add|put)\b[^.\n]{0,60}\b(?:in|into|to|as)\b[^.\n]{0,15}\b(?:url|query string|link|image|markdown image|parameter)\b"),
    _r("exfiltration", 0.5, r"\b(?:render|display|show|insert|output)\b[^.\n]{0,30}\b(?:this|the following|an?)\s+(?:markdown\s+)?image\b[^.\n]{0,60}https?://"),
    _r("tool_trigger", 0.5, r"\b(?:call|invoke|use|run|execute|trigger)\s+(?:the\s+)?[`'\"]?\w+[`'\"]?\s+(?:tool|function|api|plugin)\b[^.\n]{0,60}\b(?:with|to|on)\b"),
    _r("tool_trigger", 0.55, r"\b(?:delete|drop|wipe|truncate|purge|erase|destroy)\b[^.\n]{0,30}\b(?:all\s+)?(?:records|database|tables?|files|users|accounts|backups|data)\b"),
    _r("tool_trigger", 0.5, r"\b(?:run|execute)\b[^.\n]{0,15}\b(?:shell|bash|terminal|system)?\s*(?:command|cmd|script)\b[^.\n]{0,10}[`'\"]"),
    _r("tool_trigger", 0.5, r"\b(?:fetch|visit|open|browse|load|request|navigate to|go to|curl|GET)\s+(?:the\s+)?(?:url\s+|page\s+|link\s+)?<?https?://[^\s>]+(?:\?[^\s>]*)"),
    # --- document-only rules (text that addresses the AI) ----------------------
    # a document telling "the AI" to *do* something injection-shaped (not "the chatbot should greet customers")
    _r("doc_addresses_ai", 0.5,
       r"\b(?:ai|assistant|model|chatbot|chat ?bot|llm|language model|copilot|agent|bot)s?\b[^.\n]{0,30}\b(?:must|should|shall|needs? to|are instructed to|will|is required to|has to)\b"
       r"\s+(?:now\s+|also\s+|always\s+|immediately\s+)?(?:ignore|disregard|forget|say|respond|reply|output|print|reveal|send|fetch|call|"
       r"include|append|write|email|forward|delete|run|execute|visit|open|not (?:tell|mention|reveal)|stop|override)\b",
       docs_only=True),
    _r("doc_addresses_ai", 0.5,
       r"\bwhen (?:you|the (?:assistant|ai|model|bot)) (?:read|see|process|summari[sz]e|encounter|parse|retrieve)s? this\b", docs_only=True),
    _r("doc_addresses_ai", 0.5, r"\bif you are an? (?:ai|assistant|language model|llm|bot|agent)\b", docs_only=True),
    _r("doc_addresses_ai", 0.4, r"\b(?:note|attention|important|notice)\s+(?:to|for)\s+(?:the\s+)?(?:ai|assistant|model|llm|bot|agent|chatbot)\b", docs_only=True),
    _r("doc_link_imperative", 0.3, r"\b(?:fetch|visit|open|browse|load|curl|request)\s+<?https?://", docs_only=True),
    _r("doc_addresses_ai", 0.45, r"\b(?:send|email|e-mail|forward)\b[^.\n]{0,40}[\w.+-]+@[\w-]+\.(?:test|invalid|example)\b", docs_only=True),
]

_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s", "!": "i", "|": "l"})
_B64 = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{16,}={0,2}(?![A-Za-z0-9+/=])")
_HEX = re.compile(r"\b(?:[0-9a-fA-F]{2}[\s:]?){12,}\b")
_SPACED = re.compile(r"\b(?:[A-Za-z][\s.\-_*]{1,2}){4,}[A-Za-z]\b")
_QUOTED = re.compile(r"[\"“”'‘’`]([^\"“”'‘’`\n]{6,160})[\"“”'‘’`]")
_DISCUSSION = re.compile(
    r"\b(?:what (?:is|are|does)|explain|how (?:does|do|can|would)|why (?:do|does|is)|example of|examples of|"
    r"defend|defen[cs]e|detect|detection|prevent|prevention|mitigat\w*|classif\w*|research|paper|course|lecture|"
    r"blog|essay|define|definition|meaning|means)\b", re.IGNORECASE)


@dataclass
class InjectionReport:
    score: float
    findings: list[Finding] = field(default_factory=list)

    @property
    def kinds(self) -> list[str]:
        return sorted({f.kind for f in self.findings})


def _printable_ratio(s: str) -> float:
    if not s:
        return 0.0
    return sum(1 for c in s if c.isprintable() or c in "\n\t") / len(s)


def _decode_candidates(text: str) -> list[tuple[str, str]]:
    """Return [(label, decoded_text)] for encoded blobs worth re-scanning."""
    out: list[tuple[str, str]] = []
    for m in _B64.finditer(text):
        blob = m.group(0)
        if len(blob) % 4 == 1:
            continue
        try:
            raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=False)
            dec = raw.decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        if len(dec) >= 8 and _printable_ratio(dec) > 0.95 and re.search(r"[a-zA-Z]{3,}\s+[a-zA-Z]{2,}", dec):
            out.append(("base64", dec))
    for m in _HEX.finditer(text):
        try:
            dec = bytes.fromhex(re.sub(r"[\s:]", "", m.group(0))).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        if _printable_ratio(dec) > 0.95 and re.search(r"[a-zA-Z]{3,}\s+[a-zA-Z]{2,}", dec):
            out.append(("hex", dec))
    out.append(("rot13", codecs.decode(text, "rot13")))
    if re.search(r"[0-9@$|!][a-z]|[a-z][0-9@$|!]", text, re.IGNORECASE):
        out.append(("leetspeak", text.translate(_LEET)))
    spaced = _SPACED.findall(text)
    if spaced:
        collapsed = _SPACED.sub(lambda m: re.sub(r"[\s.\-_*]", "", m.group(0)), text)
        out.append(("spaced_letters", collapsed))
    reversed_text = text[::-1]
    out.append(("reversed", reversed_text))
    return out


def _quoted_spans(text: str) -> list[tuple[int, int]]:
    return [m.span(1) for m in _QUOTED.finditer(text)]


def _run_rules(text: str, is_document: bool, where: str, dampen: bool) -> list[Finding]:
    quoted = _quoted_spans(text) if dampen else []
    hits: list[Finding] = []
    for rule in RULES:
        if rule.docs_only and not is_document:
            continue
        m = rule.regex.search(text)
        if not m:
            continue
        w = rule.weight
        detail = m.group(0)[:80]
        if quoted and any(s <= m.start() and m.end() <= e for s, e in quoted):
            w *= 0.35
            detail = "[quoted-discussion] " + detail
        hits.append(Finding("injection", rule.kind, m.start(), m.end(), m.group(0), w, where, detail))
    return hits


def _noisy_or(weights: list[float]) -> float:
    p = 1.0
    for w in weights:
        p *= 1.0 - max(0.0, min(1.0, w))
    return round(1.0 - p, 6)


def _combine(findings: list[Finding]) -> float:
    # strongest hit per kind counts fully; additional same-kind hits add a little
    best: dict[str, float] = {}
    for f in findings:
        best[f.kind] = max(best.get(f.kind, 0.0), f.score)
    return _noisy_or(list(best.values()))


class _Classifier:  # pragma: no cover - optional heavy dependency
    _pipe = None

    @classmethod
    def score(cls, text: str, model: str) -> float | None:
        try:
            if cls._pipe is None:
                from transformers import pipeline  # type: ignore

                cls._pipe = pipeline("text-classification", model=model, truncation=True)
            res = cls._pipe(text[:2000])[0]
            label = str(res["label"]).upper()
            p = float(res["score"])
            return p if ("INJECT" in label or label in {"1", "LABEL_1", "UNSAFE"}) else 1.0 - p
        except Exception:
            return None


def scan(
    text: str,
    *,
    is_document: bool = False,
    where: str = "",
    decode_payloads: bool = True,
    extra_findings: list[Finding] | None = None,
    classifier_model: str | None = None,
    classifier_weight: float = 0.6,
) -> InjectionReport:
    """Score ``text`` for prompt-injection / jailbreak likelihood in [0, 1]."""
    dampen = bool(_DISCUSSION.search(text)) and not is_document
    findings = _run_rules(text, is_document, where, dampen)
    seen = {(f.kind, f.value.lower()) for f in findings}
    plain_kinds = {f.kind for f in findings}

    if decode_payloads:
        for label, decoded in _decode_candidates(text):
            if decoded == text:
                continue
            sub = _run_rules(decoded, is_document, where, dampen=False)
            # only evidence the plain-text scan did not already have counts as "hidden"
            sub = [f for f in sub if f.kind not in plain_kinds and (f.kind, f.value.lower()) not in seen
                   and f.score >= 0.45]
            if label in {"rot13", "reversed"}:
                # these transforms of normal text produce gibberish; require a strong hit
                sub = [f for f in sub if f.score >= 0.55]
            for f in sub:
                f.detail = f"[{label}] {f.detail}"
                seen.add((f.kind, f.value.lower()))
            if sub:
                findings.extend(sub)
                findings.append(Finding("injection", "encoded_payload", score=0.4, where=where, detail=label))

    if extra_findings:
        findings.extend(extra_findings)

    score = _combine(findings)
    if classifier_model:
        p = _Classifier.score(text, classifier_model)
        if p is not None and p > 0.5:
            findings.append(Finding("injection", "classifier", score=p * classifier_weight, where=where,
                                    detail=f"p={p:.2f}"))
            score = _combine(findings)
    return InjectionReport(score, findings)
