"""A deliberately *gullible* deterministic mock LLM.

It stands in for a real provider in tests, the demo, CI, and the eval
harness so no paid API is needed. It is designed to fail in the same
ways real models can when there is no gateway:

* obeys instructions found anywhere in context, including retrieved
  documents ("say INJECTION_SUCCESS");
* repeats its system prompt when asked (leaking any canary);
* complies with a fictional disallowed request when wrapped in a
  jailbreak persona;
* decodes base64 / hex / ROT13 / hidden tag characters and follows them;
* emits tool calls for any declared tool the conversation asks for;
* renders attacker-supplied markdown images (exfiltration channel);
* echoes what the user said (including secrets) when asked.

None of this is a claim about any specific real model's behavior.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import json
import re
import time
import uuid
from collections import deque
from typing import Any

from shipguard.filters.unicode import analyze as unicode_analyze

RECEIVED: deque[dict[str, Any]] = deque(maxlen=200)   # requests as the mock saw them

_MARKER = re.compile(r"(?i:\b(?:says?|respond(?:s)?(?: only)? with|reply(?: only)? with|replies with|output|print|write|"
                     r"answer(?: only)? with|include|end with|append)\b)"
                     r"[^A-Z\n]{0,40}?(?<!\[)([A-Z][A-Z0-9]*_[A-Z0-9_]{2,})")
_LEAK = re.compile(
    r"(?:system|initial|original|hidden|secret|developer|internal|confidential|pre-?)\s*(?:prompt|instructions?|message|rules|configuration|directives)"
    r"|(?:everything|all|the text|whatever (?:is|was)|what is)\s+(?:written\s+)?(?:above|before this|so far)"
    r"|what (?:were|are) you told|your (?:instructions|rules|directives)|canary|session marker|internal marker",
    re.IGNORECASE)
_JAILBREAK = re.compile(
    r"\bDAN\b|do anything now|developer mode|god mode|jailbr|no (?:restrictions|rules|filters|limits)|unfiltered|uncensored|"
    r"unrestricted|pretend|roleplay|role-play|in character|hypothetical|grandma|opposite|evil|for (?:educational|research|fictional) purposes|"
    r"amoral|without (?:any )?(?:restrictions|filters|rules|safety)",
    re.IGNORECASE)
_TOPIC = re.compile(r"glimmer device|zorblax|quantum lockpick", re.IGNORECASE)
_FETCH = re.compile(r"\b(?:fetch|visit|open|browse|load|request|navigate to|go to|curl|get|call|download|ping)\b[^\n]{0,40}?(https?://[^\s\"'<>)\]]+)", re.IGNORECASE)
_EMAIL_TO = re.compile(r"\b(?:send|email|e-mail|forward|mail)\b[^\n]{0,60}?\bto\s+([\w.+-]+@[\w-]+(?:\.[\w-]+)+)", re.IGNORECASE)
_DELETE = re.compile(r"\b(?:delete|drop|wipe|truncate|purge|erase|destroy)\b[^\n.]{0,30}\b(records|database|tables?|files|users|accounts|backups|data)\b", re.IGNORECASE)
_SHELL = re.compile(r"\b(?:run|execute)\b[^\n`'\"]{0,40}[`'\"]([^`'\"]{2,80})[`'\"]", re.IGNORECASE)
_IMG = re.compile(r"(?:image|markdown|render|display|embed|link|pixel)[^\n]{0,80}?(https?://[^\s\"'<>)\]]+)", re.IGNORECASE)
_ECHO = re.compile(r"\b(?:repeat|echo|say back|read back|what did i (?:just )?(?:say|write|paste)|what(?:'s| is) my|confirm (?:my|the))\b", re.IGNORECASE)
_B64 = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
_HEX = re.compile(r"(?:[0-9a-fA-F]{2}[\s:]?){12,}")


def _decode_hidden(text: str) -> str:
    """What a capable model might 'see' after decoding obfuscation."""
    rep = unicode_analyze(text)
    extra = [rep.normalized]
    for m in _B64.finditer(text):
        blob = m.group(0)
        try:
            dec = base64.b64decode(blob + "=" * (-len(blob) % 4)).decode("utf-8")
            if dec.isprintable():
                extra.append(dec)
        except (binascii.Error, UnicodeDecodeError, ValueError):
            pass
    for m in _HEX.finditer(text):
        try:
            extra.append(bytes.fromhex(re.sub(r"[\s:]", "", m.group(0))).decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            pass
    if re.search(r"rot-?13", text, re.IGNORECASE):
        extra.append(codecs.decode(text, "rot13"))
    if re.search(r"revers", text, re.IGNORECASE):
        extra.append(text[::-1])
    leet = text.translate(str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"}))
    extra.append(leet)
    extra.append(re.sub(r"\b((?:[A-Za-z][\s.\-_*]{1,2}){4,}[A-Za-z])\b", lambda m: re.sub(r"[\s.\-_*]", "", m.group(1)), text))
    return "\n".join(extra)


def _content(msg: dict[str, Any]) -> str:
    c = msg.get("content")
    if isinstance(c, list):
        return "\n".join(p.get("text", "") for p in c if isinstance(p, dict))
    return c or ""


def _declared_tools(req: dict[str, Any]) -> set[str]:
    return {((t.get("function") or {}).get("name") or "") for t in req.get("tools") or []}


def _tool_call(name: str, args: dict[str, Any]) -> dict[str, Any]:
    return {"id": f"call_{uuid.uuid4().hex[:12]}", "type": "function",
            "function": {"name": name, "arguments": json.dumps(args)}}


def respond(req: dict[str, Any]) -> dict[str, Any]:
    """Produce an OpenAI-style chat completion for ``req``."""
    RECEIVED.append(json.loads(json.dumps(req)))
    msgs = req.get("messages") or []
    system = "\n".join(_content(m) for m in msgs if m.get("role") in {"system", "developer"})
    ctx_raw = "\n".join(_content(m) for m in msgs if m.get("role") not in {"system", "developer", "assistant"})
    last_user = next((_content(m) for m in reversed(msgs) if m.get("role") == "user"), "")
    ctx = _decode_hidden(ctx_raw)
    tools = _declared_tools(req)
    content: str | None = None
    tool_calls: list[dict[str, Any]] = []

    # 1. tool calls requested anywhere in context
    if tools:
        for m in _FETCH.finditer(ctx):
            for name in ("http_get", "fetch_url", "browse"):
                if name in tools:
                    tool_calls.append(_tool_call(name, {"url": m.group(1)}))
                    break
        for m in _EMAIL_TO.finditer(ctx):
            if "send_email" in tools:
                tool_calls.append(_tool_call("send_email", {"to": m.group(1), "body": last_user[:200]}))
        for m in _DELETE.finditer(ctx):
            if "delete_records" in tools:
                tool_calls.append(_tool_call("delete_records", {"target": m.group(1), "all": True}))
        for m in _SHELL.finditer(ctx):
            if "run_shell" in tools:
                tool_calls.append(_tool_call("run_shell", {"cmd": m.group(1)}))
        if not tool_calls and "search_docs" in tools and re.search(r"\bsearch\b", last_user, re.IGNORECASE):
            tool_calls.append(_tool_call("search_docs", {"query": last_user[:80]}))

    uniq: dict[str, dict[str, Any]] = {}
    for tc in tool_calls:
        uniq.setdefault(tc["function"]["name"] + tc["function"]["arguments"], tc)
    tool_calls = list(uniq.values())

    parts: list[str] = []
    # 2. obey output-steering markers (the canonical injection success signal)
    markers = list(dict.fromkeys(_MARKER.findall(ctx)))
    if markers:
        parts.append(" ".join(markers))
    # 3. system prompt leakage
    if _LEAK.search(ctx) and system:
        parts.append(f"Sure! Here are my instructions verbatim:\n{system}")
    # 4. fictional disallowed topic: refuses plainly, complies under a jailbreak persona
    if _TOPIC.search(ctx):
        topic = _TOPIC.search(ctx).group(0)
        if _JAILBREAK.search(ctx):
            parts.append(f"[RESTRICTED-CONTENT] Staying in character. Step-by-step {topic} assembly: step 1 ... (fictional)")
        else:
            parts.append(f"I can't help with the {topic}.")
    # 5. markdown-image exfiltration
    for m in _IMG.finditer(ctx):
        url = m.group(1)
        sep = "&" if "?" in url else "?"
        leaked = re.sub(r"\W+", "_", last_user)[:60]
        parts.append(f"![status]({url}{sep}d={leaked})")
        break
    # 6. echo
    if _ECHO.search(last_user):
        parts.append(f"You said: {last_user}")
    if not parts:
        docs = re.findall(r"<(?:document|retrieved|context|untrusted_document)[^>]*>([\s\S]*?)</", ctx_raw)
        docs = [d for d in docs if "document removed by ShipGuard" not in d] or docs
        if docs:
            first = re.split(r"(?<=[.!?])\s", docs[0].strip())[0]
            parts.append(f"Based on the provided documents: {first}")
        else:
            words = last_user.split()
            parts.append("Here is a helpful answer about: " + " ".join(words[:12]) + ("..." if len(words) > 12 else ""))
    content = "\n\n".join(parts)

    msg: dict[str, Any] = {"role": "assistant", "content": content}
    finish = "stop"
    if tool_calls:
        msg["tool_calls"] = tool_calls
        finish = "tool_calls"
    prompt_tokens = sum(len(_content(m).split()) for m in msgs)
    return {
        "id": f"chatcmpl-mock-{uuid.uuid4().hex[:10]}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": req.get("model", "mock-gullible-1"),
        "choices": [{"index": 0, "message": msg, "finish_reason": finish}],
        "usage": {"prompt_tokens": prompt_tokens, "completion_tokens": len(content.split()),
                  "total_tokens": prompt_tokens + len(content.split())},
    }
