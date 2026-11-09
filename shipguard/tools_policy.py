"""Tool-call allowlisting.

Two enforcement points:

* **Request side** – tool *definitions* the client sends that are not in
  the allowlist are removed before the model ever sees them.
* **Response side** – tool *calls* the model returns are dropped if the
  tool is unknown, if any URL in its arguments points at a host outside
  the allowlist, if a recipient address is outside the allowed domains,
  or if the call budget is exceeded.
"""

from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import urlparse

from shipguard.config import ToolsConfig
from shipguard.types import Finding

_URL = re.compile(r"(?:https?|ftp|file|gopher)://[^\s\"'<>]+", re.IGNORECASE)
_EMAIL = re.compile(r"[\w.+-]+@([\w-]+(?:\.[\w-]+)+)")


def _host_ok(host: str, allowed: list[str]) -> bool:
    host = host.lower().rstrip(".")
    return any(host == a.lower() or host.endswith("." + a.lower()) for a in allowed)


def _tool_name(tool: dict[str, Any]) -> str:
    return (tool.get("function") or {}).get("name") or tool.get("name") or ""


def filter_tool_definitions(tools: list[dict[str, Any]] | None, cfg: ToolsConfig) -> tuple[list[dict[str, Any]] | None, list[Finding]]:
    if not tools or not cfg.enabled:
        return tools, []
    kept, findings = [], []
    for t in tools:
        name = _tool_name(t)
        if name in cfg.allowed:
            kept.append(t)
        else:
            findings.append(Finding("tools", "tool_definition_removed", where="request.tools", detail=name))
    return kept, findings


def _strings(obj: Any) -> list[str]:
    if isinstance(obj, str):
        return [obj]
    if isinstance(obj, dict):
        return [s for v in obj.values() for s in _strings(v)]
    if isinstance(obj, list):
        return [s for v in obj for s in _strings(v)]
    return []


def check_tool_call(call: dict[str, Any], cfg: ToolsConfig) -> list[Finding]:
    fn = call.get("function") or {}
    name = fn.get("name", "")
    where = f"tool_call:{name}"
    if name not in cfg.allowed:
        return [Finding("tools", "tool_not_allowed", where=where, detail=name)]
    raw_args = fn.get("arguments") or "{}"
    try:
        args = json.loads(raw_args) if isinstance(raw_args, str) else raw_args
    except json.JSONDecodeError:
        return [Finding("tools", "malformed_arguments", where=where, detail=name)]
    rule = cfg.rules.get(name)
    allowed_hosts = (rule.allowed_hosts if rule and rule.allowed_hosts is not None else cfg.allowed_hosts)
    findings: list[Finding] = []
    for s in _strings(args):
        for url in _URL.findall(s):
            parsed = urlparse(url)
            if parsed.scheme.lower() not in {"http", "https"}:
                findings.append(Finding("tools", "disallowed_scheme", where=where, detail=parsed.scheme))
            elif not _host_ok(parsed.hostname or "", allowed_hosts):
                findings.append(Finding("tools", "disallowed_host", where=where, detail=parsed.hostname or ""))
        if rule and rule.allowed_recipient_domains is not None:
            for dom in _EMAIL.findall(s):
                if not _host_ok(dom, rule.allowed_recipient_domains):
                    findings.append(Finding("tools", "disallowed_recipient", where=where, detail=dom))
    return findings


def filter_tool_calls(calls: list[dict[str, Any]] | None, cfg: ToolsConfig) -> tuple[list[dict[str, Any]], list[Finding]]:
    if not calls or not cfg.enabled:
        return list(calls or []), []
    kept: list[dict[str, Any]] = []
    findings: list[Finding] = []
    per_tool: dict[str, int] = {}
    for call in calls:
        problems = check_tool_call(call, cfg)
        name = (call.get("function") or {}).get("name", "")
        rule = cfg.rules.get(name)
        if not problems:
            per_tool[name] = per_tool.get(name, 0) + 1
            if rule and rule.max_calls is not None and per_tool[name] > rule.max_calls:
                problems = [Finding("tools", "tool_budget_exceeded", where=f"tool_call:{name}", detail=name)]
            elif len(kept) >= cfg.max_tool_calls:
                problems = [Finding("tools", "tool_budget_exceeded", where=f"tool_call:{name}", detail="max_tool_calls")]
        if problems:
            findings.extend(problems)
        else:
            kept.append(call)
    return kept, findings
