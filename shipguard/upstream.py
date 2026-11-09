"""Upstream providers: fan-out to real or mock chat-completions APIs.

* ``mock``      – in-process :mod:`shipguard.mock_llm` (no network)
* ``openai``    – any OpenAI-compatible endpoint: OpenAI, vLLM, Ollama
                  (``/v1``), OpenRouter, LM Studio, or the HTTP mock
                  upstream in ``mock_upstream/``
* ``anthropic`` – small adapter translating chat-completions <-> the
                  Anthropic Messages API

The provider API key lives only in the gateway's environment. The
client's ``Authorization`` header is never forwarded upstream.
"""

from __future__ import annotations

import json
import os
import time
import uuid
from typing import Any

import httpx

from shipguard import mock_llm
from shipguard.config import Policy, UpstreamConfig


class UpstreamError(RuntimeError):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status


class Upstream:
    name: str = "base"

    async def complete(self, body: dict[str, Any]) -> dict[str, Any]:  # pragma: no cover - interface
        raise NotImplementedError

    async def aclose(self) -> None:
        return None


class MockUpstream(Upstream):
    name = "mock"

    async def complete(self, body: dict[str, Any]) -> dict[str, Any]:
        return mock_llm.respond(body)


class OpenAICompatibleUpstream(Upstream):
    def __init__(self, name: str, cfg: UpstreamConfig, client: httpx.AsyncClient | None = None) -> None:
        self.name = name
        self.cfg = cfg
        self.base_url = (cfg.base_url or "https://api.openai.com/v1").rstrip("/")
        self.client = client or httpx.AsyncClient(timeout=cfg.timeout_s)

    def _headers(self) -> dict[str, str]:
        h = {"Content-Type": "application/json", **self.cfg.extra_headers}
        key = os.environ.get(self.cfg.api_key_env or "", "")
        if key:
            h["Authorization"] = f"Bearer {key}"
        return h

    async def complete(self, body: dict[str, Any]) -> dict[str, Any]:
        payload = {k: v for k, v in body.items() if k not in {"shipguard", "stream", "stream_options"}}
        if self.cfg.model_override:
            payload["model"] = self.cfg.model_override
        r = await self.client.post(f"{self.base_url}/chat/completions", json=payload, headers=self._headers())
        if r.status_code >= 400:
            raise UpstreamError(r.status_code, f"upstream {self.name} returned {r.status_code}")
        return r.json()

    async def aclose(self) -> None:
        await self.client.aclose()


def to_anthropic(body: dict[str, Any]) -> dict[str, Any]:
    """Translate an OpenAI chat-completions body into an Anthropic Messages body."""
    system_parts: list[str] = []
    messages: list[dict[str, Any]] = []
    for m in body.get("messages", []):
        role, content = m.get("role"), m.get("content") or ""
        if isinstance(content, list):
            content = "\n".join(p.get("text", "") for p in content if isinstance(p, dict))
        if role in {"system", "developer"}:
            system_parts.append(content)
        elif role == "tool":
            messages.append({"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": m.get("tool_call_id", ""), "content": content}]})
        elif role == "assistant" and m.get("tool_calls"):
            blocks: list[dict[str, Any]] = [{"type": "text", "text": content}] if content else []
            for tc in m["tool_calls"]:
                fn = tc.get("function", {})
                blocks.append({"type": "tool_use", "id": tc.get("id"), "name": fn.get("name"),
                               "input": json.loads(fn.get("arguments") or "{}")})
            messages.append({"role": "assistant", "content": blocks})
        else:
            messages.append({"role": "user" if role == "user" else "assistant", "content": content})
    out: dict[str, Any] = {"model": body.get("model"), "messages": messages,
                           "max_tokens": body.get("max_tokens") or 1024}
    if system_parts:
        out["system"] = "\n\n".join(system_parts)
    for k in ("temperature", "top_p", "stop_sequences"):
        if k in body:
            out[k] = body[k]
    if body.get("stop"):
        out["stop_sequences"] = body["stop"] if isinstance(body["stop"], list) else [body["stop"]]
    if body.get("tools"):
        out["tools"] = [{"name": t["function"]["name"], "description": t["function"].get("description", ""),
                         "input_schema": t["function"].get("parameters") or {"type": "object"}}
                        for t in body["tools"] if t.get("function")]
    return out


def from_anthropic(resp: dict[str, Any], model: str) -> dict[str, Any]:
    text, tool_calls = [], []
    for block in resp.get("content", []):
        if block.get("type") == "text":
            text.append(block.get("text", ""))
        elif block.get("type") == "tool_use":
            tool_calls.append({"id": block.get("id"), "type": "function",
                               "function": {"name": block.get("name"), "arguments": json.dumps(block.get("input", {}))}})
    msg: dict[str, Any] = {"role": "assistant", "content": "".join(text)}
    if tool_calls:
        msg["tool_calls"] = tool_calls
    stop = resp.get("stop_reason")
    finish = {"end_turn": "stop", "max_tokens": "length", "tool_use": "tool_calls", "stop_sequence": "stop"}.get(stop, "stop")
    usage = resp.get("usage", {})
    return {
        "id": resp.get("id") or f"chatcmpl-{uuid.uuid4().hex[:10]}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": model,
        "choices": [{"index": 0, "message": msg, "finish_reason": finish}],
        "usage": {"prompt_tokens": usage.get("input_tokens", 0), "completion_tokens": usage.get("output_tokens", 0),
                  "total_tokens": usage.get("input_tokens", 0) + usage.get("output_tokens", 0)},
    }


class AnthropicUpstream(Upstream):
    def __init__(self, name: str, cfg: UpstreamConfig, client: httpx.AsyncClient | None = None) -> None:
        self.name = name
        self.cfg = cfg
        self.base_url = (cfg.base_url or "https://api.anthropic.com").rstrip("/")
        self.client = client or httpx.AsyncClient(timeout=cfg.timeout_s)

    async def complete(self, body: dict[str, Any]) -> dict[str, Any]:
        payload = to_anthropic(body)
        if self.cfg.model_override:
            payload["model"] = self.cfg.model_override
        headers = {"content-type": "application/json", "anthropic-version": "2023-06-01", **self.cfg.extra_headers}
        key = os.environ.get(self.cfg.api_key_env or "ANTHROPIC_API_KEY", "")
        if key:
            headers["x-api-key"] = key
        r = await self.client.post(f"{self.base_url}/v1/messages", json=payload, headers=headers)
        if r.status_code >= 400:
            raise UpstreamError(r.status_code, f"upstream {self.name} returned {r.status_code}")
        return from_anthropic(r.json(), body.get("model", ""))

    async def aclose(self) -> None:
        await self.client.aclose()


class UpstreamRouter:
    """Resolve ``model`` -> (upstream, model-name-to-send)."""

    def __init__(self, policy: Policy, overrides: dict[str, Upstream] | None = None) -> None:
        self.policy = policy
        self.upstreams: dict[str, Upstream] = {}
        for name, cfg in policy.upstreams.items():
            if cfg.type == "mock":
                self.upstreams[name] = MockUpstream()
            elif cfg.type == "anthropic":
                self.upstreams[name] = AnthropicUpstream(name, cfg)
            else:
                self.upstreams[name] = OpenAICompatibleUpstream(name, cfg)
        self.upstreams.update(overrides or {})
        forced = os.environ.get("SHIPGUARD_UPSTREAM")
        self.default = forced or policy.routing.default_upstream
        if self.default not in self.upstreams:
            self.upstreams[self.default] = MockUpstream()

    def resolve(self, model: str) -> tuple[Upstream, str]:
        for prefix, name in self.policy.routing.model_prefixes.items():
            if model.startswith(prefix) and name in self.upstreams:
                return self.upstreams[name], model[len(prefix):]
        return self.upstreams[self.default], model

    async def aclose(self) -> None:
        for u in self.upstreams.values():
            await u.aclose()
