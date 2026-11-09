"""OpenAI-compatible HTTP front door.

Point any OpenAI SDK at ShipGuard::

    export OPENAI_BASE_URL=http://localhost:8088/v1
    export OPENAI_API_KEY=<a ShipGuard client key, or anything if auth is off>

Endpoints

* ``POST /v1/chat/completions`` – guarded proxy (``stream: true`` supported
  as *buffered* SSE: the full completion is checked before any byte is sent)
* ``GET  /v1/models``           – configured upstream routes
* ``POST /v1/shipguard/scan``   – dry run: request-side stages only, no upstream call
* ``GET  /healthz``
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, StreamingResponse

from shipguard import __version__
from shipguard.audit import AuditLog
from shipguard.config import Policy, load_policy
from shipguard.pipeline import REQUEST_STAGES, Pipeline
from shipguard.ratelimit import RateLimiter
from shipguard.upstream import Upstream, UpstreamError, UpstreamRouter

ROUTE = "/v1/chat/completions"


def _client_keys() -> set[str]:
    return {k.strip() for k in os.environ.get("SHIPGUARD_API_KEYS", "").split(",") if k.strip()}


def _client_id(request: Request) -> str:
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return "key:" + hashlib.sha256(auth[7:].encode()).hexdigest()[:16]
    explicit = request.headers.get("x-shipguard-client")
    if explicit:
        return "hdr:" + explicit
    return "ip:" + (request.client.host if request.client else "unknown")


def _error(status: int, message: str, code: str, request_id: str | None = None, headers: dict[str, str] | None = None) -> JSONResponse:
    body = {"error": {"message": message, "type": "shipguard_error" if status != 403 else "shipguard_policy_violation",
                      "code": code}}
    if request_id:
        body["error"]["request_id"] = request_id
    return JSONResponse(body, status_code=status, headers=headers or {})


def _sse(resp: dict[str, Any]) -> AsyncIterator[bytes]:
    async def gen() -> AsyncIterator[bytes]:
        base = {"id": resp.get("id"), "object": "chat.completion.chunk", "created": resp.get("created", int(time.time())),
                "model": resp.get("model")}
        for ch in resp.get("choices", []):
            msg = ch.get("message") or {}
            first = {**base, "choices": [{"index": ch.get("index", 0), "delta": {"role": "assistant"}, "finish_reason": None}]}
            yield f"data: {json.dumps(first)}\n\n".encode()
            content = msg.get("content") or ""
            for i in range(0, len(content), 64):
                chunk = {**base, "choices": [{"index": ch.get("index", 0), "delta": {"content": content[i:i + 64]},
                                              "finish_reason": None}]}
                yield f"data: {json.dumps(chunk)}\n\n".encode()
            if msg.get("tool_calls"):
                tcs = [{"index": k, **tc} for k, tc in enumerate(msg["tool_calls"])]
                chunk = {**base, "choices": [{"index": ch.get("index", 0), "delta": {"tool_calls": tcs}, "finish_reason": None}]}
                yield f"data: {json.dumps(chunk)}\n\n".encode()
            last = {**base, "choices": [{"index": ch.get("index", 0), "delta": {}, "finish_reason": ch.get("finish_reason")}]}
            yield f"data: {json.dumps(last)}\n\n".encode()
        yield b"data: [DONE]\n\n"

    return gen()


def create_app(policy: Policy | None = None, *, upstream_overrides: dict[str, Upstream] | None = None,
               audit: AuditLog | None = None) -> FastAPI:
    policy = policy or load_policy()
    router = UpstreamRouter(policy, upstream_overrides)
    pipeline = Pipeline(policy, router)
    limiter = RateLimiter(policy.rate_limits)
    audit_log = audit or AuditLog(policy.audit.db_url, policy.audit.enabled)

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        yield
        await router.aclose()

    app = FastAPI(title="ShipGuard", version=__version__, lifespan=lifespan,
                  description="OpenAI-compatible security gateway for LLM apps (educational/defensive).")
    app.state.policy = policy
    app.state.pipeline = pipeline
    app.state.limiter = limiter
    app.state.audit = audit_log
    app.state.router = router

    def _auth_ok(request: Request) -> bool:
        keys = _client_keys()
        if not keys:
            return True
        auth = request.headers.get("authorization", "")
        return auth.lower().startswith("bearer ") and auth[7:] in keys

    @app.get("/healthz")
    async def healthz() -> dict[str, Any]:
        return {"status": "ok", "version": __version__, "default_upstream": router.default}

    @app.get("/v1/models")
    async def models() -> dict[str, Any]:
        data = [{"id": f"{prefix}*", "object": "model", "owned_by": name}
                for prefix, name in policy.routing.model_prefixes.items()]
        data.append({"id": "*", "object": "model", "owned_by": router.default})
        return {"object": "list", "data": data}

    @app.post("/v1/shipguard/scan")
    async def scan(request: Request) -> JSONResponse:
        if not _auth_ok(request):
            return _error(401, "invalid ShipGuard client key", "unauthorized")
        body = await request.json()
        ctx = pipeline.new_context(body, client_id=_client_id(request), route="/v1/shipguard/scan")
        for name in REQUEST_STAGES:
            ctx.add(getattr(pipeline, f"stage_{name}")(ctx))
            if ctx.blocked:
                break
        return JSONResponse({"decision": ctx.decision.value, "reason": ctx.reason, "stages": ctx.stage_names,
                             "findings": [f.public() for f in ctx.findings],
                             "redacted_messages": ctx.body.get("messages")})

    @app.post(ROUTE)
    async def chat_completions(request: Request):
        if not _auth_ok(request):
            return _error(401, "invalid ShipGuard client key", "unauthorized")
        client = _client_id(request)
        ok, retry = limiter.check(ROUTE, client)
        if not ok:
            audit_log.record(request_id="ratelimited", route=ROUTE, client_hash=client[-16:], decision="block",
                             reason="rate limit", filters_fired=["ratelimit"], status_code=429)
            return _error(429, "rate limit exceeded", "rate_limited", headers={"Retry-After": f"{max(1, int(retry + 0.999))}"})
        try:
            body = await request.json()
        except json.JSONDecodeError:
            return _error(400, "body must be JSON", "invalid_json")
        if not isinstance(body, dict):
            return _error(400, "body must be a JSON object", "invalid_request")

        ctx = pipeline.new_context(body, client_id=client, session_id=request.headers.get("x-shipguard-session"))
        try:
            resp = await pipeline.run(ctx)
        except UpstreamError as e:
            audit_log.record(**{**pipeline.audit_fields(ctx, 502), "decision": "error", "reason": str(e)})
            return _error(502, str(e), "upstream_error", ctx.request_id)
        except Exception as e:  # httpx connect errors etc.
            audit_log.record(**{**pipeline.audit_fields(ctx, 502), "decision": "error", "reason": type(e).__name__})
            return _error(502, f"upstream unavailable: {type(e).__name__}", "upstream_error", ctx.request_id)

        status = 200
        if ctx.blocked and policy.server.on_block == "error":
            status = 403
        audit_log.record(**pipeline.audit_fields(ctx, status))
        headers = {"X-ShipGuard-Request-Id": ctx.request_id, "X-ShipGuard-Decision": ctx.decision.value,
                   "X-ShipGuard-Filters": ",".join(ctx.filters_fired)}
        if status == 403:
            return _error(403, f"blocked by ShipGuard: {ctx.reason}", "policy_violation", ctx.request_id, headers)
        if policy.server.expose_decision_in_body:
            resp["shipguard"] = {"request_id": ctx.request_id, "decision": ctx.decision.value,
                                 "reason": ctx.reason, "filters": ctx.filters_fired}
        if body.get("stream"):
            return StreamingResponse(_sse(resp), media_type="text/event-stream", headers=headers)
        return JSONResponse(resp, headers=headers)

    return app


def main() -> None:  # pragma: no cover
    import uvicorn

    uvicorn.run("shipguard.server:create_app", host=os.environ.get("SHIPGUARD_HOST", "0.0.0.0"),
                port=int(os.environ.get("SHIPGUARD_PORT", "8088")), factory=True)


if __name__ == "__main__":  # pragma: no cover
    main()
