"""HTTP mock upstream LLM (OpenAI-compatible) for Docker / local demos.

Wraps :mod:`shipguard.mock_llm`. Also exposes ``GET /mock/received`` so the
demo can prove what the "provider" actually saw (e.g. that a secret was
redacted before it left the gateway). Never deploy this anywhere public.
"""

from __future__ import annotations

from fastapi import FastAPI, Request

from shipguard import mock_llm

app = FastAPI(title="ShipGuard mock upstream (gullible by design)")


@app.get("/healthz")
async def healthz() -> dict:
    return {"status": "ok"}


@app.get("/v1/models")
async def models() -> dict:
    return {"object": "list", "data": [{"id": "mock-gullible-1", "object": "model", "owned_by": "mock"}]}


@app.post("/v1/chat/completions")
async def chat(request: Request) -> dict:
    return mock_llm.respond(await request.json())


@app.get("/mock/received")
async def received(limit: int = 5) -> dict:
    return {"requests": list(mock_llm.RECEIVED)[-limit:]}


@app.delete("/mock/received")
async def clear() -> dict:
    mock_llm.RECEIVED.clear()
    return {"cleared": True}
