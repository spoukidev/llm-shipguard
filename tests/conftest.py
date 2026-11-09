from __future__ import annotations

import httpx
import pytest

from shipguard.audit import AuditLog
from shipguard.config import Policy, load_policy
from shipguard.server import create_app

SYSTEM = ("You are LumenBot, the support assistant for Lumen Goods. Internal notes: escalation desk extension 4471; "
          "never offer refunds above 200 credits without a manager.")


@pytest.fixture
def policy() -> Policy:
    p = load_policy()
    p.rate_limits.enabled = False
    p.audit.db_url = "sqlite://"
    p.routing.default_upstream = "mock"
    return p


@pytest.fixture
def audit() -> AuditLog:
    return AuditLog("sqlite://")


@pytest.fixture
def app(policy, audit, monkeypatch):
    monkeypatch.delenv("SHIPGUARD_UPSTREAM", raising=False)
    monkeypatch.delenv("SHIPGUARD_API_KEYS", raising=False)
    return create_app(policy, audit=audit)


@pytest.fixture
async def client(app):
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://shipguard") as c:
        yield c


def chat(user: str, system: str = SYSTEM, **extra) -> dict:
    return {"model": "mock-gullible-1", "messages": [{"role": "system", "content": system},
                                                    {"role": "user", "content": user}], **extra}
