"""The *same* LumenBot, unchanged, with its OpenAI base URL pointed at ShipGuard.

This is the whole integration: no code changes in the app, only::

    OPENAI_BASE_URL=http://localhost:8088/v1

Run::

    SHIPGUARD_URL=http://localhost:8088/v1 python -m demo.guarded_app
"""

from __future__ import annotations

import os

from demo.vulnerable_app import SupportBot
from demo.vulnerable_app import create_app as _create_vulnerable_app

GATEWAY_URL = os.environ.get("SHIPGUARD_URL", "http://localhost:8088/v1")


def create_app(base_url: str | None = None):
    return _create_vulnerable_app(base_url or GATEWAY_URL, title="LumenBot (behind ShipGuard)")


def guarded_bot(base_url: str | None = None, **kw) -> SupportBot:
    return SupportBot(base_url or GATEWAY_URL, **kw)


if __name__ == "__main__":  # pragma: no cover
    import uvicorn

    uvicorn.run(create_app(), host="0.0.0.0", port=int(os.environ.get("PORT", "8102")))
