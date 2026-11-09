"""In-memory token-bucket rate limiting keyed by (route, client).

Good enough for a single gateway replica; swap :class:`RateLimiter` for a
Redis-backed implementation to share limits across replicas.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass

from shipguard.config import RateLimit, RateLimitConfig


@dataclass
class _Bucket:
    tokens: float
    updated: float


class RateLimiter:
    def __init__(self, cfg: RateLimitConfig, clock=time.monotonic) -> None:
        self.cfg = cfg
        self.clock = clock
        self._buckets: dict[tuple[str, str], _Bucket] = {}
        self._lock = threading.Lock()

    def limit_for(self, route: str) -> RateLimit:
        return self.cfg.routes.get(route, self.cfg.default)

    def check(self, route: str, client: str) -> tuple[bool, float]:
        """Consume one token. Returns (allowed, retry_after_seconds)."""
        if not self.cfg.enabled:
            return True, 0.0
        lim = self.limit_for(route)
        rate = lim.requests_per_minute / 60.0
        now = self.clock()
        with self._lock:
            b = self._buckets.get((route, client))
            if b is None:
                b = _Bucket(tokens=float(lim.burst), updated=now)
                self._buckets[(route, client)] = b
            b.tokens = min(float(lim.burst), b.tokens + (now - b.updated) * rate)
            b.updated = now
            if b.tokens >= 1.0:
                b.tokens -= 1.0
                return True, 0.0
            retry = (1.0 - b.tokens) / rate if rate > 0 else 60.0
            return False, retry

    def reset(self) -> None:
        with self._lock:
            self._buckets.clear()
