"""Token-bucket rate limiting.

Buckets live in memory, so limits apply per AgentWarden instance: with N instances behind a load
balancer, a client can reach roughly N times the configured rate. That is the usual trade-off for
a limiter whose only job is to blunt floods and brute force; exact global quotas belong in the
load balancer or API gateway.
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from collections.abc import Callable


class RateLimiter:
    """``rate_per_minute`` tokens per key, refilled continuously, with a burst of the same size.

    A rate of ``0`` disables the limiter. At most ``max_keys`` buckets are kept (least recently
    used are dropped), so an attacker rotating keys can't exhaust memory.
    """

    def __init__(
        self,
        rate_per_minute: int,
        *,
        burst: int | None = None,
        clock: Callable[[], float] = time.monotonic,
        max_keys: int = 50_000,
    ) -> None:
        self.rate_per_minute = rate_per_minute
        self.capacity = float(burst if burst is not None else rate_per_minute)
        self._per_second = rate_per_minute / 60.0
        self._clock = clock
        self._max_keys = max_keys
        self._buckets: OrderedDict[str, tuple[float, float]] = OrderedDict()
        self._lock = threading.Lock()

    @property
    def enabled(self) -> bool:
        return self.rate_per_minute > 0

    def _level(self, key: str, now: float) -> float:
        tokens, last = self._buckets.get(key, (self.capacity, now))
        return min(self.capacity, tokens + (now - last) * self._per_second)

    def _retry_after(self, tokens: float) -> float:
        return max(0.001, (1.0 - tokens) / self._per_second)

    def peek(self, key: str) -> float | None:
        """Seconds until ``key`` may act again, or ``None`` if it may act now. Consumes nothing."""
        if not self.enabled:
            return None
        with self._lock:
            tokens = self._level(key, self._clock())
            return None if tokens >= 1.0 else self._retry_after(tokens)

    def hit(self, key: str) -> float | None:
        """Consume one token. Returns ``None`` if allowed, else seconds until the next token."""
        if not self.enabled:
            return None
        with self._lock:
            now = self._clock()
            tokens = self._level(key, now)
            if tokens < 1.0:
                self._buckets[key] = (tokens, now)
                self._buckets.move_to_end(key)
                return self._retry_after(tokens)
            self._buckets[key] = (tokens - 1.0, now)
            self._buckets.move_to_end(key)
            while len(self._buckets) > self._max_keys:
                self._buckets.popitem(last=False)
            return None
