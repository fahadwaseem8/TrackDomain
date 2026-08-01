"""In-process sliding-window rate limiting for the auth endpoints.

Scope: this counter lives in the worker's memory, so N uvicorn workers allow N
times the configured attempts, and restarting clears the window. It raises the
cost of online password guessing considerably, but it is not a substitute for a
shared limiter (Redis) or an edge/WAF rule in production.
"""

import time
from collections import deque

from fastapi import HTTPException, Request, status


class SlidingWindowLimiter:
    def __init__(self, max_attempts: int, window_seconds: float) -> None:
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self._hits: dict[str, deque[float]] = {}
        self._last_prune = 0.0

    def _prune(self, now: float) -> None:
        """Drop keys whose windows have fully expired, so the dict can't grow without bound."""
        if now - self._last_prune < self.window_seconds:
            return
        self._last_prune = now
        stale = [k for k, hits in self._hits.items() if not hits or now - hits[-1] > self.window_seconds]
        for key in stale:
            del self._hits[key]

    def hit(self, key: str) -> float | None:
        """Record an attempt. Returns None if allowed, or seconds until retry if limited."""
        now = time.monotonic()
        self._prune(now)

        hits = self._hits.setdefault(key, deque())
        while hits and now - hits[0] > self.window_seconds:
            hits.popleft()

        if len(hits) >= self.max_attempts:
            return round(self.window_seconds - (now - hits[0]), 1)

        hits.append(now)
        return None

    def reset(self, key: str) -> None:
        """Clear a key's window — called after a success so a legitimate user
        isn't locked out by earlier typos."""
        self._hits.pop(key, None)


def client_key(request: Request, identifier: str) -> str:
    """Bucket by caller IP *and* target account, so one attacker cannot lock out
    an account they don't control, and one IP cannot spray many accounts.

    Behind a proxy this sees the proxy's IP unless uvicorn runs with
    `--proxy-headers` and a trusted `--forwarded-allow-ips`.
    """
    ip = request.client.host if request.client else "unknown"
    return f"{ip}|{identifier.strip().lower()}"


def enforce(limiter: SlidingWindowLimiter, key: str, message: str) -> None:
    retry_after = limiter.hit(key)
    if retry_after is not None:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=message,
            headers={"Retry-After": str(int(retry_after) + 1)},
        )
