"""Per-identity rate limiting.

A fixed-window counter keyed by the authenticated identity (falling back to the
client address for unauthenticated traffic). In-process by design; the same
interface takes a Redis backend in production.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass

from ...config import Settings, get_settings
from ...errors import RateLimitExceeded


@dataclass(slots=True)
class _Window:
    count: int
    reset_at: float


class RateLimiter:
    def __init__(
        self,
        *,
        limit: int | None = None,
        window_seconds: int | None = None,
        settings: Settings | None = None,
    ) -> None:
        settings = settings or get_settings()
        self.enabled = settings.rate_limit_enabled
        self.limit = limit or settings.rate_limit_requests
        self.window_seconds = window_seconds or settings.rate_limit_window_seconds
        self._windows: dict[str, _Window] = {}
        self._lock = threading.Lock()

    def check(self, key: str) -> tuple[int, int]:
        """Consume one unit. Returns ``(remaining, reset_in_seconds)``."""
        if not self.enabled:
            return self.limit, self.window_seconds
        now = time.monotonic()
        with self._lock:
            window = self._windows.get(key)
            if window is None or window.reset_at <= now:
                window = _Window(count=0, reset_at=now + self.window_seconds)
                self._windows[key] = window
            window.count += 1
            remaining = self.limit - window.count
            reset_in = int(window.reset_at - now)
            if window.count > self.limit:
                raise RateLimitExceeded(
                    "rate limit exceeded", retry_after=max(reset_in, 1), limit=self.limit
                )
        return max(remaining, 0), max(reset_in, 0)

    def reset(self, key: str | None = None) -> None:
        with self._lock:
            if key is None:
                self._windows.clear()
            else:
                self._windows.pop(key, None)
