"""In-process TTL cache for resolved credentials.

Keeps the hot path off the database and off the identity provider without ever
writing plaintext secrets anywhere durable. Redis can replace this behind the
same tiny interface.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Generic, TypeVar

T = TypeVar("T")


def _now() -> datetime:
    return datetime.now(UTC)


@dataclass(slots=True)
class _Entry(Generic[T]):
    value: T
    expires_at: datetime


class TokenCache(Generic[T]):
    def __init__(self, *, default_ttl_seconds: int = 300, leeway_seconds: int = 30) -> None:
        self.default_ttl_seconds = default_ttl_seconds
        self.leeway_seconds = leeway_seconds
        self._entries: dict[str, _Entry[T]] = {}
        self._lock = threading.Lock()

    def get(self, key: str) -> T | None:
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                return None
            if entry.expires_at <= _now() + timedelta(seconds=self.leeway_seconds):
                self._entries.pop(key, None)
                return None
            return entry.value

    def set(self, key: str, value: T, *, expires_at: datetime | None = None) -> None:
        if expires_at is None:
            expires_at = _now() + timedelta(seconds=self.default_ttl_seconds)
        elif expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=UTC)
        with self._lock:
            self._entries[key] = _Entry(value=value, expires_at=expires_at)

    def invalidate(self, key: str) -> None:
        with self._lock:
            self._entries.pop(key, None)

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()

    def __len__(self) -> int:  # pragma: no cover - diagnostics
        with self._lock:
            return len(self._entries)
