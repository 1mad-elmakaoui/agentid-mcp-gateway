"""Request identity plumbing: a correlation id on every request."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from ...identity.secrets import random_id

REQUEST_ID_HEADER = "X-Request-Id"


class RequestIdMiddleware:
    """Assigns (or propagates) a request id and echoes it on the response."""

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: dict[str, Any], receive: Callable, send: Callable) -> None:
        if scope["type"] != "http":  # pragma: no cover - websockets unsupported
            await self.app(scope, receive, send)
            return

        headers = {
            k.decode("latin-1").lower(): v.decode("latin-1")
            for k, v in scope.get("headers", [])
        }
        request_id = headers.get(REQUEST_ID_HEADER.lower()) or f"req_{random_id(8)}"
        scope.setdefault("state", {})["request_id"] = request_id

        async def send_with_header(message: dict[str, Any]) -> None:
            if message["type"] == "http.response.start":
                message.setdefault("headers", [])
                message["headers"].append(
                    (REQUEST_ID_HEADER.encode("latin-1"), request_id.encode("latin-1"))
                )
            await send(message)

        await self.app(scope, receive, send_with_header)
