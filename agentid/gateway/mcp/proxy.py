"""The MCP proxy.

Forwards an already-authorized call to the target MCP server with the
gateway-issued credential attached. The proxy has no authorization logic of its
own precisely so it cannot be used to bypass any (invariant 5): it is only ever
handed a :class:`~agentid.authorization.decisions.Decision` that already allows.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import httpx

from ...config import Settings, get_settings
from ...errors import DownstreamError
from . import protocol
from .router import Route


@dataclass(slots=True)
class ProxyResponse:
    status_code: int
    result: dict[str, Any] | None = None
    error: dict[str, Any] | None = None
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def is_error(self) -> bool:
        if self.error is not None:
            return True
        return bool(self.result and self.result.get("isError"))


class McpProxy:
    def __init__(
        self,
        *,
        settings: Settings | None = None,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self._client = client
        self._owns_client = client is None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=self.settings.downstream_timeout_seconds)
        return self._client

    async def aclose(self) -> None:
        if self._client is not None and self._owns_client:
            await self._client.aclose()
            self._client = None

    async def call_tool(
        self,
        route: Route,
        arguments: dict[str, Any],
        *,
        headers: dict[str, str],
        request_id: str | None = None,
    ) -> ProxyResponse:
        payload = protocol.tools_call(
            route.downstream_name, arguments, request_id=request_id
        )
        return await self._post(route.url, payload, headers=headers, server=route.server.name)

    async def list_tools(
        self, endpoint: str, *, headers: dict[str, str], server: str
    ) -> ProxyResponse:
        payload = protocol.tools_list()
        return await self._post(f"{endpoint}/mcp", payload, headers=headers, server=server)

    async def _post(
        self,
        url: str,
        payload: dict[str, Any],
        *,
        headers: dict[str, str],
        server: str,
    ) -> ProxyResponse:
        client = await self._get_client()
        try:
            response = await client.post(
                url,
                json=payload,
                headers={"Content-Type": "application/json", **headers},
                timeout=self.settings.downstream_timeout_seconds,
            )
        except httpx.TimeoutException as exc:
            raise DownstreamError(
                f"{server} timed out", code="downstream_timeout", server=server
            ) from exc
        except httpx.HTTPError as exc:
            raise DownstreamError(
                f"{server} is unreachable: {exc}", code="downstream_unreachable", server=server
            ) from exc

        try:
            body = response.json()
        except ValueError as exc:
            raise DownstreamError(
                f"{server} returned a non-JSON response",
                code="downstream_malformed",
                server=server,
            ) from exc

        if not isinstance(body, dict):
            raise DownstreamError(
                f"{server} returned an unexpected payload",
                code="downstream_malformed",
                server=server,
            )

        return ProxyResponse(
            status_code=response.status_code,
            result=body.get("result"),
            error=body.get("error"),
            raw=body,
        )
