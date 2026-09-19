"""The slice of the MCP wire protocol the gateway speaks.

Requests are JSON-RPC 2.0 (``tools/list``, ``tools/call``) so downstream
servers can be ordinary MCP servers fronted by the AgentID SDK.
"""

from __future__ import annotations

import itertools
from typing import Any

JSONRPC_VERSION = "2.0"
METHOD_TOOLS_LIST = "tools/list"
METHOD_TOOLS_CALL = "tools/call"

_counter = itertools.count(1)


def next_id() -> int:
    return next(_counter)


def tools_call(
    name: str, arguments: dict[str, Any] | None = None, *, request_id: Any = None
) -> dict[str, Any]:
    return {
        "jsonrpc": JSONRPC_VERSION,
        "id": request_id if request_id is not None else next_id(),
        "method": METHOD_TOOLS_CALL,
        "params": {"name": name, "arguments": arguments or {}},
    }


def tools_list(*, request_id: Any = None) -> dict[str, Any]:
    return {
        "jsonrpc": JSONRPC_VERSION,
        "id": request_id if request_id is not None else next_id(),
        "method": METHOD_TOOLS_LIST,
        "params": {},
    }


def text_result(text: str, *, is_error: bool = False) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": text}], "isError": is_error}


def error_response(request_id: Any, code: int, message: str, data: Any = None) -> dict[str, Any]:
    error: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    return {"jsonrpc": JSONRPC_VERSION, "id": request_id, "error": error}


def success_response(request_id: Any, result: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": JSONRPC_VERSION, "id": request_id, "result": result}
