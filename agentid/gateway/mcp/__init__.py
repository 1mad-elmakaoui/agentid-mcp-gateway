"""Gateway-side MCP routing, proxying and discovery."""

from .discovery import DiscoveryResult, discover, permitted_tool_names
from .protocol import METHOD_TOOLS_CALL, METHOD_TOOLS_LIST, tools_call, tools_list
from .proxy import McpProxy, ProxyResponse
from .router import Route, resolve_route

__all__ = [
    "METHOD_TOOLS_CALL",
    "METHOD_TOOLS_LIST",
    "DiscoveryResult",
    "McpProxy",
    "ProxyResponse",
    "Route",
    "discover",
    "permitted_tool_names",
    "resolve_route",
    "tools_call",
    "tools_list",
]
