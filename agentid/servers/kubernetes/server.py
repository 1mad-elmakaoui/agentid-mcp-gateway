"""Example Kubernetes MCP server.

Exists mainly to give the policy engine something genuinely dangerous to deny:
``kubernetes.delete_namespace`` is the canonical denied tool in the demo.
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI

from ...sdk.server import GatewayClaims
from ..common import ResourceDenied, ToolSpec, build_server, text

AUDIENCE = "agentid-mcp:kubernetes"

_NAMESPACES = {
    "default": {"pods": ["api-7f9", "worker-2c1"]},
    "production": {"pods": ["api-prod-1", "api-prod-2"]},
    "staging": {"pods": ["api-stg-1"]},
}

#: Namespaces no caller may destroy, whatever the gateway decided.
PROTECTED_NAMESPACES = {"default", "production"}


def _get_logs(claims: GatewayClaims, arguments: dict[str, Any]) -> dict[str, Any]:
    namespace = str(arguments.get("namespace", "default"))
    pod = str(arguments.get("pod", ""))
    if namespace not in _NAMESPACES:
        raise ResourceDenied(f"unknown namespace: {namespace}", resource=namespace)
    pods = _NAMESPACES[namespace]["pods"]
    if pod and pod not in pods:
        raise ResourceDenied(f"unknown pod: {pod}", resource=f"{namespace}/{pod}")
    target = pod or pods[0]
    return text(
        f"[{namespace}/{target}] served 200 OK (log read by {claims.identity_chain()})"
    )


def _list_pods(_claims: GatewayClaims, arguments: dict[str, Any]) -> dict[str, Any]:
    namespace = str(arguments.get("namespace", "default"))
    if namespace not in _NAMESPACES:
        raise ResourceDenied(f"unknown namespace: {namespace}", resource=namespace)
    return text("\n".join(_NAMESPACES[namespace]["pods"]))


def _delete_namespace(claims: GatewayClaims, arguments: dict[str, Any]) -> dict[str, Any]:
    namespace = str(arguments.get("namespace", ""))
    if namespace in PROTECTED_NAMESPACES:
        raise ResourceDenied(f"{namespace} is protected", resource=namespace)
    if namespace not in _NAMESPACES:
        raise ResourceDenied(f"unknown namespace: {namespace}", resource=namespace)
    return text(f"deleted namespace {namespace} (by {claims.identity_chain()})")


TOOLS = [
    ToolSpec(
        name="get_logs",
        description="Read logs for a pod",
        input_schema={
            "type": "object",
            "properties": {"namespace": {"type": "string"}, "pod": {"type": "string"}},
        },
        handler=_get_logs,
    ),
    ToolSpec(
        name="list_pods",
        description="List pods in a namespace",
        input_schema={"type": "object", "properties": {"namespace": {"type": "string"}}},
        handler=_list_pods,
    ),
    ToolSpec(
        name="delete_namespace",
        description="Delete a namespace (destructive)",
        input_schema={
            "type": "object",
            "properties": {"namespace": {"type": "string"}},
            "required": ["namespace"],
        },
        handler=_delete_namespace,
    ),
]


def create_app(secret: str | None = None) -> FastAPI:
    return build_server(title="Kubernetes MCP", audience=AUDIENCE, tools=TOOLS, secret=secret)


app = create_app()
