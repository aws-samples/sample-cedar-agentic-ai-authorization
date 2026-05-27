# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""MCP JSON-RPC 2.0 tool call message parser.

Parses MCP tool call messages, extracts method name, params, agent identity,
and security metadata. Returns a structured ParsedMcpRequest or raises
McpParseError for malformed messages.

Validates: Requirements 5.2
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional


class McpParseError(Exception):
    """Raised when an MCP message is malformed or missing required fields."""

    def __init__(self, message: str, error_code: int = -32600) -> None:
        self.message = message
        self.error_code = error_code
        super().__init__(message)

    def to_jsonrpc_error(self, request_id: Any = None) -> dict:
        """Return a JSON-RPC 2.0 error response dict."""
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {
                "code": self.error_code,
                "message": self.message,
            },
        }


@dataclass
class UserContext:
    """Originating user context extracted from MCP _meta."""

    user_id: str
    role: str
    mfa_verified: bool
    authentication_method: str
    session_id: str


@dataclass
class DelegationHop:
    """A single hop in the delegation chain from MCP _meta."""

    hop: int
    agent_id: str
    capabilities_granted: list[str] = field(default_factory=list)
    timestamp: str = ""


@dataclass
class AgentIdentity:
    """Agent identity extracted from MCP _meta."""

    agent_id: str
    trust_level: int
    namespace: str
    registered_capabilities: list[str] = field(default_factory=list)
    lifecycle_stage: str = ""


@dataclass
class ParsedMcpRequest:
    """Structured result of parsing an MCP tool call message."""

    jsonrpc: str
    request_id: Any
    method: str
    tool_name: str
    arguments: dict = field(default_factory=dict)
    agent_identity: Optional[AgentIdentity] = None
    user_context: Optional[UserContext] = None
    delegation_chain: list[DelegationHop] = field(default_factory=list)
    delegation_depth: int = 0
    raw_meta: dict = field(default_factory=dict)


def parse_mcp_message(message: dict) -> ParsedMcpRequest:
    """Parse an MCP JSON-RPC 2.0 tool call message.

    Args:
        message: The raw MCP message dict (already deserialized from JSON).

    Returns:
        ParsedMcpRequest with all extracted fields.

    Raises:
        McpParseError: If the message is malformed or missing required fields.
    """
    _validate_jsonrpc_structure(message)
    _validate_method(message)

    params = message.get("params")
    if not isinstance(params, dict):
        raise McpParseError("'params' must be a JSON object")

    tool_name = _extract_tool_name(params)
    arguments = params.get("arguments", {})
    if not isinstance(arguments, dict):
        raise McpParseError("'params.arguments' must be a JSON object")

    meta = params.get("_meta", {})
    if not isinstance(meta, dict):
        raise McpParseError("'params._meta' must be a JSON object")

    agent_identity = _extract_agent_identity(meta)
    user_context = _extract_user_context(meta)
    delegation_chain = _extract_delegation_chain(meta)
    delegation_depth = _extract_delegation_depth(meta)

    return ParsedMcpRequest(
        jsonrpc=message["jsonrpc"],
        request_id=message["id"],
        method=message["method"],
        tool_name=tool_name,
        arguments=arguments,
        agent_identity=agent_identity,
        user_context=user_context,
        delegation_chain=delegation_chain,
        delegation_depth=delegation_depth,
        raw_meta=meta,
    )


def _validate_jsonrpc_structure(message: dict) -> None:
    """Validate the top-level JSON-RPC 2.0 structure."""
    if not isinstance(message, dict):
        raise McpParseError("MCP message must be a JSON object", error_code=-32600)

    if message.get("jsonrpc") != "2.0":
        raise McpParseError(
            "Missing or invalid 'jsonrpc' field: must be '2.0'",
            error_code=-32600,
        )

    if "id" not in message:
        raise McpParseError(
            "Missing required 'id' field in JSON-RPC message",
            error_code=-32600,
        )

    if "method" not in message:
        raise McpParseError(
            "Missing required 'method' field in JSON-RPC message",
            error_code=-32600,
        )

    if "params" not in message:
        raise McpParseError(
            "Missing required 'params' field in JSON-RPC message",
            error_code=-32600,
        )


def _validate_method(message: dict) -> None:
    """Validate that the method is 'tools/call'."""
    method = message["method"]
    if method != "tools/call":
        raise McpParseError(
            f"Unsupported method '{method}': only 'tools/call' is supported",
            error_code=-32601,
        )


def _extract_tool_name(params: dict) -> str:
    """Extract and validate the tool name from params."""
    name = params.get("name")
    if not name or not isinstance(name, str):
        raise McpParseError("Missing or invalid 'params.name': must be a non-empty string")
    return name


def _extract_agent_identity(meta: dict) -> Optional[AgentIdentity]:
    """Extract agent identity from _meta if present."""
    agent_id = meta.get("agent_id")
    if agent_id is None:
        return None

    trust_level = meta.get("trust_level")
    if not isinstance(trust_level, int):
        raise McpParseError(
            "'_meta.trust_level' must be an integer when agent_id is present"
        )

    namespace = meta.get("namespace")
    if not isinstance(namespace, str):
        raise McpParseError(
            "'_meta.namespace' must be a string when agent_id is present"
        )

    return AgentIdentity(
        agent_id=str(agent_id),
        trust_level=trust_level,
        namespace=namespace,
        registered_capabilities=meta.get("registered_capabilities", []),
        lifecycle_stage=meta.get("lifecycle_stage", ""),
    )


def _extract_user_context(meta: dict) -> Optional[UserContext]:
    """Extract user context from _meta.user_context if present."""
    uc = meta.get("user_context")
    if uc is None:
        return None

    if not isinstance(uc, dict):
        raise McpParseError("'_meta.user_context' must be a JSON object")

    required_fields = ["user_id", "role", "mfa_verified", "authentication_method", "session_id"]
    missing = [f for f in required_fields if f not in uc]
    if missing:
        raise McpParseError(
            f"Missing required user_context fields: {', '.join(missing)}"
        )

    if not isinstance(uc["mfa_verified"], bool):
        raise McpParseError("'user_context.mfa_verified' must be a boolean")

    return UserContext(
        user_id=str(uc["user_id"]),
        role=str(uc["role"]),
        mfa_verified=uc["mfa_verified"],
        authentication_method=str(uc["authentication_method"]),
        session_id=str(uc["session_id"]),
    )


def _extract_delegation_chain(meta: dict) -> list[DelegationHop]:
    """Extract delegation chain from _meta if present."""
    chain = meta.get("delegation_chain")
    if chain is None:
        return []

    if not isinstance(chain, list):
        raise McpParseError("'_meta.delegation_chain' must be an array")

    hops: list[DelegationHop] = []
    for i, entry in enumerate(chain):
        if not isinstance(entry, dict):
            raise McpParseError(f"delegation_chain[{i}] must be a JSON object")
        if "agent_id" not in entry:
            raise McpParseError(f"delegation_chain[{i}] missing required 'agent_id'")
        hops.append(
            DelegationHop(
                hop=entry.get("hop", i),
                agent_id=str(entry["agent_id"]),
                capabilities_granted=entry.get("capabilities_granted", []),
                timestamp=str(entry.get("timestamp", "")),
            )
        )
    return hops


def _extract_delegation_depth(meta: dict) -> int:
    """Extract delegation depth from _meta, defaulting to 0."""
    depth = meta.get("delegation_depth", 0)
    if not isinstance(depth, int) or depth < 0:
        raise McpParseError("'_meta.delegation_depth' must be a non-negative integer")
    return depth
