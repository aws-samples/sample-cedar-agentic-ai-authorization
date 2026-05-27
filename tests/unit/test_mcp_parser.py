# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Unit tests for MCP message parser.

Tests valid MCP request parsing, malformed message handling,
and extraction of agent identity, user context, and delegation chain.
"""

from __future__ import annotations

import importlib

import pytest

# ``lambda`` is a Python keyword, so we use importlib to import from it.
_parser_mod = importlib.import_module("mcp_adapter.mcp_parser")

McpParseError = _parser_mod.McpParseError
ParsedMcpRequest = _parser_mod.ParsedMcpRequest
AgentIdentity = _parser_mod.AgentIdentity
UserContext = _parser_mod.UserContext
parse_mcp_message = _parser_mod.parse_mcp_message


def _make_valid_mcp_message(**overrides: object) -> dict:
    """Build a minimal valid MCP tool call message."""
    msg: dict = {
        "jsonrpc": "2.0",
        "method": "tools/call",
        "id": "req-001",
        "params": {
            "name": "process_payment",
            "arguments": {"amount": 100},
            "_meta": {
                "agent_id": "finance-agent",
                "trust_level": 3,
                "namespace": "payments",
                "registered_capabilities": ["process_payment"],
                "lifecycle_stage": "production",
                "user_context": {
                    "user_id": "user-123",
                    "role": "admin",
                    "mfa_verified": True,
                    "authentication_method": "sso",
                    "session_id": "sess-abc",
                },
                "delegation_chain": [
                    {
                        "hop": 0,
                        "agent_id": "orchestrator",
                        "capabilities_granted": ["process_payment"],
                        "timestamp": "2026-04-13T12:00:00Z",
                    }
                ],
                "delegation_depth": 1,
            },
        },
    }
    for key, val in overrides.items():
        msg[key] = val
    return msg


# ── Happy path ──────────────────────────────────────────────────────


class TestParseValidMessage:
    def test_extracts_jsonrpc_fields(self) -> None:
        result = parse_mcp_message(_make_valid_mcp_message())
        assert result.jsonrpc == "2.0"
        assert result.request_id == "req-001"
        assert result.method == "tools/call"

    def test_extracts_tool_name(self) -> None:
        result = parse_mcp_message(_make_valid_mcp_message())
        assert result.tool_name == "process_payment"

    def test_extracts_arguments(self) -> None:
        result = parse_mcp_message(_make_valid_mcp_message())
        assert result.arguments == {"amount": 100}

    def test_extracts_agent_identity(self) -> None:
        result = parse_mcp_message(_make_valid_mcp_message())
        ai = result.agent_identity
        assert ai is not None
        assert ai.agent_id == "finance-agent"
        assert ai.trust_level == 3
        assert ai.namespace == "payments"
        assert ai.registered_capabilities == ["process_payment"]
        assert ai.lifecycle_stage == "production"

    def test_extracts_user_context(self) -> None:
        result = parse_mcp_message(_make_valid_mcp_message())
        uc = result.user_context
        assert uc is not None
        assert uc.user_id == "user-123"
        assert uc.role == "admin"
        assert uc.mfa_verified is True
        assert uc.authentication_method == "sso"
        assert uc.session_id == "sess-abc"

    def test_extracts_delegation_chain(self) -> None:
        result = parse_mcp_message(_make_valid_mcp_message())
        assert len(result.delegation_chain) == 1
        hop = result.delegation_chain[0]
        assert hop.hop == 0
        assert hop.agent_id == "orchestrator"
        assert hop.capabilities_granted == ["process_payment"]

    def test_extracts_delegation_depth(self) -> None:
        result = parse_mcp_message(_make_valid_mcp_message())
        assert result.delegation_depth == 1

    def test_preserves_raw_meta(self) -> None:
        result = parse_mcp_message(_make_valid_mcp_message())
        assert "agent_id" in result.raw_meta


# ── Optional fields ─────────────────────────────────────────────────


class TestOptionalFields:
    def test_missing_meta_returns_none_agent_and_user(self) -> None:
        msg = _make_valid_mcp_message()
        msg["params"]["_meta"] = {}
        result = parse_mcp_message(msg)
        assert result.agent_identity is None
        assert result.user_context is None
        assert result.delegation_chain == []
        assert result.delegation_depth == 0

    def test_missing_arguments_defaults_to_empty_dict(self) -> None:
        msg = _make_valid_mcp_message()
        del msg["params"]["arguments"]
        result = parse_mcp_message(msg)
        assert result.arguments == {}

    def test_missing_delegation_chain_defaults_to_empty(self) -> None:
        msg = _make_valid_mcp_message()
        del msg["params"]["_meta"]["delegation_chain"]
        result = parse_mcp_message(msg)
        assert result.delegation_chain == []


# ── Malformed messages ──────────────────────────────────────────────


class TestMalformedMessages:
    def test_missing_jsonrpc_field(self) -> None:
        msg = _make_valid_mcp_message()
        del msg["jsonrpc"]
        with pytest.raises(McpParseError, match="jsonrpc"):
            parse_mcp_message(msg)

    def test_wrong_jsonrpc_version(self) -> None:
        with pytest.raises(McpParseError, match="jsonrpc"):
            parse_mcp_message(_make_valid_mcp_message(jsonrpc="1.0"))

    def test_missing_id(self) -> None:
        msg = _make_valid_mcp_message()
        del msg["id"]
        with pytest.raises(McpParseError, match="id"):
            parse_mcp_message(msg)

    def test_missing_method(self) -> None:
        msg = _make_valid_mcp_message()
        del msg["method"]
        with pytest.raises(McpParseError, match="method"):
            parse_mcp_message(msg)

    def test_unsupported_method(self) -> None:
        with pytest.raises(McpParseError, match="Unsupported method"):
            parse_mcp_message(_make_valid_mcp_message(method="resources/list"))

    def test_missing_params(self) -> None:
        msg = _make_valid_mcp_message()
        del msg["params"]
        with pytest.raises(McpParseError, match="params"):
            parse_mcp_message(msg)

    def test_params_not_dict(self) -> None:
        msg = _make_valid_mcp_message()
        msg["params"] = "not-a-dict"
        with pytest.raises(McpParseError, match="params.*JSON object"):
            parse_mcp_message(msg)

    def test_missing_tool_name(self) -> None:
        msg = _make_valid_mcp_message()
        del msg["params"]["name"]
        with pytest.raises(McpParseError, match="params.name"):
            parse_mcp_message(msg)

    def test_empty_tool_name(self) -> None:
        msg = _make_valid_mcp_message()
        msg["params"]["name"] = ""
        with pytest.raises(McpParseError, match="params.name"):
            parse_mcp_message(msg)

    def test_meta_not_dict(self) -> None:
        msg = _make_valid_mcp_message()
        msg["params"]["_meta"] = "bad"
        with pytest.raises(McpParseError, match="_meta.*JSON object"):
            parse_mcp_message(msg)

    def test_trust_level_not_int(self) -> None:
        msg = _make_valid_mcp_message()
        msg["params"]["_meta"]["trust_level"] = "high"
        with pytest.raises(McpParseError, match="trust_level"):
            parse_mcp_message(msg)

    def test_missing_user_context_field(self) -> None:
        msg = _make_valid_mcp_message()
        del msg["params"]["_meta"]["user_context"]["role"]
        with pytest.raises(McpParseError, match="role"):
            parse_mcp_message(msg)

    def test_mfa_verified_not_bool(self) -> None:
        msg = _make_valid_mcp_message()
        msg["params"]["_meta"]["user_context"]["mfa_verified"] = "yes"
        with pytest.raises(McpParseError, match="mfa_verified.*boolean"):
            parse_mcp_message(msg)

    def test_negative_delegation_depth(self) -> None:
        msg = _make_valid_mcp_message()
        msg["params"]["_meta"]["delegation_depth"] = -1
        with pytest.raises(McpParseError, match="delegation_depth"):
            parse_mcp_message(msg)

    def test_delegation_chain_not_list(self) -> None:
        msg = _make_valid_mcp_message()
        msg["params"]["_meta"]["delegation_chain"] = "bad"
        with pytest.raises(McpParseError, match="delegation_chain.*array"):
            parse_mcp_message(msg)

    def test_delegation_chain_entry_missing_agent_id(self) -> None:
        msg = _make_valid_mcp_message()
        msg["params"]["_meta"]["delegation_chain"] = [{"hop": 0}]
        with pytest.raises(McpParseError, match="agent_id"):
            parse_mcp_message(msg)


# ── JSON-RPC error response ────────────────────────────────────────


class TestJsonRpcErrorResponse:
    def test_error_response_format(self) -> None:
        err = McpParseError("test error", error_code=-32600)
        resp = err.to_jsonrpc_error(request_id="req-1")
        assert resp["jsonrpc"] == "2.0"
        assert resp["id"] == "req-1"
        assert resp["error"]["code"] == -32600
        assert resp["error"]["message"] == "test error"

    def test_error_response_with_none_id(self) -> None:
        err = McpParseError("bad request")
        resp = err.to_jsonrpc_error()
        assert resp["id"] is None
