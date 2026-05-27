# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Unit tests for MCP Adapter Lambda handler.

Tests the handler entry point wiring: body parsing, error mapping,
and Cedar Evaluator invocation.
"""

from __future__ import annotations

import importlib
import json
from unittest.mock import MagicMock, patch

import pytest

_handler_mod = importlib.import_module("mcp_adapter.handler")
_parser_mod = importlib.import_module("mcp_adapter.mcp_parser")
_guardrails_mod = importlib.import_module("mcp_adapter.guardrails_client")
_envelope_mod = importlib.import_module("mcp_adapter.envelope_builder")

handler = _handler_mod.handler
McpParseError = _parser_mod.McpParseError
GuardrailsUnavailableError = _guardrails_mod.GuardrailsUnavailableError
EnvelopeBuildError = _envelope_mod.EnvelopeBuildError


def _make_valid_mcp_body() -> dict:
    """Return a minimal valid MCP tool call message dict."""
    return {
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
                "delegation_chain": [],
                "delegation_depth": 0,
            },
        },
    }


def _api_gw_event(body: dict | str | None = None) -> dict:
    """Wrap a body into an API Gateway proxy event."""
    if body is None:
        return {"body": None}
    if isinstance(body, dict):
        return {"body": json.dumps(body)}
    return {"body": body}


# ── Body parsing ────────────────────────────────────────────────────


class TestBodyParsing:
    def test_missing_body_returns_400(self) -> None:
        resp = handler({"body": None}, None)
        assert resp["statusCode"] == 400

    def test_invalid_json_body_returns_400(self) -> None:
        resp = handler({"body": "not-json{"}, None)
        assert resp["statusCode"] == 400

    def test_non_object_body_returns_400(self) -> None:
        resp = handler({"body": '"just a string"'}, None)
        assert resp["statusCode"] == 400

    def test_dict_body_accepted(self) -> None:
        """When body is already a dict (e.g. direct Lambda invoke), it works."""
        event = {"body": _make_valid_mcp_body()}
        with patch.object(_handler_mod, "apply_guardrail") as mock_gr, \
             patch.object(_handler_mod, "build_envelope") as mock_env, \
             patch.object(_handler_mod, "_invoke_cedar_evaluator") as mock_invoke:
            mock_gr.return_value = MagicMock()
            mock_env.return_value = {"request_id": "test"}
            mock_invoke.return_value = {"decision": "PERMIT"}
            resp = handler(event, None)
        assert resp["statusCode"] == 200


# ── McpParseError → 400 ────────────────────────────────────────────


class TestMcpParseErrorMapping:
    def test_malformed_mcp_returns_400_jsonrpc_error(self) -> None:
        body = {"jsonrpc": "2.0", "id": "r1", "method": "tools/call"}
        # Missing "params" → McpParseError
        resp = handler(_api_gw_event(body), None)
        assert resp["statusCode"] == 400
        error_body = json.loads(resp["body"])
        assert "error" in error_body


# ── GuardrailsUnavailableError → 503 ───────────────────────────────


class TestGuardrailsUnavailableMapping:
    def test_guardrails_unavailable_returns_503(self) -> None:
        event = _api_gw_event(_make_valid_mcp_body())
        with patch.object(
            _handler_mod,
            "apply_guardrail",
            side_effect=GuardrailsUnavailableError("service down"),
        ):
            resp = handler(event, None)
        assert resp["statusCode"] == 503
        body = json.loads(resp["body"])
        assert "unavailable" in body["error"].lower()


# ── EnvelopeBuildError → 400 ───────────────────────────────────────


class TestEnvelopeBuildErrorMapping:
    def test_envelope_build_error_returns_400(self) -> None:
        event = _api_gw_event(_make_valid_mcp_body())
        with patch.object(_handler_mod, "apply_guardrail") as mock_gr, \
             patch.object(
                 _handler_mod,
                 "build_envelope",
                 side_effect=EnvelopeBuildError("missing agent"),
             ):
            mock_gr.return_value = MagicMock()
            resp = handler(event, None)
        assert resp["statusCode"] == 400
        body = json.loads(resp["body"])
        assert "missing agent" in body["message"]


# ── Cedar Evaluator invocation failure → 502 ───────────────────────


class TestCedarEvaluatorInvocationFailure:
    def test_invocation_failure_returns_502(self) -> None:
        event = _api_gw_event(_make_valid_mcp_body())
        with patch.object(_handler_mod, "apply_guardrail") as mock_gr, \
             patch.object(_handler_mod, "build_envelope") as mock_env, \
             patch.object(
                 _handler_mod,
                 "_invoke_cedar_evaluator",
                 side_effect=_handler_mod._CedarEvaluatorInvocationError("timeout"),
             ):
            mock_gr.return_value = MagicMock()
            mock_env.return_value = {"request_id": "test"}
            resp = handler(event, None)
        assert resp["statusCode"] == 502
        body = json.loads(resp["body"])
        assert "timeout" in body["message"]


# ── Happy path ──────────────────────────────────────────────────────


class TestHappyPath:
    def test_successful_evaluation_returns_200(self) -> None:
        event = _api_gw_event(_make_valid_mcp_body())
        eval_result = {"decision": "PERMIT", "layer_results": {"L1": "PERMIT"}}
        with patch.object(_handler_mod, "apply_guardrail") as mock_gr, \
             patch.object(_handler_mod, "build_envelope") as mock_env, \
             patch.object(_handler_mod, "_invoke_cedar_evaluator") as mock_invoke:
            mock_gr.return_value = MagicMock()
            mock_env.return_value = {"request_id": "test-id"}
            mock_invoke.return_value = eval_result
            resp = handler(event, None)
        assert resp["statusCode"] == 200
        body = json.loads(resp["body"])
        assert body["decision"] == "PERMIT"

    def test_response_has_json_content_type(self) -> None:
        event = _api_gw_event(_make_valid_mcp_body())
        with patch.object(_handler_mod, "apply_guardrail") as mock_gr, \
             patch.object(_handler_mod, "build_envelope") as mock_env, \
             patch.object(_handler_mod, "_invoke_cedar_evaluator") as mock_invoke:
            mock_gr.return_value = MagicMock()
            mock_env.return_value = {"request_id": "test-id"}
            mock_invoke.return_value = {"decision": "DENY"}
            resp = handler(event, None)
        assert resp["headers"]["Content-Type"] == "application/json"


# ── _invoke_cedar_evaluator ─────────────────────────────────────────


class TestInvokeCedarEvaluator:
    def test_missing_function_name_raises(self) -> None:
        with patch.object(_handler_mod, "CEDAR_EVALUATOR_FUNCTION_NAME", ""):
            with pytest.raises(_handler_mod._CedarEvaluatorInvocationError, match="not set"):
                _handler_mod._invoke_cedar_evaluator({"request_id": "test"})

    def test_function_error_raises(self) -> None:
        mock_client = MagicMock()
        payload_mock = MagicMock()
        payload_mock.read.return_value = b'{"errorMessage": "boom"}'
        mock_client.invoke.return_value = {
            "FunctionError": "Unhandled",
            "Payload": payload_mock,
        }
        with patch.object(_handler_mod, "CEDAR_EVALUATOR_FUNCTION_NAME", "my-func"), \
             patch.object(_handler_mod, "_get_lambda_client", return_value=mock_client):
            with pytest.raises(_handler_mod._CedarEvaluatorInvocationError, match="error"):
                _handler_mod._invoke_cedar_evaluator({"request_id": "test"})

    def test_successful_invoke_returns_payload(self) -> None:
        mock_client = MagicMock()
        result = {"decision": "PERMIT"}
        payload_mock = MagicMock()
        payload_mock.read.return_value = json.dumps(result).encode()
        mock_client.invoke.return_value = {
            "Payload": payload_mock,
        }
        with patch.object(_handler_mod, "CEDAR_EVALUATOR_FUNCTION_NAME", "my-func"), \
             patch.object(_handler_mod, "_get_lambda_client", return_value=mock_client):
            out = _handler_mod._invoke_cedar_evaluator({"request_id": "test"})
        assert out == result
