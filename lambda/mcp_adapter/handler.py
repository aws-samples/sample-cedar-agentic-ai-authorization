# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""MCP Protocol Adapter Lambda handler.

Entry point that wires together mcp_parser → guardrails_client →
envelope_builder → synchronous invoke of Cedar Evaluator Lambda.

Validates: Requirements 5.1, 5.2, 5.3, 5.4, 7.5
"""

from __future__ import annotations

import importlib
import json
import logging
import os
from typing import Any

import boto3

# ``lambda`` is a Python keyword — use importlib for intra-package imports.
_parser_mod = importlib.import_module("mcp_adapter.mcp_parser")
_guardrails_mod = importlib.import_module("mcp_adapter.guardrails_client")
_envelope_mod = importlib.import_module("mcp_adapter.envelope_builder")

parse_mcp_message = _parser_mod.parse_mcp_message
McpParseError = _parser_mod.McpParseError

apply_guardrail = _guardrails_mod.apply_guardrail
GuardrailsUnavailableError = _guardrails_mod.GuardrailsUnavailableError

build_envelope = _envelope_mod.build_envelope
EnvelopeBuildError = _envelope_mod.EnvelopeBuildError

logger = logging.getLogger(__name__)
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

# Environment variables
CEDAR_EVALUATOR_FUNCTION_NAME = os.environ.get("CEDAR_EVALUATOR_FUNCTION_NAME", "")

# Module-level lazy Lambda client
_lambda_client = None


def _get_lambda_client():
    """Return a boto3 Lambda client (lazy singleton)."""
    global _lambda_client  # noqa: PLW0603
    if _lambda_client is None:
        _lambda_client = boto3.client("lambda")
    return _lambda_client


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """Lambda handler for the MCP Protocol Adapter.

    Receives an API Gateway event, parses the MCP JSON-RPC message,
    applies Amazon Bedrock Guardrails content filtering, builds a signed
    Request Envelope, and invokes the Cedar Evaluator Lambda.

    Args:
        event: API Gateway proxy event with the MCP message in ``body``.
        context: Lambda context (unused).

    Returns:
        API Gateway proxy response with the Cedar evaluation result.
    """
    request_id: str | None = None

    try:
        # 1. Parse the API Gateway event body as JSON
        body = _parse_event_body(event)

        # 2. Parse the MCP JSON-RPC message
        parsed = parse_mcp_message(body)
        request_id = parsed.request_id

        # 3. Apply Amazon Bedrock Guardrails content filtering
        content_filter_result = apply_guardrail(body)

        # 4. Build the signed Request Envelope
        envelope = build_envelope(parsed, content_filter_result)

        # 5. Invoke the Cedar Evaluator Lambda synchronously
        evaluation_result = _invoke_cedar_evaluator(envelope)

        # 6. Return the evaluation result
        return _success_response(evaluation_result)

    except McpParseError as exc:
        logger.warning("MCP parse error: %s", exc.message)
        return _error_response(
            status_code=400,
            body=exc.to_jsonrpc_error(request_id),
        )

    except GuardrailsUnavailableError as exc:
        logger.error("Guardrails unavailable: %s", exc.message)
        return _error_response(
            status_code=503,
            body={"error": "Content filtering service unavailable", "message": exc.message},
        )

    except EnvelopeBuildError as exc:
        logger.warning("Envelope build error: %s", exc.message)
        return _error_response(
            status_code=400,
            body={"error": "Envelope construction failed", "message": exc.message},
        )

    except _CedarEvaluatorInvocationError as exc:
        logger.error("Cedar Evaluator invocation failed: %s", exc.message)
        return _error_response(
            status_code=502,
            body={
                "error": "Cedar Evaluator invocation failed",
                "message": exc.message,
                "request_id": request_id,
            },
        )

    except Exception:
        logger.exception("Unexpected error in MCP Adapter handler")
        return _error_response(
            status_code=500,
            body={"error": "Internal server error"},
        )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


class _CedarEvaluatorInvocationError(Exception):
    """Raised when the Cedar Evaluator Lambda invocation fails."""

    def __init__(self, message: str) -> None:
        self.message = message
        super().__init__(message)


def _parse_event_body(event: dict[str, Any]) -> dict:
    """Extract and parse the JSON body from an API Gateway event.

    Args:
        event: The API Gateway proxy event.

    Returns:
        The parsed JSON body as a dict.

    Raises:
        McpParseError: If the body is missing or not valid JSON.
    """
    raw_body = event.get("body")
    if raw_body is None:
        raise McpParseError("Request body is missing")

    if isinstance(raw_body, dict):
        return raw_body

    try:
        parsed = json.loads(raw_body)
    except (json.JSONDecodeError, TypeError) as exc:
        raise McpParseError(f"Request body is not valid JSON: {exc}") from exc

    if not isinstance(parsed, dict):
        raise McpParseError("Request body must be a JSON object")

    return parsed


def _invoke_cedar_evaluator(envelope: dict[str, Any]) -> dict[str, Any]:
    """Invoke the Cedar Evaluator Lambda synchronously.

    Args:
        envelope: The signed Request Envelope dict.

    Returns:
        The evaluation result dict from the Cedar Evaluator.

    Raises:
        _CedarEvaluatorInvocationError: If the invocation fails.
    """
    if not CEDAR_EVALUATOR_FUNCTION_NAME:
        raise _CedarEvaluatorInvocationError(
            "CEDAR_EVALUATOR_FUNCTION_NAME environment variable is not set"
        )

    client = _get_lambda_client()

    try:
        response = client.invoke(
            FunctionName=CEDAR_EVALUATOR_FUNCTION_NAME,
            InvocationType="RequestResponse",
            Payload=json.dumps(envelope).encode("utf-8"),
        )
    except Exception as exc:
        raise _CedarEvaluatorInvocationError(
            f"Failed to invoke Cedar Evaluator: {exc}"
        ) from exc

    # Check for Lambda-level errors
    if response.get("FunctionError"):
        error_payload = response["Payload"].read().decode("utf-8")
        raise _CedarEvaluatorInvocationError(
            f"Cedar Evaluator returned error: {error_payload}"
        )

    # Parse the response payload
    try:
        payload = json.loads(response["Payload"].read().decode("utf-8"))
    except (json.JSONDecodeError, KeyError) as exc:
        raise _CedarEvaluatorInvocationError(
            f"Invalid response from Cedar Evaluator: {exc}"
        ) from exc

    return payload


def _success_response(body: dict[str, Any]) -> dict[str, Any]:
    """Build an API Gateway success response."""
    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(body),
    }


def _error_response(status_code: int, body: dict[str, Any]) -> dict[str, Any]:
    """Build an API Gateway error response."""
    return {
        "statusCode": status_code,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(body),
    }
