# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Request Envelope builder for the MCP Protocol Adapter.

Accepts a ParsedMcpRequest and ContentFilterResult, signs the originating
user context, and constructs a validated RequestEnvelope dict ready for
JSON serialization and forwarding to the Cedar Evaluator Lambda.

Validates: Requirements 2.1, 2.2, 5.2
"""

from __future__ import annotations

import importlib
import uuid
from datetime import datetime, timezone
from typing import Any

import jsonschema

# ``lambda`` is a Python keyword — use importlib for intra-package imports.
_types_mod = importlib.import_module("shared.types")
_schema_mod = importlib.import_module("shared.envelope_schema")
_parser_mod = importlib.import_module("mcp_adapter.mcp_parser")
_signer_mod = importlib.import_module("mcp_adapter.context_signer")

RequestEnvelope = _types_mod.RequestEnvelope
SourceAgent = _types_mod.SourceAgent
Action = _types_mod.Action
DelegationHop = _types_mod.DelegationHop
OriginatingUserContext = _types_mod.OriginatingUserContext
ContentFilterResult = _types_mod.ContentFilterResult

ParsedMcpRequest = _parser_mod.ParsedMcpRequest
validate_envelope = _schema_mod.validate_envelope


class EnvelopeBuildError(Exception):
    """Raised when the envelope cannot be built or fails schema validation."""

    def __init__(self, message: str) -> None:
        self.message = message
        super().__init__(message)


def build_envelope(
    parsed: ParsedMcpRequest,
    content_filter_result: ContentFilterResult,
    signing_key: str | None = None,
    *,
    secrets_client: object | None = None,
) -> dict[str, Any]:
    """Build and validate a RequestEnvelope from a parsed MCP request.

    Args:
        parsed: The parsed MCP request from ``mcp_parser.parse_mcp_message``.
        content_filter_result: The Amazon Bedrock Guardrails content filter result.
        signing_key: An explicit HMAC signing key. If ``None``, the key is
            retrieved from AWS Secrets Manager via ``sign_user_context_with_secret``.
        secrets_client: Optional boto3 AWS Secrets Manager client (used only when
            ``signing_key`` is ``None``).

    Returns:
        A dict representation of the validated RequestEnvelope, ready for
        JSON serialization.

    Raises:
        EnvelopeBuildError: If the parsed request is missing required fields
            (agent identity or user context) or if the built envelope fails
            JSON schema validation.
    """
    if parsed.agent_identity is None:
        raise EnvelopeBuildError(
            "Cannot build envelope: parsed request has no agent identity"
        )

    if parsed.user_context is None:
        raise EnvelopeBuildError(
            "Cannot build envelope: parsed request has no user context"
        )

    # Generate unique request ID and UTC timestamp
    request_id = str(uuid.uuid4())
    timestamp = datetime.now(timezone.utc).isoformat()

    # Sign the originating user context
    signature = _sign_user_context(parsed.user_context, signing_key, secrets_client)

    # Build sub-models
    source_agent = _build_source_agent(parsed)
    action = _build_action(parsed)
    delegation_chain = _build_delegation_chain(parsed)
    originating_user = _build_originating_user(parsed.user_context, signature)

    # Construct the Pydantic RequestEnvelope model
    envelope = RequestEnvelope(
        request_id=request_id,
        timestamp=timestamp,
        source_protocol="MCP",
        source_agent=source_agent,
        action=action,
        delegation_chain=delegation_chain,
        delegation_depth=parsed.delegation_depth,
        originating_user=originating_user,
        content_filter_result=content_filter_result,
    )

    # Serialize to dict and validate against JSON schema
    envelope_dict = envelope.model_dump()
    try:
        validate_envelope(envelope_dict)
    except jsonschema.ValidationError as exc:
        raise EnvelopeBuildError(
            f"Envelope failed JSON schema validation: {exc.message}"
        ) from exc

    return envelope_dict


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _sign_user_context(
    user_context: _parser_mod.UserContext,
    signing_key: str | None,
    secrets_client: object | None,
) -> str:
    """Sign the user context using HMAC-SHA256."""
    if signing_key is not None:
        return _signer_mod.sign_user_context(user_context, signing_key)
    return _signer_mod.sign_user_context_with_secret(
        user_context, client=secrets_client
    )


def _build_source_agent(parsed: ParsedMcpRequest) -> SourceAgent:
    """Build a SourceAgent from the parsed agent identity."""
    ai = parsed.agent_identity
    return SourceAgent(
        agent_id=ai.agent_id,
        trust_level=ai.trust_level,
        namespace=ai.namespace,
        registered_capabilities=list(ai.registered_capabilities),
        lifecycle_stage=ai.lifecycle_stage or "production",
    )


def _build_action(parsed: ParsedMcpRequest) -> Action:
    """Derive the Action from the parsed MCP request.

    The action type is ``invoke_tool`` (since MCP messages are tool calls).
    The target resource is ``AgentAuthz::Tool::<tool_name>``.
    Requested capabilities come from the agent identity if available.
    """
    requested_caps: list[str] = []
    if parsed.agent_identity and parsed.agent_identity.registered_capabilities:
        requested_caps = list(parsed.agent_identity.registered_capabilities)

    return Action(
        type="invoke_tool",
        target_resource=f"AgentAuthz::Tool::{parsed.tool_name}",
        requested_capabilities=requested_caps,
    )


def _build_delegation_chain(parsed: ParsedMcpRequest) -> list[DelegationHop]:
    """Convert parser DelegationHop dataclasses to Pydantic DelegationHop models."""
    hops: list[DelegationHop] = []
    for hop in parsed.delegation_chain:
        hops.append(
            DelegationHop(
                hop=hop.hop,
                agent_id=hop.agent_id,
                capabilities_granted=list(hop.capabilities_granted),
                timestamp=hop.timestamp or datetime.now(timezone.utc).isoformat(),
            )
        )
    return hops


def _build_originating_user(
    uc: _parser_mod.UserContext, signature: str
) -> OriginatingUserContext:
    """Build the OriginatingUserContext Pydantic model with the HMAC signature."""
    return OriginatingUserContext(
        user_id=uc.user_id,
        role=uc.role,
        mfa_verified=uc.mfa_verified,
        authentication_method=uc.authentication_method,
        session_id=uc.session_id,
        signature=signature,
    )
