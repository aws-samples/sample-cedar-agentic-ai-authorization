# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Property 9: MCP parsing produces valid envelope.

For any valid MCP tool call message, the Protocol Adapter's parsing logic
SHALL produce a Request Envelope that passes JSON schema validation and
contains the correct tool name, parameters, and security metadata from the
original MCP message.

**Validates: Requirements 5.2**

Feature: agent-authz-protection
Property 9: MCP parsing produces valid envelope
"""

from __future__ import annotations

import importlib

from hypothesis import given, settings
from hypothesis import strategies as st

_parser_mod = importlib.import_module("mcp_adapter.mcp_parser")
_builder_mod = importlib.import_module("mcp_adapter.envelope_builder")
_schema_mod = importlib.import_module("shared.envelope_schema")
_types_mod = importlib.import_module("shared.types")

parse_mcp_message = _parser_mod.parse_mcp_message
build_envelope = _builder_mod.build_envelope
validate_envelope = _schema_mod.validate_envelope
ContentFilterResult = _types_mod.ContentFilterResult

# nosec: Test-only constant for deterministic property testing, never used in production.
_SIGNING_KEY = "property-test-signing-key-9"

# ---------------------------------------------------------------------------
# Hypothesis strategies
# ---------------------------------------------------------------------------

# Non-empty printable text without control characters
_nonempty_text = st.text(
    alphabet=st.characters(whitelist_categories=("L", "N", "P", "S", "Z")),
    min_size=1,
    max_size=40,
).filter(lambda s: s.strip())

# Tool names: simple identifiers
_tool_names = st.from_regex(r"[a-z][a-z0-9_]{0,29}", fullmatch=True)

# Agent IDs: realistic identifiers
_agent_ids = st.from_regex(r"[a-z][a-z0-9\-]{0,29}", fullmatch=True)

# Namespaces
_namespaces = st.sampled_from(["payments", "data", "support", "analytics", "infra"])

# Trust levels (1-5 per schema)
_trust_levels = st.integers(min_value=1, max_value=5)

# Lifecycle stages
_lifecycle_stages = st.sampled_from(["production", "staging", "development", "canary"])

# Capabilities
_capabilities = st.lists(
    st.from_regex(r"[a-z_]{2,15}", fullmatch=True),
    min_size=0,
    max_size=3,
)

# Delegation depth (non-negative)
_delegation_depths = st.integers(min_value=0, max_value=10)

# Roles for user context
_roles = st.sampled_from(["admin", "analyst", "support", "finance_manager", "support_lead", "data_engineer"])

# Authentication methods
_auth_methods = st.sampled_from(["sso", "oauth2", "saml", "api_key", "cognito"])

# Session IDs
_session_ids = st.from_regex(r"session-[a-z0-9]{4,12}", fullmatch=True)


def _build_mcp_message(
    tool_name: str,
    agent_id: str,
    trust_level: int,
    namespace: str,
    lifecycle_stage: str,
    capabilities: list[str],
    user_id: str,
    role: str,
    mfa_verified: bool,
    auth_method: str,
    session_id: str,
    delegation_depth: int,
) -> dict:
    """Build a valid MCP tool call message with all required metadata."""
    return {
        "jsonrpc": "2.0",
        "method": "tools/call",
        "id": "prop9-req",
        "params": {
            "name": tool_name,
            "arguments": {},
            "_meta": {
                "agent_id": agent_id,
                "trust_level": trust_level,
                "namespace": namespace,
                "lifecycle_stage": lifecycle_stage,
                "registered_capabilities": capabilities,
                "delegation_depth": delegation_depth,
                "user_context": {
                    "user_id": user_id,
                    "role": role,
                    "mfa_verified": mfa_verified,
                    "authentication_method": auth_method,
                    "session_id": session_id,
                },
            },
        },
    }


@settings(max_examples=100)
@given(
    tool_name=_tool_names,
    agent_id=_agent_ids,
    trust_level=_trust_levels,
    namespace=_namespaces,
    lifecycle_stage=_lifecycle_stages,
    capabilities=_capabilities,
    user_id=_nonempty_text,
    role=_roles,
    mfa_verified=st.booleans(),
    auth_method=_auth_methods,
    session_id=_session_ids,
    delegation_depth=_delegation_depths,
)
def test_mcp_parsing_produces_valid_envelope(
    tool_name: str,
    agent_id: str,
    trust_level: int,
    namespace: str,
    lifecycle_stage: str,
    capabilities: list[str],
    user_id: str,
    role: str,
    mfa_verified: bool,
    auth_method: str,
    session_id: str,
    delegation_depth: int,
) -> None:
    """Property 9 — MCP parsing produces valid envelope.

    **Validates: Requirements 5.2**
    """
    # 1. Build a random valid MCP message
    msg = _build_mcp_message(
        tool_name=tool_name,
        agent_id=agent_id,
        trust_level=trust_level,
        namespace=namespace,
        lifecycle_stage=lifecycle_stage,
        capabilities=capabilities,
        user_id=user_id,
        role=role,
        mfa_verified=mfa_verified,
        auth_method=auth_method,
        session_id=session_id,
        delegation_depth=delegation_depth,
    )

    # 2. Parse the MCP message
    parsed = parse_mcp_message(msg)

    # 3. Build envelope with a fixed signing key and content filter result
    content_filter = ContentFilterResult(
        injection_score=0,
        filter_applied=True,
        filter_source="bedrock-guardrails",
    )
    envelope = build_envelope(parsed, content_filter, signing_key=_SIGNING_KEY)

    # 4. Validate envelope against JSON schema — raises on failure
    validate_envelope(envelope)

    # 5. Assert correct tool name preserved
    assert envelope["action"]["target_resource"] == f"AgentAuthz::Tool::{tool_name}"

    # 6. Assert correct agent identity preserved
    assert envelope["source_agent"]["agent_id"] == agent_id
    assert envelope["source_agent"]["trust_level"] == trust_level
    assert envelope["source_agent"]["namespace"] == namespace
    assert envelope["source_agent"]["lifecycle_stage"] == lifecycle_stage

    # 7. Assert originating user fields preserved
    assert envelope["originating_user"]["user_id"] == user_id
    assert envelope["originating_user"]["role"] == role
    assert envelope["originating_user"]["mfa_verified"] is mfa_verified
    assert envelope["originating_user"]["authentication_method"] == auth_method
    assert envelope["originating_user"]["session_id"] == session_id

    # 8. Assert delegation depth preserved
    assert envelope["delegation_depth"] == delegation_depth

    # 9. Assert source protocol is MCP
    assert envelope["source_protocol"] == "MCP"
