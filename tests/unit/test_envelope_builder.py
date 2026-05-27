# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Unit tests for the Request Envelope builder.

Tests cover:
- All envelope fields populated correctly from ParsedMcpRequest
- UUID v4 request_id generation
- ISO 8601 UTC timestamp generation
- HMAC-SHA256 signing of user context (explicit key and AWS Secrets Manager)
- JSON schema validation passes for valid envelopes
- Missing agent identity raises EnvelopeBuildError
- Missing user context raises EnvelopeBuildError
- Delegation chain conversion

Validates: Requirements 2.1, 2.2, 5.2
"""

from __future__ import annotations

import importlib
import re
import uuid
from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest

_builder = importlib.import_module("mcp_adapter.envelope_builder")
_parser = importlib.import_module("mcp_adapter.mcp_parser")
_signer = importlib.import_module("mcp_adapter.context_signer")
_types = importlib.import_module("shared.types")

build_envelope = _builder.build_envelope
EnvelopeBuildError = _builder.EnvelopeBuildError
ParsedMcpRequest = _parser.ParsedMcpRequest
AgentIdentity = _parser.AgentIdentity
UserContext = _parser.UserContext
DelegationHop = _parser.DelegationHop
ContentFilterResult = _types.ContentFilterResult
sign_user_context = _signer.sign_user_context

# nosec: Test-only constant used exclusively in unit tests, never in production.
SIGNING_KEY = "test-signing-key-for-envelope"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_agent_identity(**overrides) -> AgentIdentity:
    defaults = dict(
        agent_id="finance-agent",
        trust_level=3,
        namespace="payments",
        registered_capabilities=["process_payment"],
        lifecycle_stage="production",
    )
    defaults.update(overrides)
    return AgentIdentity(**defaults)


def _make_user_context(**overrides) -> UserContext:
    defaults = dict(
        user_id="user-123",
        role="admin",
        mfa_verified=True,
        authentication_method="cognito",
        session_id="sess-abc",
    )
    defaults.update(overrides)
    return UserContext(**defaults)


def _make_delegation_hop(**overrides) -> DelegationHop:
    defaults = dict(
        hop=0,
        agent_id="orchestrator",
        capabilities_granted=["process_payment"],
        timestamp="2026-04-13T12:00:00+00:00",
    )
    defaults.update(overrides)
    return DelegationHop(**defaults)


def _make_content_filter(**overrides) -> ContentFilterResult:
    defaults = dict(
        injection_score=0,
        filter_applied=False,
        filter_source="bedrock-guardrails",
    )
    defaults.update(overrides)
    return ContentFilterResult(**defaults)


def _make_parsed_request(**overrides) -> ParsedMcpRequest:
    defaults = dict(
        jsonrpc="2.0",
        request_id=1,
        method="tools/call",
        tool_name="process_payment",
        arguments={"amount": 100},
        agent_identity=_make_agent_identity(),
        user_context=_make_user_context(),
        delegation_chain=[_make_delegation_hop()],
        delegation_depth=1,
        raw_meta={},
    )
    defaults.update(overrides)
    return ParsedMcpRequest(**defaults)


UUID4_PATTERN = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)


# ---------------------------------------------------------------------------
# Tests: build_envelope — happy path
# ---------------------------------------------------------------------------


class TestBuildEnvelopeHappyPath:
    def test_returns_dict(self):
        result = build_envelope(
            _make_parsed_request(), _make_content_filter(), signing_key=SIGNING_KEY
        )
        assert isinstance(result, dict)

    def test_request_id_is_uuid4(self):
        result = build_envelope(
            _make_parsed_request(), _make_content_filter(), signing_key=SIGNING_KEY
        )
        assert UUID4_PATTERN.match(result["request_id"])

    def test_timestamp_is_iso8601_utc(self):
        result = build_envelope(
            _make_parsed_request(), _make_content_filter(), signing_key=SIGNING_KEY
        )
        ts = result["timestamp"]
        # Should parse as a valid datetime
        parsed_ts = datetime.fromisoformat(ts)
        assert parsed_ts.tzinfo is not None

    def test_source_protocol_is_mcp(self):
        result = build_envelope(
            _make_parsed_request(), _make_content_filter(), signing_key=SIGNING_KEY
        )
        assert result["source_protocol"] == "MCP"

    def test_source_agent_fields(self):
        result = build_envelope(
            _make_parsed_request(), _make_content_filter(), signing_key=SIGNING_KEY
        )
        sa = result["source_agent"]
        assert sa["agent_id"] == "finance-agent"
        assert sa["trust_level"] == 3
        assert sa["namespace"] == "payments"
        assert sa["registered_capabilities"] == ["process_payment"]
        assert sa["lifecycle_stage"] == "production"

    def test_action_fields(self):
        result = build_envelope(
            _make_parsed_request(), _make_content_filter(), signing_key=SIGNING_KEY
        )
        action = result["action"]
        assert action["type"] == "invoke_tool"
        assert action["target_resource"] == "AgentAuthz::Tool::process_payment"

    def test_delegation_chain_populated(self):
        result = build_envelope(
            _make_parsed_request(), _make_content_filter(), signing_key=SIGNING_KEY
        )
        chain = result["delegation_chain"]
        assert len(chain) == 1
        assert chain[0]["agent_id"] == "orchestrator"
        assert chain[0]["hop"] == 0

    def test_delegation_depth(self):
        result = build_envelope(
            _make_parsed_request(), _make_content_filter(), signing_key=SIGNING_KEY
        )
        assert result["delegation_depth"] == 1

    def test_originating_user_fields(self):
        result = build_envelope(
            _make_parsed_request(), _make_content_filter(), signing_key=SIGNING_KEY
        )
        user = result["originating_user"]
        assert user["user_id"] == "user-123"
        assert user["role"] == "admin"
        assert user["mfa_verified"] is True
        assert user["authentication_method"] == "cognito"
        assert user["session_id"] == "sess-abc"

    def test_originating_user_signature_is_valid_hmac(self):
        parsed = _make_parsed_request()
        result = build_envelope(parsed, _make_content_filter(), signing_key=SIGNING_KEY)
        sig = result["originating_user"]["signature"]
        # Should be a 64-char hex string
        assert len(sig) == 64
        int(sig, 16)
        # Should match what sign_user_context produces
        expected = sign_user_context(parsed.user_context, SIGNING_KEY)
        assert sig == expected

    def test_content_filter_result_fields(self):
        cfr = _make_content_filter(injection_score=42, filter_applied=True)
        result = build_envelope(
            _make_parsed_request(), cfr, signing_key=SIGNING_KEY
        )
        cf = result["content_filter_result"]
        assert cf["injection_score"] == 42
        assert cf["filter_applied"] is True
        assert cf["filter_source"] == "bedrock-guardrails"

    def test_unique_request_ids(self):
        """Two calls should produce different request_ids."""
        r1 = build_envelope(
            _make_parsed_request(), _make_content_filter(), signing_key=SIGNING_KEY
        )
        r2 = build_envelope(
            _make_parsed_request(), _make_content_filter(), signing_key=SIGNING_KEY
        )
        assert r1["request_id"] != r2["request_id"]


# ---------------------------------------------------------------------------
# Tests: build_envelope — error cases
# ---------------------------------------------------------------------------


class TestBuildEnvelopeErrors:
    def test_missing_agent_identity_raises(self):
        parsed = _make_parsed_request(agent_identity=None)
        with pytest.raises(EnvelopeBuildError, match="no agent identity"):
            build_envelope(parsed, _make_content_filter(), signing_key=SIGNING_KEY)

    def test_missing_user_context_raises(self):
        parsed = _make_parsed_request(user_context=None)
        with pytest.raises(EnvelopeBuildError, match="no user context"):
            build_envelope(parsed, _make_content_filter(), signing_key=SIGNING_KEY)


# ---------------------------------------------------------------------------
# Tests: build_envelope — empty delegation chain
# ---------------------------------------------------------------------------


class TestBuildEnvelopeEmptyDelegation:
    def test_empty_delegation_chain(self):
        parsed = _make_parsed_request(delegation_chain=[], delegation_depth=0)
        result = build_envelope(parsed, _make_content_filter(), signing_key=SIGNING_KEY)
        assert result["delegation_chain"] == []
        assert result["delegation_depth"] == 0


# ---------------------------------------------------------------------------
# Tests: build_envelope — AWS Secrets Manager signing path
# ---------------------------------------------------------------------------


class TestBuildEnvelopeSecretsManager:
    def test_uses_secrets_manager_when_no_explicit_key(self):
        sm_client = MagicMock()
        sm_client.get_secret_value.return_value = {"SecretString": "sm-key"}
        # Invalidate cache so it fetches fresh
        _signer._invalidate_key_cache()

        parsed = _make_parsed_request()
        result = build_envelope(
            parsed, _make_content_filter(), secrets_client=sm_client
        )
        expected_sig = sign_user_context(parsed.user_context, "sm-key")
        assert result["originating_user"]["signature"] == expected_sig
        sm_client.get_secret_value.assert_called_once()

        # Clean up cache
        _signer._invalidate_key_cache()
