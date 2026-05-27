# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Unit tests for shared types and envelope schema validation.

Validates: Requirements 3.1, 7.1
"""

import importlib
import uuid

import pytest
from jsonschema import ValidationError as JsonSchemaValidationError
from pydantic import ValidationError as PydanticValidationError

# ``lambda`` is a Python keyword, so we use importlib to import from it.
_envelope_mod = importlib.import_module("shared.envelope_schema")
_types_mod = importlib.import_module("shared.types")

validate_envelope = _envelope_mod.validate_envelope
OriginatingUserContext = _types_mod.OriginatingUserContext


# ---------------------------------------------------------------------------
# Helpers — build a valid envelope dict for JSON schema tests
# ---------------------------------------------------------------------------


def _valid_envelope() -> dict:
    """Return a minimal valid request envelope dictionary."""
    return {
        "request_id": str(uuid.uuid4()),
        "timestamp": "2026-04-13T12:00:00.000Z",
        "source_protocol": "MCP",
        "source_agent": {
            "agent_id": "finance-agent",
            "trust_level": 3,
            "namespace": "payments",
            "registered_capabilities": ["process_payment"],
            "lifecycle_stage": "production",
        },
        "action": {
            "type": "invoke_tool",
            "target_resource": "Tool::process_payment",
            "requested_capabilities": ["process_payment"],
        },
        "delegation_chain": [],
        "delegation_depth": 0,
        "originating_user": {
            "user_id": "user-12345",
            "role": "admin",
            "mfa_verified": True,
            "authentication_method": "cognito",
            "session_id": "session-abc",
            "signature": "abcdef0123456789",
        },
        "content_filter_result": {
            "injection_score": 0,
            "filter_applied": True,
            "filter_source": "bedrock-guardrails",
        },
    }


# ===================================================================
# RequestEnvelope JSON schema validation tests
# ===================================================================


class TestRequestEnvelopeJsonSchema:
    """Tests for the JSON schema defined in envelope_schema.py."""

    def test_valid_envelope_passes(self):
        """A fully populated, valid envelope passes schema validation."""
        envelope = _valid_envelope()
        validate_envelope(envelope)

    def test_missing_request_id_rejected(self):
        """Omitting the required 'request_id' field raises ValidationError."""
        envelope = _valid_envelope()
        del envelope["request_id"]
        with pytest.raises(JsonSchemaValidationError):
            validate_envelope(envelope)

    def test_missing_timestamp_rejected(self):
        """Omitting the required 'timestamp' field raises ValidationError."""
        envelope = _valid_envelope()
        del envelope["timestamp"]
        with pytest.raises(JsonSchemaValidationError):
            validate_envelope(envelope)

    def test_missing_source_agent_rejected(self):
        """Omitting the required 'source_agent' field raises ValidationError."""
        envelope = _valid_envelope()
        del envelope["source_agent"]
        with pytest.raises(JsonSchemaValidationError):
            validate_envelope(envelope)

    def test_missing_originating_user_rejected(self):
        """Omitting 'originating_user' raises ValidationError."""
        envelope = _valid_envelope()
        del envelope["originating_user"]
        with pytest.raises(JsonSchemaValidationError):
            validate_envelope(envelope)

    def test_invalid_uuid_format_rejected(self):
        """A request_id that is not a valid UUID v4 raises ValidationError."""
        envelope = _valid_envelope()
        envelope["request_id"] = "not-a-uuid"
        with pytest.raises(JsonSchemaValidationError):
            validate_envelope(envelope)

    def test_uuid_v1_format_rejected(self):
        """A UUID v1 string does not match the UUID v4 pattern and is rejected."""
        envelope = _valid_envelope()
        envelope["request_id"] = "6ba7b810-9dad-11d1-80b4-00c04fd430c8"
        with pytest.raises(JsonSchemaValidationError):
            validate_envelope(envelope)

    def test_invalid_action_type_rejected(self):
        """An action type not in the allowed enum raises ValidationError."""
        envelope = _valid_envelope()
        envelope["action"]["type"] = "unknown_action"
        with pytest.raises(JsonSchemaValidationError):
            validate_envelope(envelope)

    def test_additional_top_level_properties_rejected(self):
        """Extra top-level properties are rejected (additionalProperties: false)."""
        envelope = _valid_envelope()
        envelope["extra_field"] = "should not be here"
        with pytest.raises(JsonSchemaValidationError):
            validate_envelope(envelope)


# ===================================================================
# OriginatingUserContext Pydantic model tests
# ===================================================================


class TestOriginatingUserContext:
    """Tests for the OriginatingUserContext Pydantic model."""

    def _valid_user_kwargs(self) -> dict:
        return {
            "user_id": "user-12345",
            "role": "admin",
            "mfa_verified": True,
            "authentication_method": "cognito",
            "session_id": "session-abc",
            "signature": "abcdef0123456789",
        }

    def test_valid_context_created(self):
        """All required fields provided with valid hex signature succeeds."""
        ctx = OriginatingUserContext(**self._valid_user_kwargs())
        assert ctx.user_id == "user-12345"
        assert ctx.role == "admin"
        assert ctx.mfa_verified is True
        assert ctx.authentication_method == "cognito"
        assert ctx.session_id == "session-abc"
        assert ctx.signature == "abcdef0123456789"

    @pytest.mark.parametrize("missing_field", [
        "user_id",
        "role",
        "mfa_verified",
        "authentication_method",
        "session_id",
    ])
    def test_missing_required_field_rejected(self, missing_field: str):
        """Each of the five identity fields is required."""
        kwargs = self._valid_user_kwargs()
        del kwargs[missing_field]
        with pytest.raises(PydanticValidationError):
            OriginatingUserContext(**kwargs)

    def test_missing_signature_rejected(self):
        """The signature field is also required."""
        kwargs = self._valid_user_kwargs()
        del kwargs["signature"]
        with pytest.raises(PydanticValidationError):
            OriginatingUserContext(**kwargs)

    def test_valid_hex_signature_accepted(self):
        """A valid hex string signature is accepted."""
        kwargs = self._valid_user_kwargs()
        kwargs["signature"] = "0123456789abcdefABCDEF"
        ctx = OriginatingUserContext(**kwargs)
        assert ctx.signature == "0123456789abcdefABCDEF"

    def test_invalid_hex_signature_rejected(self):
        """A non-hex signature raises ValidationError."""
        kwargs = self._valid_user_kwargs()
        kwargs["signature"] = "not-a-hex-string!"
        with pytest.raises(PydanticValidationError, match="hex"):
            OriginatingUserContext(**kwargs)

    def test_empty_hex_signature_rejected(self):
        """An empty string is not a valid hex signature."""
        kwargs = self._valid_user_kwargs()
        kwargs["signature"] = ""
        with pytest.raises(PydanticValidationError):
            OriginatingUserContext(**kwargs)
