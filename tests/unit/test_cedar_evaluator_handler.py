# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Unit tests for Cedar Evaluator Lambda handler.

Tests the handler entry point: envelope validation, signature
verification, Cedar evaluation, audit emission, and error handling.
"""

from __future__ import annotations

import hashlib
import hmac
import importlib
import json
import uuid
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

_handler_mod = importlib.import_module("cedar_evaluator.handler")
_types_mod = importlib.import_module("shared.types")
_sig_mod = importlib.import_module("cedar_evaluator.signature_verifier")

handler = _handler_mod.handler
Decision = _types_mod.Decision
AuthzDecision = _types_mod.AuthzDecision
LayerResult = _types_mod.LayerResult
LayerResults = _types_mod.LayerResults
SignatureVerificationError = _sig_mod.SignatureVerificationError

SIGNING_KEY = "test-signing-key-abc123"


def _sign(user_id, role, mfa, auth_method, session_id):
    """Compute HMAC-SHA256 signature matching the canonical format."""
    canonical = f"{user_id}|{role}|{mfa}|{auth_method}|{session_id}"
    return hmac.new(
        SIGNING_KEY.encode(), canonical.encode(), hashlib.sha256
    ).hexdigest()


def _make_valid_envelope(**overrides) -> dict:
    """Build a minimal valid Request Envelope dict."""
    user_id = "user-123"
    role = "admin"
    mfa = True
    auth_method = "sso"
    session_id = "sess-abc"
    sig = _sign(user_id, role, mfa, auth_method, session_id)

    envelope = {
        "request_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
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
            "target_resource": "process_payment",
            "requested_capabilities": ["process_payment"],
        },
        "delegation_chain": [],
        "delegation_depth": 0,
        "originating_user": {
            "user_id": user_id,
            "role": role,
            "mfa_verified": mfa,
            "authentication_method": auth_method,
            "session_id": session_id,
            "signature": sig,
        },
        "content_filter_result": {
            "injection_score": 0,
            "filter_applied": True,
            "filter_source": "bedrock-guardrails",
        },
    }
    envelope.update(overrides)
    return envelope


def _permit_decision() -> AuthzDecision:
    """Build a PERMIT AuthzDecision."""
    lr = LayerResult(decision=Decision.PERMIT, evaluation_details=None)
    return AuthzDecision(
        decision=Decision.PERMIT,
        denying_layer=None,
        layer_results=LayerResults(L1=lr, L2=lr, L3=lr),
    )


def _deny_decision(layer: str = "L1") -> AuthzDecision:
    """Build a DENY AuthzDecision."""
    deny = LayerResult(decision=Decision.DENY, evaluation_details="denied")
    permit = LayerResult(decision=Decision.PERMIT, evaluation_details=None)
    not_eval = LayerResult(decision=Decision.DENY, evaluation_details="Not evaluated")
    results = {"L1": permit, "L2": permit, "L3": permit}
    results[layer] = deny
    for l in ["L1", "L2", "L3"]:
        if l > layer:
            results[l] = not_eval
    return AuthzDecision(
        decision=Decision.DENY,
        denying_layer=layer,
        layer_results=LayerResults(**results),
    )


# ── Invalid envelope → DENY ────────────────────────────────────────


class TestInvalidEnvelope:
    def test_missing_required_fields_returns_deny(self) -> None:
        with patch.object(_handler_mod, "emit_audit_event"):
            result = handler({}, None)
        assert result["decision"] == "DENY"
        assert result["denying_layer"] == "pre-evaluation"
        lr = result["layer_results"]["L1"]
        assert "invalid_envelope" in lr["evaluation_details"]

    def test_invalid_request_id_format_returns_deny(self) -> None:
        envelope = _make_valid_envelope(request_id="not-a-uuid")
        with patch.object(_handler_mod, "emit_audit_event"):
            result = handler(envelope, None)
        assert result["decision"] == "DENY"

    def test_audit_emitted_on_invalid_envelope(self) -> None:
        with patch.object(_handler_mod, "emit_audit_event") as mock_audit:
            handler({}, None)
        mock_audit.assert_called_once()


# ── Signature verification failure → DENY ──────────────────────────


class TestSignatureVerificationFailure:
    def test_tampered_signature_returns_deny(self) -> None:
        envelope = _make_valid_envelope()
        envelope["originating_user"]["signature"] = "deadbeef" * 8
        with patch.object(
            _handler_mod, "verify_user_context",
            side_effect=SignatureVerificationError("tampered"),
        ), patch.object(_handler_mod, "emit_audit_event"):
            result = handler(envelope, None)
        assert result["decision"] == "DENY"
        lr = result["layer_results"]["L1"]
        assert "signature_verification_failed" in lr["evaluation_details"]

    def test_unexpected_sig_error_returns_deny(self) -> None:
        envelope = _make_valid_envelope()
        with patch.object(
            _handler_mod, "verify_user_context",
            side_effect=RuntimeError("unexpected"),
        ), patch.object(_handler_mod, "emit_audit_event"):
            result = handler(envelope, None)
        assert result["decision"] == "DENY"
        assert "signature_verification_failed" in (
            result["layer_results"]["L1"]["evaluation_details"]
        )


# ── Cedar evaluation error → DENY (fail-closed) ───────────────────


class TestCedarEvaluationError:
    def test_evaluation_exception_returns_deny(self) -> None:
        envelope = _make_valid_envelope()
        with patch.object(
            _handler_mod, "verify_user_context", return_value=True,
        ), patch.object(
            _handler_mod, "evaluate",
            side_effect=RuntimeError("cedarpy crash"),
        ), patch.object(_handler_mod, "emit_audit_event"):
            result = handler(envelope, None)
        assert result["decision"] == "DENY"
        lr = result["layer_results"]["L1"]
        assert "cedar_evaluation_error" in lr["evaluation_details"]


# ── Audit emission failure → non-blocking ──────────────────────────


class TestAuditEmissionFailure:
    def test_audit_failure_does_not_block_decision(self) -> None:
        envelope = _make_valid_envelope()
        with patch.object(
            _handler_mod, "verify_user_context", return_value=True,
        ), patch.object(
            _handler_mod, "evaluate", return_value=_permit_decision(),
        ), patch.object(
            _handler_mod, "emit_audit_event",
            side_effect=RuntimeError("CloudWatch down"),
        ):
            result = handler(envelope, None)
        # Decision should still be returned despite audit failure
        assert result["decision"] == "PERMIT"


# ── Happy path ──────────────────────────────────────────────────────


class TestHappyPath:
    def test_permit_decision_returned(self) -> None:
        envelope = _make_valid_envelope()
        with patch.object(
            _handler_mod, "verify_user_context", return_value=True,
        ), patch.object(
            _handler_mod, "evaluate", return_value=_permit_decision(),
        ), patch.object(_handler_mod, "emit_audit_event"):
            result = handler(envelope, None)
        assert result["decision"] == "PERMIT"
        assert result["denying_layer"] is None
        assert result["layer_results"]["L1"]["decision"] == "PERMIT"
        assert result["layer_results"]["L2"]["decision"] == "PERMIT"
        assert result["layer_results"]["L3"]["decision"] == "PERMIT"

    def test_deny_decision_includes_denying_layer(self) -> None:
        envelope = _make_valid_envelope()
        with patch.object(
            _handler_mod, "verify_user_context", return_value=True,
        ), patch.object(
            _handler_mod, "evaluate", return_value=_deny_decision("L3"),
        ), patch.object(_handler_mod, "emit_audit_event"):
            result = handler(envelope, None)
        assert result["decision"] == "DENY"
        assert result["denying_layer"] == "L3"

    def test_audit_emitted_on_success(self) -> None:
        envelope = _make_valid_envelope()
        with patch.object(
            _handler_mod, "verify_user_context", return_value=True,
        ), patch.object(
            _handler_mod, "evaluate", return_value=_permit_decision(),
        ), patch.object(_handler_mod, "emit_audit_event") as mock_audit:
            handler(envelope, None)
        mock_audit.assert_called_once()
        # Verify latency_ms argument is a positive float
        _, _, latency_ms = mock_audit.call_args[0]
        assert isinstance(latency_ms, float)
        assert latency_ms >= 0


# ── _decision_to_dict serialisation ─────────────────────────────────


class TestDecisionToDict:
    def test_permit_serialisation(self) -> None:
        d = _handler_mod._decision_to_dict(_permit_decision())
        assert d["decision"] == "PERMIT"
        assert d["denying_layer"] is None
        assert d["layer_results"]["L1"]["decision"] == "PERMIT"

    def test_deny_serialisation(self) -> None:
        d = _handler_mod._decision_to_dict(_deny_decision("L2"))
        assert d["decision"] == "DENY"
        assert d["denying_layer"] == "L2"
        assert d["layer_results"]["L2"]["decision"] == "DENY"
