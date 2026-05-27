# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Integration tests for MCP Adapter → Cedar Evaluator pipeline.

Wires together the full pipeline: MCP parser → guardrails → envelope builder
→ signature verification → policy evaluation → audit emission.

Mocks external AWS services (AWS Secrets Manager, Amazon Bedrock Guardrails, Lambda invoke)
using unittest.mock. Uses the real Cedar policy evaluation engine (cedarpy)
with actual policy files.

Validates: Requirements 1.4, 2.4, 5.2
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

# Import modules via importlib (``lambda`` is a Python keyword)
_parser_mod = importlib.import_module("mcp_adapter.mcp_parser")
_envelope_mod = importlib.import_module("mcp_adapter.envelope_builder")
_signer_mod = importlib.import_module("mcp_adapter.context_signer")
_guardrails_mod = importlib.import_module("mcp_adapter.guardrails_client")
_sig_verifier_mod = importlib.import_module("cedar_evaluator.signature_verifier")
_evaluator_mod = importlib.import_module("cedar_evaluator.policy_evaluator")
_audit_mod = importlib.import_module("cedar_evaluator.audit_emitter")
_ocsf_mod = importlib.import_module("shared.ocsf_event_builder")
_types_mod = importlib.import_module("shared.types")

parse_mcp_message = _parser_mod.parse_mcp_message
build_envelope = _envelope_mod.build_envelope
sign_user_context = _signer_mod.sign_user_context
verify_signature = _sig_verifier_mod.verify_signature
evaluate = _evaluator_mod.evaluate
reset_cache = _evaluator_mod.reset_cache
build_ocsf_event = _ocsf_mod.build_ocsf_event
ContentFilterResult = _types_mod.ContentFilterResult
Decision = _types_mod.Decision

# nosec: Test-only constant used exclusively in integration tests, never in production.
SIGNING_KEY = "integration-test-signing-key-2024"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_mcp_request(
    tool_name: str = "delete_records",
    agent_id: str = "data-bot",
    trust_level: int = 4,
    namespace: str = "data",
    lifecycle_stage: str = "production",
    user_id: str = "user-admin-001",
    user_role: str = "admin",
    mfa_verified: bool = True,
    auth_method: str = "sso",
    session_id: str = "sess-int-001",
    delegation_depth: int = 1,
    delegation_chain: list | None = None,
    registered_capabilities: list | None = None,
) -> dict:
    """Build a valid MCP JSON-RPC 2.0 tool call message."""
    if delegation_chain is None:
        delegation_chain = [
            {
                "hop": 0,
                "agent_id": "orchestrator",
                "capabilities_granted": registered_capabilities or [tool_name],
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        ]
    if registered_capabilities is None:
        registered_capabilities = [tool_name]

    return {
        "jsonrpc": "2.0",
        "id": str(uuid.uuid4()),
        "method": "tools/call",
        "params": {
            "name": tool_name,
            "arguments": {"record_id": "rec-123"},
            "_meta": {
                "agent_id": agent_id,
                "trust_level": trust_level,
                "namespace": namespace,
                "lifecycle_stage": lifecycle_stage,
                "registered_capabilities": registered_capabilities,
                "user_context": {
                    "user_id": user_id,
                    "role": user_role,
                    "mfa_verified": mfa_verified,
                    "authentication_method": auth_method,
                    "session_id": session_id,
                },
                "delegation_chain": delegation_chain,
                "delegation_depth": delegation_depth,
            },
        },
    }


def _mock_content_filter_result() -> ContentFilterResult:
    """Return a clean content filter result (no injection detected)."""
    return ContentFilterResult(
        injection_score=0,
        filter_applied=True,
        filter_source="bedrock-guardrails",
    )


def _run_full_pipeline(mcp_request: dict) -> dict:
    """Execute the full pipeline: parse → build envelope → verify → evaluate.

    Returns a dict with 'envelope', 'decision', and 'ocsf_event'.
    """
    # Step 1: Parse MCP message
    parsed = parse_mcp_message(mcp_request)

    # Step 2: Build signed envelope (mock guardrails, use real signer)
    content_filter = _mock_content_filter_result()
    envelope = build_envelope(parsed, content_filter, signing_key=SIGNING_KEY)

    # Step 3: Verify signature (real verification)
    ou = envelope["originating_user"]

    class _UserCtx:
        def __init__(self, d):
            self.user_id = d["user_id"]
            self.role = d["role"]
            self.mfa_verified = d["mfa_verified"]
            self.authentication_method = d["authentication_method"]
            self.session_id = d["session_id"]

    user_ctx = _UserCtx(ou)
    sig_valid = verify_signature(user_ctx, ou["signature"], SIGNING_KEY)

    # Step 4: Evaluate Cedar policies (real cedarpy with actual policy files)
    decision = evaluate(envelope)

    # Step 5: Build OCSF audit event
    ocsf_event = build_ocsf_event(envelope, decision, evaluation_latency_ms=0.5)

    return {
        "envelope": envelope,
        "signature_valid": sig_valid,
        "decision": decision,
        "ocsf_event": ocsf_event,
    }


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _clean_policy_cache():
    """Reset Cedar policy cache before each test."""
    reset_cache()
    yield
    reset_cache()


# ---------------------------------------------------------------------------
# Task 8.1: MCP Adapter → Cedar Evaluator pipeline integration tests
# ---------------------------------------------------------------------------


class TestHappyPathPermit:
    """Valid MCP request with authorized agent + admin user + MFA → PERMIT.

    Validates: Requirements 1.4, 5.2
    """

    def test_admin_delete_records_full_pipeline_permit(self):
        """Admin user + MFA + data-bot → delete_records → all three layers PERMIT."""
        mcp_req = _make_mcp_request(
            tool_name="delete_records",
            agent_id="data-bot",
            trust_level=4,
            namespace="data",
            lifecycle_stage="production",
            user_role="admin",
            mfa_verified=True,
            delegation_depth=1,
        )
        result = _run_full_pipeline(mcp_req)

        assert result["signature_valid"] is True
        assert result["decision"].decision == Decision.PERMIT
        assert result["decision"].denying_layer is None
        assert result["decision"].layer_results.L1.decision == Decision.PERMIT
        assert result["decision"].layer_results.L2.decision == Decision.PERMIT
        assert result["decision"].layer_results.L3.decision == Decision.PERMIT

    def test_finance_agent_payment_full_pipeline_permit(self):
        """Admin user + MFA + finance-agent → process_payment → PERMIT."""
        mcp_req = _make_mcp_request(
            tool_name="process_payment",
            agent_id="finance-agent",
            trust_level=3,
            namespace="payments",
            lifecycle_stage="production",
            user_role="admin",
            mfa_verified=True,
            delegation_depth=1,
            registered_capabilities=["process_payment"],
        )
        result = _run_full_pipeline(mcp_req)

        assert result["decision"].decision == Decision.PERMIT
        assert result["decision"].denying_layer is None

    def test_envelope_has_correct_fields_from_mcp(self):
        """Verify the envelope built from MCP has all required fields."""
        mcp_req = _make_mcp_request(
            tool_name="delete_records",
            agent_id="data-bot",
            user_id="user-test-42",
            user_role="admin",
            mfa_verified=True,
        )
        result = _run_full_pipeline(mcp_req)
        envelope = result["envelope"]

        assert envelope["source_protocol"] == "MCP"
        assert envelope["source_agent"]["agent_id"] == "data-bot"
        assert envelope["action"]["type"] == "invoke_tool"
        assert envelope["action"]["target_resource"] == "AgentAuthz::Tool::delete_records"
        assert envelope["originating_user"]["user_id"] == "user-test-42"
        assert envelope["originating_user"]["role"] == "admin"
        assert envelope["originating_user"]["mfa_verified"] is True
        assert len(envelope["originating_user"]["signature"]) == 64  # SHA-256 hex


class TestDenyPathUnauthorizedUser:
    """Valid MCP request → DENY when user role is unauthorized at L3.

    Validates: Requirements 1.4, 2.4
    """

    def test_support_user_delete_records_denied_at_l3(self):
        """Support user → data-bot → delete_records → L3 DENY."""
        mcp_req = _make_mcp_request(
            tool_name="delete_records",
            agent_id="data-bot",
            trust_level=4,
            namespace="data",
            lifecycle_stage="production",
            user_role="support",
            mfa_verified=False,
            delegation_depth=1,
        )
        result = _run_full_pipeline(mcp_req)

        assert result["signature_valid"] is True
        assert result["decision"].decision == Decision.DENY
        assert result["decision"].denying_layer == "L3"
        # L1 should have passed (agent is authorized)
        assert result["decision"].layer_results.L1.decision == Decision.PERMIT

    def test_analyst_user_delete_records_denied_at_l3(self):
        """Analyst user (no MFA) → data-bot → delete_records → L3 DENY."""
        mcp_req = _make_mcp_request(
            tool_name="delete_records",
            agent_id="data-bot",
            trust_level=4,
            namespace="data",
            lifecycle_stage="production",
            user_role="analyst",
            mfa_verified=False,
            delegation_depth=1,
        )
        result = _run_full_pipeline(mcp_req)

        assert result["decision"].decision == Decision.DENY
        assert result["decision"].denying_layer == "L3"


class TestSignatureTampering:
    """Modified user context after signing → DENY with signature failure.

    Validates: Requirements 2.4, 5.2
    """

    def test_tampered_role_fails_verification(self):
        """Changing user role after signing invalidates the signature."""
        mcp_req = _make_mcp_request(
            user_role="support",
            mfa_verified=False,
        )
        parsed = parse_mcp_message(mcp_req)
        content_filter = _mock_content_filter_result()
        envelope = build_envelope(parsed, content_filter, signing_key=SIGNING_KEY)

        # Tamper: change role from "support" to "admin"
        envelope["originating_user"]["role"] = "admin"

        # Verify signature should fail
        ou = envelope["originating_user"]

        class _UserCtx:
            def __init__(self, d):
                self.user_id = d["user_id"]
                self.role = d["role"]
                self.mfa_verified = d["mfa_verified"]
                self.authentication_method = d["authentication_method"]
                self.session_id = d["session_id"]

        user_ctx = _UserCtx(ou)
        sig_valid = verify_signature(user_ctx, ou["signature"], SIGNING_KEY)
        assert sig_valid is False

    def test_tampered_mfa_fails_verification(self):
        """Changing mfa_verified after signing invalidates the signature."""
        mcp_req = _make_mcp_request(
            user_role="admin",
            mfa_verified=False,
        )
        parsed = parse_mcp_message(mcp_req)
        content_filter = _mock_content_filter_result()
        envelope = build_envelope(parsed, content_filter, signing_key=SIGNING_KEY)

        # Tamper: flip mfa_verified from False to True
        envelope["originating_user"]["mfa_verified"] = True

        ou = envelope["originating_user"]

        class _UserCtx:
            def __init__(self, d):
                self.user_id = d["user_id"]
                self.role = d["role"]
                self.mfa_verified = d["mfa_verified"]
                self.authentication_method = d["authentication_method"]
                self.session_id = d["session_id"]

        user_ctx = _UserCtx(ou)
        sig_valid = verify_signature(user_ctx, ou["signature"], SIGNING_KEY)
        assert sig_valid is False

    def test_tampered_user_id_fails_verification(self):
        """Changing user_id after signing invalidates the signature."""
        mcp_req = _make_mcp_request(user_id="user-legit")
        parsed = parse_mcp_message(mcp_req)
        content_filter = _mock_content_filter_result()
        envelope = build_envelope(parsed, content_filter, signing_key=SIGNING_KEY)

        # Tamper: change user_id
        envelope["originating_user"]["user_id"] = "user-attacker"

        ou = envelope["originating_user"]

        class _UserCtx:
            def __init__(self, d):
                self.user_id = d["user_id"]
                self.role = d["role"]
                self.mfa_verified = d["mfa_verified"]
                self.authentication_method = d["authentication_method"]
                self.session_id = d["session_id"]

        user_ctx = _UserCtx(ou)
        sig_valid = verify_signature(user_ctx, ou["signature"], SIGNING_KEY)
        assert sig_valid is False
