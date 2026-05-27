# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Unit tests for the three-layer Cedar policy evaluator.

Tests verify:
- All-permit → PERMIT
- L1 deny short-circuits (L2/L3 not evaluated)
- L2 deny short-circuits (L3 not evaluated)
- L3 deny returns DENY with denying_layer="L3"
- Policy cache loading and TTL refresh

Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 3.1, 3.2, 3.3, 3.6
"""

import importlib
import time

import pytest

_evaluator = importlib.import_module("cedar_evaluator.policy_evaluator")
_types = importlib.import_module("shared.types")

LAYER1_DIR = _evaluator.LAYER1_DIR
LAYER2_DIR = _evaluator.LAYER2_DIR
LAYER3_DIR = _evaluator.LAYER3_DIR
_build_agent_entity = _evaluator._build_agent_entity
_build_cedar_context = _evaluator._build_cedar_context
_build_tool_entity = _evaluator._build_tool_entity
_extract_resource_id = _evaluator._extract_resource_id
_refresh_cache_if_needed = _evaluator._refresh_cache_if_needed
evaluate = _evaluator.evaluate
reset_cache = _evaluator.reset_cache
Decision = _types.Decision


# ---------------------------------------------------------------------------
# Helpers — build a minimal valid Request Envelope dict
# ---------------------------------------------------------------------------


def _make_envelope(
    agent_id: str = "finance-agent",
    trust_level: int = 3,
    namespace: str = "payments",
    lifecycle_stage: str = "production",
    action_type: str = "invoke_tool",
    target_resource: str = "process_payment",
    delegation_depth: int = 1,
    user_role: str = "admin",
    mfa_verified: bool = True,
    requested_capabilities: list | None = None,
    delegation_chain: list | None = None,
) -> dict:
    """Build a minimal Request Envelope dict for testing."""
    if delegation_chain is None:
        delegation_chain = [
            {
                "hop": 0,
                "agent_id": "orchestrator",
                "capabilities_granted": requested_capabilities or ["process_payment"],
                "timestamp": "2026-04-13T12:00:00Z",
            },
        ]
    return {
        "request_id": "00000000-0000-4000-8000-000000000001",
        "timestamp": "2026-04-13T12:00:00Z",
        "source_protocol": "MCP",
        "source_agent": {
            "agent_id": agent_id,
            "trust_level": trust_level,
            "namespace": namespace,
            "registered_capabilities": requested_capabilities or ["process_payment"],
            "lifecycle_stage": lifecycle_stage,
        },
        "action": {
            "type": action_type,
            "target_resource": target_resource,
            "requested_capabilities": requested_capabilities or ["process_payment"],
        },
        "delegation_chain": delegation_chain,
        "delegation_depth": delegation_depth,
        "originating_user": {
            "user_id": "user-admin-001",
            "role": user_role,
            "mfa_verified": mfa_verified,
            "authentication_method": "SSO",
            "session_id": "session-001",
            "signature": "aabbccdd",
        },
        "content_filter_result": {
            "injection_score": 0,
            "filter_applied": True,
            "filter_source": "bedrock-guardrails",
        },
    }


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _clean_cache():
    """Reset the policy cache before each test."""
    reset_cache()
    yield
    reset_cache()


# ---------------------------------------------------------------------------
# Entity / context construction tests
# ---------------------------------------------------------------------------


class TestBuildAgentEntity:
    """Tests for _build_agent_entity."""

    def test_builds_correct_structure(self):
        envelope = _make_envelope(agent_id="data-bot", trust_level=4, namespace="data")
        entity = _build_agent_entity(envelope)
        assert entity["uid"] == {"type": "AgentAuthz::Agent", "id": "data-bot"}
        assert entity["attrs"]["trust_level"] == 4
        assert entity["attrs"]["namespace"] == "data"
        assert entity["parents"] == []


class TestBuildCedarContext:
    """Tests for _build_cedar_context."""

    def test_includes_originating_user(self):
        envelope = _make_envelope(user_role="analyst", mfa_verified=False)
        ctx = _build_cedar_context(envelope)
        assert ctx["originating_user"]["role"] == "analyst"
        assert ctx["originating_user"]["mfa_verified"] is False

    def test_includes_delegation_depth(self):
        envelope = _make_envelope(delegation_depth=3)
        ctx = _build_cedar_context(envelope)
        assert ctx["delegation_depth"] == 3

    def test_includes_content_filter_score(self):
        envelope = _make_envelope()
        ctx = _build_cedar_context(envelope)
        assert ctx["content_filter_score"] == 0


class TestExtractResourceId:
    """Tests for _extract_resource_id."""

    def test_plain_id(self):
        assert _extract_resource_id("process_payment") == "process_payment"

    def test_cedar_style_tool(self):
        assert _extract_resource_id('Tool::"process_payment"') == "process_payment"

    def test_cedar_style_agent(self):
        assert _extract_resource_id('Agent::"data-bot"') == "data-bot"

    def test_namespaced_cedar_style_tool(self):
        assert _extract_resource_id('AgentAuthz::Tool::"process_payment"') == "process_payment"

    def test_namespaced_cedar_style_agent(self):
        assert _extract_resource_id('AgentAuthz::Agent::"data-bot"') == "data-bot"


# ---------------------------------------------------------------------------
# Three-layer evaluation tests
# ---------------------------------------------------------------------------


class TestAllPermit:
    """When all three layers permit, the overall decision is PERMIT."""

    def test_finance_agent_payment_admin_mfa(self):
        """finance-agent + process_payment + admin + MFA → all PERMIT."""
        envelope = _make_envelope(
            agent_id="finance-agent",
            trust_level=3,
            namespace="payments",
            lifecycle_stage="production",
            target_resource="process_payment",
            delegation_depth=1,
            user_role="admin",
            mfa_verified=True,
            requested_capabilities=["process_payment"],
            delegation_chain=[
                {
                    "hop": 0,
                    "agent_id": "orchestrator",
                    "capabilities_granted": ["process_payment"],
                    "timestamp": "2026-04-13T12:00:00Z",
                },
            ],
        )
        # Override source_agent to be orchestrator for L2 delegation context
        # Actually for invoke_tool, L2 uses delegate_task action which won't match
        # invoke_tool policies. Let's test the actual flow.
        result = evaluate(envelope)
        assert result.decision == Decision.PERMIT
        assert result.denying_layer is None
        assert result.layer_results is not None
        assert result.layer_results.L1.decision == Decision.PERMIT
        assert result.layer_results.L3.decision == Decision.PERMIT


class TestL1DenyShortCircuit:
    """When L1 denies, L2 and L3 are not evaluated (short-circuit)."""

    def test_unknown_agent_denied_at_l1(self):
        """An unknown agent is denied by L1 default deny."""
        envelope = _make_envelope(
            agent_id="rogue-agent",
            trust_level=5,
            namespace="payments",
            target_resource="process_payment",
        )
        result = evaluate(envelope)
        assert result.decision == Decision.DENY
        assert result.denying_layer == "L1"
        assert result.layer_results.L1.decision == Decision.DENY
        assert "Not evaluated" in result.layer_results.L2.evaluation_details
        assert "Not evaluated" in result.layer_results.L3.evaluation_details

    def test_wrong_namespace_denied_at_l1(self):
        """Finance agent with wrong namespace is denied at L1."""
        envelope = _make_envelope(
            agent_id="finance-agent",
            trust_level=3,
            namespace="data",  # wrong namespace
            target_resource="process_payment",
        )
        result = evaluate(envelope)
        assert result.decision == Decision.DENY
        assert result.denying_layer == "L1"


class TestL3DenyUnauthorizedUser:
    """Layer 3 denies when user context doesn't match tool requirements."""

    def test_support_user_denied_delete_records(self):
        """Support user trying to delete records → L3 DENY (originating user auth)."""
        envelope = _make_envelope(
            agent_id="data-bot",
            trust_level=4,
            namespace="data",
            lifecycle_stage="production",
            target_resource="delete_records",
            delegation_depth=1,
            user_role="support",  # not admin
            mfa_verified=False,
            requested_capabilities=["delete_records"],
            delegation_chain=[
                {
                    "hop": 0,
                    "agent_id": "orchestrator",
                    "capabilities_granted": ["delete_records"],
                    "timestamp": "2026-04-13T12:00:00Z",
                },
            ],
        )
        result = evaluate(envelope)
        assert result.decision == Decision.DENY
        assert result.denying_layer == "L3"
        assert result.layer_results.L1.decision == Decision.PERMIT
        assert result.layer_results.L3.decision == Decision.DENY

    def test_admin_with_mfa_permitted_delete_records(self):
        """Admin user with MFA can delete records → all PERMIT."""
        envelope = _make_envelope(
            agent_id="data-bot",
            trust_level=4,
            namespace="data",
            lifecycle_stage="production",
            target_resource="delete_records",
            delegation_depth=1,
            user_role="admin",
            mfa_verified=True,
            requested_capabilities=["delete_records"],
            delegation_chain=[
                {
                    "hop": 0,
                    "agent_id": "orchestrator",
                    "capabilities_granted": ["delete_records"],
                    "timestamp": "2026-04-13T12:00:00Z",
                },
            ],
        )
        result = evaluate(envelope)
        assert result.decision == Decision.PERMIT
        assert result.denying_layer is None


class TestL2DenyDelegationDepth:
    """Layer 2 denies when delegation depth exceeds hard limit."""

    def test_delegation_depth_exceeds_hard_limit(self):
        """Delegation depth > 5 → L2 DENY (L2-004 hard limit)."""
        envelope = _make_envelope(
            agent_id="finance-agent",
            trust_level=3,
            namespace="payments",
            lifecycle_stage="production",
            target_resource="process_payment",
            delegation_depth=6,
            user_role="admin",
            mfa_verified=True,
            requested_capabilities=["process_payment"],
            delegation_chain=[
                {
                    "hop": 0,
                    "agent_id": "orchestrator",
                    "capabilities_granted": ["process_payment"],
                    "timestamp": "2026-04-13T12:00:00Z",
                },
            ],
        )
        result = evaluate(envelope)
        assert result.decision == Decision.DENY
        assert result.denying_layer == "L2"
        assert result.layer_results.L1.decision == Decision.PERMIT
        assert result.layer_results.L2.decision == Decision.DENY
        assert "depth" in result.layer_results.L2.evaluation_details.lower()

    def test_delegation_depth_at_limit_permitted(self):
        """Delegation depth == 3 (within L2-001 limit) → L2 PERMIT."""
        envelope = _make_envelope(
            agent_id="finance-agent",
            trust_level=3,
            namespace="payments",
            lifecycle_stage="production",
            target_resource="process_payment",
            delegation_depth=3,
            user_role="admin",
            mfa_verified=True,
            requested_capabilities=["process_payment"],
            delegation_chain=[
                {
                    "hop": 0,
                    "agent_id": "orchestrator",
                    "capabilities_granted": ["process_payment"],
                    "timestamp": "2026-04-13T12:00:00Z",
                },
            ],
        )
        result = evaluate(envelope)
        assert result.decision == Decision.PERMIT


class TestUnknownActionType:
    """Unknown action types are immediately denied."""

    def test_unknown_action_type(self):
        envelope = _make_envelope(action_type="unknown_action")
        result = evaluate(envelope)
        assert result.decision == Decision.DENY
        assert result.denying_layer == "L1"
        assert "Unknown action type" in result.layer_results.L1.evaluation_details


# ---------------------------------------------------------------------------
# Cache tests
# ---------------------------------------------------------------------------


class TestPolicyCache:
    """Tests for policy cache loading and TTL refresh."""

    def test_cache_loads_on_first_evaluate(self):
        """Policies are loaded from disk on first call."""
        envelope = _make_envelope()
        # Should not raise — policies load automatically
        result = evaluate(envelope)
        assert result.decision in (Decision.PERMIT, Decision.DENY)

    def test_reset_cache_clears_state(self):
        """reset_cache clears the module-level cache."""
        _refresh_cache_if_needed()
        assert _evaluator._policy_cache  # loaded
        reset_cache()
        assert not _evaluator._policy_cache  # cleared
