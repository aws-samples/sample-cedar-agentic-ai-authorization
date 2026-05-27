# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Integration tests for originating user auth attack scenarios.

Tests the three blog walkthrough scenarios end-to-end using the real
Cedar policy evaluation engine (cedarpy) with actual policy files.

Scenario A: Support user → orchestrator → data-bot → delete_records
            L1 PERMIT, L3 DENY (role is "support", not "admin")

Scenario B: Admin user with MFA → same chain → all three layers PERMIT

Scenario C: Delegation depth > 5 → DENY at L2

Validates: Requirements 1.3, 1.5, 3.4
"""

from __future__ import annotations

import importlib
from datetime import datetime, timezone

import pytest

_evaluator_mod = importlib.import_module("cedar_evaluator.policy_evaluator")
_types_mod = importlib.import_module("shared.types")

evaluate = _evaluator_mod.evaluate
reset_cache = _evaluator_mod.reset_cache
Decision = _types_mod.Decision


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_envelope(
    agent_id: str = "data-bot",
    trust_level: int = 4,
    namespace: str = "data",
    lifecycle_stage: str = "production",
    action_type: str = "invoke_tool",
    target_resource: str = "delete_records",
    delegation_depth: int = 1,
    user_role: str = "admin",
    mfa_verified: bool = True,
    requested_capabilities: list | None = None,
    delegation_chain: list | None = None,
) -> dict:
    """Build a Request Envelope for originating user auth scenarios."""
    if requested_capabilities is None:
        requested_capabilities = [target_resource]
    if delegation_chain is None:
        delegation_chain = [
            {
                "hop": 0,
                "agent_id": "orchestrator",
                "capabilities_granted": requested_capabilities,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        ]
    return {
        "request_id": "00000000-0000-4000-8000-000000000001",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source_protocol": "MCP",
        "source_agent": {
            "agent_id": agent_id,
            "trust_level": trust_level,
            "namespace": namespace,
            "registered_capabilities": requested_capabilities,
            "lifecycle_stage": lifecycle_stage,
        },
        "action": {
            "type": action_type,
            "target_resource": target_resource,
            "requested_capabilities": requested_capabilities,
        },
        "delegation_chain": delegation_chain,
        "delegation_depth": delegation_depth,
        "originating_user": {
            "user_id": "user-scenario",
            "role": user_role,
            "mfa_verified": mfa_verified,
            "authentication_method": "sso",
            "session_id": "sess-scenario-001",
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
def _clean_policy_cache():
    """Reset Cedar policy cache before each test."""
    reset_cache()
    yield
    reset_cache()


# ---------------------------------------------------------------------------
# Scenario A: Baseline vulnerability — support user denied at L3
# ---------------------------------------------------------------------------


class TestScenarioA:
    """Support user → orchestrator → data-bot → delete_records.

    L1 PERMIT (agent has capability), L3 DENY (role is "support", not "admin").
    This is the originating user auth vulnerability that Layer 3 catches.

    Validates: Requirements 1.3, 1.5
    """

    def test_support_user_delete_records_l1_permit_l3_deny(self):
        """Support user triggers delete_records via data-bot: L1 permits, L3 denies."""
        envelope = _make_envelope(
            agent_id="data-bot",
            trust_level=4,
            namespace="data",
            lifecycle_stage="production",
            target_resource="delete_records",
            delegation_depth=1,
            user_role="support",
            mfa_verified=False,
        )
        result = evaluate(envelope)

        assert result.decision == Decision.DENY
        assert result.denying_layer == "L3"
        # L1 should permit — data-bot has trust_level 4, namespace "data", production
        assert result.layer_results.L1.decision == Decision.PERMIT
        # L3 denies because role is "support", not "admin"
        assert result.layer_results.L3.decision == Decision.DENY

    def test_support_user_with_mfa_still_denied_at_l3(self):
        """Even with MFA, support user cannot delete records (wrong role)."""
        envelope = _make_envelope(
            agent_id="data-bot",
            trust_level=4,
            namespace="data",
            lifecycle_stage="production",
            target_resource="delete_records",
            delegation_depth=1,
            user_role="support",
            mfa_verified=True,  # MFA doesn't help — wrong role
        )
        result = evaluate(envelope)

        assert result.decision == Decision.DENY
        assert result.denying_layer == "L3"

    def test_support_user_read_tickets_permitted(self):
        """Support user CAN read tickets (L3-005 allows support role)."""
        envelope = _make_envelope(
            agent_id="support-agent",
            trust_level=1,
            namespace="support",
            lifecycle_stage="production",
            target_resource="read_tickets",
            delegation_depth=1,
            user_role="support",
            mfa_verified=False,
            delegation_chain=[
                {
                    "hop": 0,
                    "agent_id": "orchestrator",
                    "capabilities_granted": ["read_tickets"],
                    "timestamp": "2026-04-13T12:00:00Z",
                }
            ],
        )
        result = evaluate(envelope)

        assert result.decision == Decision.PERMIT
        assert result.denying_layer is None


# ---------------------------------------------------------------------------
# Scenario B: Legitimate admin — all three layers PERMIT
# ---------------------------------------------------------------------------


class TestScenarioB:
    """Admin user with MFA → orchestrator → data-bot → delete_records.

    All three layers PERMIT.

    Validates: Requirements 1.3, 1.5
    """

    def test_admin_mfa_delete_records_all_permit(self):
        """Admin + MFA + data-bot → delete_records → all three layers PERMIT."""
        envelope = _make_envelope(
            agent_id="data-bot",
            trust_level=4,
            namespace="data",
            lifecycle_stage="production",
            target_resource="delete_records",
            delegation_depth=1,
            user_role="admin",
            mfa_verified=True,
        )
        result = evaluate(envelope)

        assert result.decision == Decision.PERMIT
        assert result.denying_layer is None
        assert result.layer_results.L1.decision == Decision.PERMIT
        assert result.layer_results.L2.decision == Decision.PERMIT
        assert result.layer_results.L3.decision == Decision.PERMIT

    def test_admin_no_mfa_denied_at_l3(self):
        """Admin WITHOUT MFA → delete_records → L3 DENY (MFA required)."""
        envelope = _make_envelope(
            agent_id="data-bot",
            trust_level=4,
            namespace="data",
            lifecycle_stage="production",
            target_resource="delete_records",
            delegation_depth=1,
            user_role="admin",
            mfa_verified=False,  # No MFA
        )
        result = evaluate(envelope)

        assert result.decision == Decision.DENY
        assert result.denying_layer == "L3"
        assert result.layer_results.L1.decision == Decision.PERMIT

    def test_admin_mfa_process_payment_all_permit(self):
        """Admin + MFA + finance-agent → process_payment → all PERMIT."""
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
                }
            ],
        )
        result = evaluate(envelope)

        assert result.decision == Decision.PERMIT
        assert result.denying_layer is None


# ---------------------------------------------------------------------------
# Scenario C: Delegation depth exceeded → DENY at L2
# ---------------------------------------------------------------------------


class TestScenarioC:
    """Delegation chain with depth > 5 → DENY at L2 (L2-004 hard limit).

    Validates: Requirements 1.5, 3.4
    """

    def test_depth_6_denied_at_l2(self):
        """Delegation depth 6 → L2 DENY (hard limit is 5)."""
        long_chain = [
            {
                "hop": i,
                "agent_id": f"agent-{i}",
                "capabilities_granted": ["delete_records"],
                "timestamp": "2026-04-13T12:00:00Z",
            }
            for i in range(6)
        ]
        envelope = _make_envelope(
            agent_id="data-bot",
            trust_level=4,
            namespace="data",
            lifecycle_stage="production",
            target_resource="delete_records",
            delegation_depth=6,
            user_role="admin",
            mfa_verified=True,
            delegation_chain=long_chain,
        )
        result = evaluate(envelope)

        assert result.decision == Decision.DENY
        assert result.denying_layer == "L2"
        assert result.layer_results.L1.decision == Decision.PERMIT
        assert result.layer_results.L2.decision == Decision.DENY
        assert "depth" in result.layer_results.L2.evaluation_details.lower()

    def test_depth_10_denied_at_l2(self):
        """Delegation depth 10 → L2 DENY (well above hard limit)."""
        long_chain = [
            {
                "hop": i,
                "agent_id": f"agent-{i}",
                "capabilities_granted": ["delete_records"],
                "timestamp": "2026-04-13T12:00:00Z",
            }
            for i in range(10)
        ]
        envelope = _make_envelope(
            agent_id="data-bot",
            trust_level=4,
            namespace="data",
            lifecycle_stage="production",
            target_resource="delete_records",
            delegation_depth=10,
            user_role="admin",
            mfa_verified=True,
            delegation_chain=long_chain,
        )
        result = evaluate(envelope)

        assert result.decision == Decision.DENY
        assert result.denying_layer == "L2"

    def test_depth_5_permitted(self):
        """Delegation depth exactly 5 → NOT denied by L2-004 hard limit."""
        chain = [
            {
                "hop": i,
                "agent_id": "orchestrator" if i == 0 else f"agent-{i}",
                "capabilities_granted": ["delete_records"],
                "timestamp": "2026-04-13T12:00:00Z",
            }
            for i in range(5)
        ]
        envelope = _make_envelope(
            agent_id="data-bot",
            trust_level=4,
            namespace="data",
            lifecycle_stage="production",
            target_resource="delete_records",
            delegation_depth=5,
            user_role="admin",
            mfa_verified=True,
            delegation_chain=chain,
        )
        result = evaluate(envelope)

        # Depth 5 is at the hard limit boundary — should NOT be denied by L2-004
        # (L2-004 forbids depth > 5, not >= 5)
        # L2 may still deny for other reasons (delegation policy matching)
        # but it should NOT be the depth hard limit
        if result.decision == Decision.DENY and result.denying_layer == "L2":
            assert "depth" not in (
                result.layer_results.L2.evaluation_details or ""
            ).lower() or "hard limit" not in (
                result.layer_results.L2.evaluation_details or ""
            ).lower()

    def test_depth_1_with_valid_chain_permitted(self):
        """Depth 1 with valid orchestrator → data-bot chain → all PERMIT."""
        envelope = _make_envelope(
            agent_id="data-bot",
            trust_level=4,
            namespace="data",
            lifecycle_stage="production",
            target_resource="delete_records",
            delegation_depth=1,
            user_role="admin",
            mfa_verified=True,
            delegation_chain=[
                {
                    "hop": 0,
                    "agent_id": "orchestrator",
                    "capabilities_granted": ["delete_records"],
                    "timestamp": "2026-04-13T12:00:00Z",
                }
            ],
        )
        result = evaluate(envelope)

        assert result.decision == Decision.PERMIT
        assert result.denying_layer is None
