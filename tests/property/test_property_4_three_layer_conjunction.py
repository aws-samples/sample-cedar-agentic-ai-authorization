# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Property 4: Sequential three-layer conjunction with deny identification.

For any Request Envelope, the Cedar Evaluator SHALL return PERMIT if and only
if Layer 1, Layer 2, and Layer 3 all independently return PERMIT. If any layer
returns DENY, the overall decision SHALL be DENY and the response SHALL include
the identifier of the first denying layer (short-circuit evaluation order:
L1 → L2 → L3).

**Validates: Requirements 1.4, 1.5, 3.2, 3.3**

Feature: agent-authz-protection
Property 4: Sequential three-layer conjunction with deny identification
"""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

from hypothesis import given, settings
from hypothesis import strategies as st

# Add lambda dir to path for imports
_project_root = Path(__file__).resolve().parent.parent.parent
_lambda_dir = _project_root / "lambda"
if str(_lambda_dir) not in sys.path:
    sys.path.insert(0, str(_lambda_dir))

_evaluator = importlib.import_module("cedar_evaluator.policy_evaluator")
_types = importlib.import_module("shared.types")

evaluate = _evaluator.evaluate
reset_cache = _evaluator.reset_cache
Decision = _types.Decision


# ---------------------------------------------------------------------------
# Known valid combinations that pass all three layers
# ---------------------------------------------------------------------------

# (agent_id, trust, namespace, stage, tool_id, action_type,
#  delegating_agent, user_role, mfa, max_depth_l2, max_depth_l3)
_VALID_COMBOS = [
    # finance-agent → process_payment: L1 needs trust≥3, ns=payments, prod
    # L2 needs orchestrator→finance-agent, depth≤3, caps contained
    # L3 needs (admin|finance_manager) + MFA + depth≤3
    ("finance-agent", 3, "payments", "production", "process_payment",
     "orchestrator", "admin", True, 3, 3),
    ("finance-agent", 4, "payments", "production", "process_payment",
     "orchestrator", "finance_manager", True, 2, 3),
    # finance-agent → process_refund
    ("finance-agent", 3, "payments", "production", "process_refund",
     "orchestrator", "support_lead", True, 1, 3),
    # data-bot → read_records: L1 needs trust≥2, ns=data
    # L2 needs orchestrator→data-bot, depth≤3
    # L3 needs (admin|analyst|data_engineer) + depth≤3
    ("data-bot", 2, "data", "production", "read_records",
     "orchestrator", "analyst", False, 1, 3),
    ("data-bot", 3, "data", "production", "read_records",
     "orchestrator", "data_engineer", True, 0, 2),
    # data-bot → delete_records: L1 needs trust≥4, ns=data, prod
    # L2 needs orchestrator→data-bot, depth≤3
    # L3 needs admin + MFA + depth≤2
    ("data-bot", 4, "data", "production", "delete_records",
     "orchestrator", "admin", True, 1, 2),
    # support-agent → read_tickets: L1 needs trust≥1, ns=support
    # L2 needs orchestrator→support-agent, depth≤2
    # L3 needs (admin|support|support_lead) + depth≤2
    ("support-agent", 1, "support", "production", "read_tickets",
     "orchestrator", "support", False, 1, 2),
]


def _build_envelope(
    agent_id: str,
    trust_level: int,
    namespace: str,
    lifecycle_stage: str,
    tool_id: str,
    delegating_agent: str,
    user_role: str,
    mfa: bool,
    depth: int,
) -> dict:
    """Build a Request Envelope dict for the policy evaluator."""
    caps = [namespace]
    return {
        "request_id": "prop4-test",
        "timestamp": "2025-01-01T00:00:00Z",
        "source_protocol": "MCP",
        "source_agent": {
            "agent_id": agent_id,
            "trust_level": trust_level,
            "namespace": namespace,
            "registered_capabilities": caps,
            "lifecycle_stage": lifecycle_stage,
        },
        "action": {
            "type": "invoke_tool",
            "target_resource": f"AgentAuthz::Tool::{tool_id}",
            "requested_capabilities": caps,
        },
        "delegation_chain": [
            {
                "hop": 0,
                "agent_id": delegating_agent,
                "capabilities_granted": caps,
                "timestamp": "2025-01-01T00:00:00Z",
            }
        ],
        "delegation_depth": depth,
        "originating_user": {
            "user_id": "test-user",
            "role": user_role,
            "mfa_verified": mfa,
            "authentication_method": "password",
            "session_id": "sess-001",
        },
        "content_filter_result": {
            "injection_score": 0,
            "filter_applied": True,
            "filter_source": "bedrock-guardrails",
        },
    }


# ---------------------------------------------------------------------------
# Hypothesis strategies
# ---------------------------------------------------------------------------

_combo_st = st.sampled_from(_VALID_COMBOS)
_depth_st = st.integers(min_value=0, max_value=7)

# Strategy for breaking L1: wrong trust/namespace/stage
_break_l1_st = st.sampled_from(["low_trust", "wrong_namespace", "wrong_stage", "none"])
# Strategy for breaking L3: wrong role or no MFA
_break_l3_st = st.sampled_from(["wrong_role", "no_mfa", "deep_depth", "none"])


@settings(max_examples=100)
@given(
    combo=_combo_st,
    depth=_depth_st,
    break_l1=_break_l1_st,
    break_l3=_break_l3_st,
)
def test_three_layer_conjunction_and_deny_identification(
    combo: tuple,
    depth: int,
    break_l1: str,
    break_l3: str,
) -> None:
    """Property 4 — PERMIT iff all three layers PERMIT; DENY includes first denying layer.

    **Validates: Requirements 1.4, 1.5, 3.2, 3.3**
    """
    (agent_id, trust, namespace, stage, tool_id,
     delegating_agent, user_role, mfa, max_depth_l2, max_depth_l3) = combo

    # Optionally break L1
    actual_trust = trust
    actual_ns = namespace
    actual_stage = stage
    if break_l1 == "low_trust":
        actual_trust = 0
    elif break_l1 == "wrong_namespace":
        actual_ns = "broken"
    elif break_l1 == "wrong_stage":
        # Only matters for rules that require production
        if tool_id in ("process_payment", "process_refund", "delete_records"):
            actual_stage = "staging"

    # Optionally break L3
    actual_role = user_role
    actual_mfa = mfa
    actual_depth = min(depth, max_depth_l2)  # keep within L2 range by default
    if break_l3 == "wrong_role":
        actual_role = "guest"
    elif break_l3 == "no_mfa":
        # Only matters for rules that require MFA
        if tool_id in ("delete_records", "process_payment", "process_refund"):
            actual_mfa = False
    elif break_l3 == "deep_depth":
        actual_depth = max_depth_l3 + 1

    envelope = _build_envelope(
        agent_id, actual_trust, actual_ns, actual_stage, tool_id,
        delegating_agent, actual_role, actual_mfa, actual_depth,
    )

    reset_cache()
    result = evaluate(envelope)

    # Determine expected L1 outcome
    l1_should_permit = _l1_permits(agent_id, tool_id, actual_trust, actual_ns, actual_stage)
    # L2: delegating_agent→agent_id with depth
    l2_should_permit = _l2_permits(delegating_agent, agent_id, actual_depth, [actual_ns])
    # L3: user role/mfa/depth
    l3_should_permit = _l3_permits(agent_id, tool_id, actual_role, actual_mfa, actual_depth)

    all_permit = l1_should_permit and l2_should_permit and l3_should_permit

    if all_permit:
        assert result.decision == Decision.PERMIT, (
            f"Expected PERMIT but got DENY (layer={result.denying_layer}) for {envelope}"
        )
    else:
        assert result.decision == Decision.DENY, (
            f"Expected DENY but got PERMIT for {envelope}"
        )
        # Verify denying layer is the first one that denies (short-circuit)
        if not l1_should_permit:
            assert result.denying_layer == "L1"
        elif not l2_should_permit:
            assert result.denying_layer == "L2"
        else:
            assert result.denying_layer == "L3"


# ---------------------------------------------------------------------------
# Oracle helpers (reuse logic from Properties 1-3)
# ---------------------------------------------------------------------------

_L1_RULES = [
    ("finance-agent", "process_payment", 3, "payments", True),
    ("finance-agent", "process_refund",  3, "payments", True),
    ("data-bot",      "read_records",    2, "data",     False),
    ("data-bot",      "delete_records",  4, "data",     True),
    ("support-agent", "read_tickets",    1, "support",  False),
]

_L2_RULES = [
    ("orchestrator", "finance-agent", 3),
    ("orchestrator", "data-bot",      3),
    ("orchestrator", "support-agent", 2),
]

_L3_RULES: list[tuple[str, str, set[str], bool, int]] = [
    ("data-bot",      "delete_records",  {"admin"},                                    True,  2),
    ("finance-agent", "process_payment", {"admin", "finance_manager"},                 True,  3),
    ("finance-agent", "process_refund",  {"admin", "finance_manager", "support_lead"}, True,  3),
    ("data-bot",      "read_records",    {"admin", "analyst", "data_engineer"},         False, 3),
    ("support-agent", "read_tickets",    {"admin", "support", "support_lead"},          False, 2),
]


def _l1_permits(agent_id: str, tool_id: str, trust: int, ns: str, stage: str) -> bool:
    for ra, rt, mt, rn, rp in _L1_RULES:
        if (agent_id == ra and tool_id == rt and trust >= mt
                and ns == rn and (not rp or stage == "production")):
            return True
    return False


def _l2_permits(from_agent: str, to_agent: str, depth: int, caps: list[str]) -> bool:
    if depth > 5:
        return False
    for rf, rt, md in _L2_RULES:
        if from_agent == rf and to_agent == rt and depth <= md:
            # caps check: requested ⊆ target — in our test they're the same
            return True
    return False


def _l3_permits(agent_id: str, tool_id: str, role: str, mfa: bool, depth: int) -> bool:
    for ra, rt, roles, req_mfa, md in _L3_RULES:
        if (agent_id == ra and tool_id == rt and role in roles
                and (not req_mfa or mfa) and depth <= md):
            return True
    return False
