# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Property 3: Layer 3 originating user auth correctness.

For any tool invocation request by an Agent on behalf of an
Originating_User_Context, the Layer 3 Cedar policy evaluation SHALL return
PERMIT if and only if the originating user's role and MFA status satisfy the
specific tool's requirements (L3-001 through L3-005) AND the delegation_depth
is within the tool-specific limit. If no originating_user context is present,
L3-999 SHALL cause a DENY.

**Validates: Requirements 1.3**

Feature: agent-authz-protection
Property 3: Layer 3 originating user auth correctness
"""

from __future__ import annotations

import sys
from pathlib import Path

import cedarpy
from hypothesis import given, settings
from hypothesis import strategies as st

_cedar_tests_dir = Path(__file__).resolve().parent.parent.parent / "cedar" / "tests"
if str(_cedar_tests_dir) not in sys.path:
    sys.path.insert(0, str(_cedar_tests_dir))

from helpers import LAYER3_DIR, make_agent_entity, make_tool_entity, make_invoke_request


# ---------------------------------------------------------------------------
# Load Layer 3 permit-only policies
# ---------------------------------------------------------------------------

def _load_l3_permit_policies() -> str:
    parts = []
    for f in sorted(LAYER3_DIR.glob("*.cedar")):
        if "-999-" not in f.stem:
            parts.append(f.read_text())
    return "\n".join(parts)


_L3_PERMIT_POLICIES = _load_l3_permit_policies()


# ---------------------------------------------------------------------------
# Known L3 permit rules — ground truth oracle
# ---------------------------------------------------------------------------

# L3-001: data-bot + delete_records → admin + MFA + depth ≤ 2
# L3-002: finance-agent + process_payment → (admin|finance_manager) + MFA + depth ≤ 3
# L3-003: finance-agent + process_refund → (admin|finance_manager|support_lead) + MFA + depth ≤ 3
# L3-004: data-bot + read_records → (admin|analyst|data_engineer) + depth ≤ 3
# L3-005: support-agent + read_tickets → (admin|support|support_lead) + depth ≤ 2

_L3_RULES: list[tuple[str, str, set[str], bool, int]] = [
    ("data-bot",       "delete_records",  {"admin"},                                    True,  2),
    ("finance-agent",  "process_payment", {"admin", "finance_manager"},                 True,  3),
    ("finance-agent",  "process_refund",  {"admin", "finance_manager", "support_lead"}, True,  3),
    ("data-bot",       "read_records",    {"admin", "analyst", "data_engineer"},         False, 3),
    ("support-agent",  "read_tickets",    {"admin", "support", "support_lead"},          False, 2),
]

_KNOWN_AGENT_TOOL_PAIRS = [
    ("data-bot", "delete_records"),
    ("finance-agent", "process_payment"),
    ("finance-agent", "process_refund"),
    ("data-bot", "read_records"),
    ("support-agent", "read_tickets"),
]

_ROLES = ["admin", "finance_manager", "support_lead", "analyst",
          "data_engineer", "support", "viewer", "guest"]


def _should_permit(agent_id: str, tool_id: str, role: str,
                   mfa: bool, depth: int) -> bool:
    """Oracle: determine if L3 should PERMIT based on the known rules."""
    for rule_agent, rule_tool, allowed_roles, requires_mfa, max_depth in _L3_RULES:
        if (agent_id == rule_agent
                and tool_id == rule_tool
                and role in allowed_roles
                and (not requires_mfa or mfa)
                and depth <= max_depth):
            return True
    return False


# ---------------------------------------------------------------------------
# Hypothesis strategies
# ---------------------------------------------------------------------------

_agent_tool_st = st.sampled_from(
    _KNOWN_AGENT_TOOL_PAIRS + [("rogue-agent", "hack_tool")]
)
_role_st = st.sampled_from(_ROLES)
_mfa_st = st.booleans()
_depth_st = st.integers(min_value=0, max_value=5)


# ---------------------------------------------------------------------------
# Property test
# ---------------------------------------------------------------------------

@settings(max_examples=100)
@given(
    agent_tool=_agent_tool_st,
    role=_role_st,
    mfa=_mfa_st,
    depth=_depth_st,
)
def test_layer3_permit_iff_user_satisfies_requirements(
    agent_tool: tuple[str, str],
    role: str,
    mfa: bool,
    depth: int,
) -> None:
    """Property 3 — L3 returns PERMIT iff user role/MFA/depth satisfy tool requirements.

    **Validates: Requirements 1.3**
    """
    agent_id, tool_id = agent_tool

    entities = [
        make_agent_entity(agent_id),
        make_tool_entity(tool_id),
    ]
    context = {
        "originating_user": {
            "user_id": "test-user",
            "role": role,
            "mfa_verified": mfa,
            "authentication_method": "password",
            "session_id": "sess-001",
        },
        "delegation_depth": depth,
    }
    request = make_invoke_request(agent_id, tool_id, context=context)

    result = cedarpy.is_authorized(request, _L3_PERMIT_POLICIES, entities)
    expected = _should_permit(agent_id, tool_id, role, mfa, depth)

    assert result.allowed is expected, (
        f"Expected {'PERMIT' if expected else 'DENY'} but got "
        f"{'PERMIT' if result.allowed else 'DENY'} for "
        f"agent={agent_id}, tool={tool_id}, role={role}, "
        f"mfa={mfa}, depth={depth}"
    )
