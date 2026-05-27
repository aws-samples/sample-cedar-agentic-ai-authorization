# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Property 1: Layer 1 agent-to-tool policy correctness.

For any Agent entity with a given trust_level, namespace, lifecycle_stage,
and registered_capabilities, and for any Tool entity, the Layer 1 Cedar
policy evaluation SHALL return PERMIT if and only if there exists a matching
permit rule (L1-001 through L1-005) where the agent identity, trust level,
namespace, and lifecycle stage satisfy the rule's conditions. Otherwise,
L1-999 (default deny) SHALL cause a DENY.

**Validates: Requirements 1.1**

Feature: agent-authz-protection
Property 1: Layer 1 agent-to-tool policy correctness
"""

from __future__ import annotations

import sys
from pathlib import Path

import cedarpy
from hypothesis import given, settings
from hypothesis import strategies as st

# Ensure cedar/tests helpers are importable
_cedar_tests_dir = Path(__file__).resolve().parent.parent.parent / "cedar" / "tests"
if str(_cedar_tests_dir) not in sys.path:
    sys.path.insert(0, str(_cedar_tests_dir))

from helpers import LAYER1_DIR, make_agent_entity, make_tool_entity, make_invoke_request


# ---------------------------------------------------------------------------
# Load Layer 1 permit-only policies (same approach as policy_evaluator.py)
# ---------------------------------------------------------------------------

def _load_l1_permit_policies() -> str:
    parts = []
    for f in sorted(LAYER1_DIR.glob("*.cedar")):
        if "-999-" not in f.stem:
            parts.append(f.read_text())
    return "\n".join(parts)


_L1_PERMIT_POLICIES = _load_l1_permit_policies()


# ---------------------------------------------------------------------------
# Known L1 permit rules — the ground truth for the property oracle
# ---------------------------------------------------------------------------

# Each rule: (agent_id, tool_id, min_trust, required_namespace, requires_production)
_L1_RULES = [
    ("finance-agent", "process_payment", 3, "payments", True),   # L1-001
    ("finance-agent", "process_refund",  3, "payments", True),   # L1-002
    ("data-bot",      "read_records",    2, "data",     False),  # L1-003
    ("data-bot",      "delete_records",  4, "data",     True),   # L1-004
    ("support-agent", "read_tickets",    1, "support",  False),  # L1-005
]

_KNOWN_AGENTS = ["finance-agent", "data-bot", "support-agent"]
_KNOWN_TOOLS = ["process_payment", "process_refund", "read_records", "delete_records", "read_tickets"]
_NAMESPACES = ["payments", "data", "support", "unknown"]
_LIFECYCLE_STAGES = ["production", "staging", "development", "testing"]


def _should_permit(agent_id: str, tool_id: str, trust_level: int,
                   namespace: str, lifecycle_stage: str) -> bool:
    """Oracle: determine if L1 should PERMIT based on the known rules."""
    for rule_agent, rule_tool, min_trust, req_ns, req_prod in _L1_RULES:
        if (agent_id == rule_agent
                and tool_id == rule_tool
                and trust_level >= min_trust
                and namespace == req_ns
                and (not req_prod or lifecycle_stage == "production")):
            return True
    return False


# ---------------------------------------------------------------------------
# Hypothesis strategies
# ---------------------------------------------------------------------------

# Mix known agents/tools with random ones to test both permit and deny paths
_agent_id_st = st.sampled_from(_KNOWN_AGENTS + ["rogue-agent", "unknown-agent"])
_tool_id_st = st.sampled_from(_KNOWN_TOOLS + ["unknown_tool", "hack_tool"])
_trust_level_st = st.integers(min_value=1, max_value=5)
_namespace_st = st.sampled_from(_NAMESPACES)
_lifecycle_st = st.sampled_from(_LIFECYCLE_STAGES)


# ---------------------------------------------------------------------------
# Property test
# ---------------------------------------------------------------------------

@settings(max_examples=100)
@given(
    agent_id=_agent_id_st,
    tool_id=_tool_id_st,
    trust_level=_trust_level_st,
    namespace=_namespace_st,
    lifecycle_stage=_lifecycle_st,
)
def test_layer1_permit_iff_matching_rule(
    agent_id: str,
    tool_id: str,
    trust_level: int,
    namespace: str,
    lifecycle_stage: str,
) -> None:
    """Property 1 — L1 returns PERMIT iff a matching permit rule exists.

    **Validates: Requirements 1.1**
    """
    entities = [
        make_agent_entity(agent_id, trust_level=trust_level, namespace=namespace,
                          lifecycle_stage=lifecycle_stage),
        make_tool_entity(tool_id, namespace=namespace),
    ]
    request = make_invoke_request(agent_id, tool_id)

    result = cedarpy.is_authorized(request, _L1_PERMIT_POLICIES, entities)
    expected = _should_permit(agent_id, tool_id, trust_level, namespace, lifecycle_stage)

    assert result.allowed is expected, (
        f"Expected {'PERMIT' if expected else 'DENY'} but got "
        f"{'PERMIT' if result.allowed else 'DENY'} for "
        f"agent={agent_id}, tool={tool_id}, trust={trust_level}, "
        f"ns={namespace}, stage={lifecycle_stage}"
    )
