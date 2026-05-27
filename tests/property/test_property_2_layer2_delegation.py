# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Property 2: Layer 2 delegation policy correctness.

For any delegation request from a principal Agent to a target Agent, with a
given delegation_depth, target_capabilities, and requested_capabilities, the
Layer 2 Cedar policy evaluation SHALL return PERMIT if and only if:
(a) there exists a matching permit rule (L2-001 through L2-003) where the
delegation depth is within the per-target limit AND target_capabilities
contains all requested_capabilities, AND (b) the delegation_depth does not
exceed the hard limit of 5 (L2-004). Otherwise, L2-999 (default deny
delegation) SHALL cause a DENY.

**Validates: Requirements 1.2**

Feature: agent-authz-protection
Property 2: Layer 2 delegation policy correctness
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

from helpers import LAYER2_DIR, make_agent_entity, make_delegate_request


# ---------------------------------------------------------------------------
# Load Layer 2 permit-only policies (exclude L2-004 forbid and L2-999)
# ---------------------------------------------------------------------------

def _load_l2_permit_policies() -> str:
    parts = []
    for f in sorted(LAYER2_DIR.glob("*.cedar")):
        name = f.stem
        if "-999-" in name:
            continue
        if "-004-" in name:
            continue
        parts.append(f.read_text())
    return "\n".join(parts)


_L2_PERMIT_POLICIES = _load_l2_permit_policies()


# ---------------------------------------------------------------------------
# Known L2 permit rules — ground truth oracle
# ---------------------------------------------------------------------------

# (from_agent, to_agent, max_depth)
_L2_RULES = [
    ("orchestrator", "finance-agent",  3),  # L2-001
    ("orchestrator", "data-bot",       3),  # L2-002
    ("orchestrator", "support-agent",  2),  # L2-003
]

_HARD_DEPTH_LIMIT = 5

_FROM_AGENTS = ["orchestrator", "finance-agent", "rogue-agent"]
_TO_AGENTS = ["finance-agent", "data-bot", "support-agent", "unknown-agent"]
_ALL_CAPABILITIES = ["payments", "refunds", "data_read", "data_delete", "support"]


def _should_permit(from_agent: str, to_agent: str, depth: int,
                   target_caps: list[str], requested_caps: list[str]) -> bool:
    """Oracle: determine if L2 should PERMIT based on the known rules."""
    # L2-004: hard depth limit (handled in Python by policy_evaluator,
    # but for direct Cedar evaluation we only test permit policies)
    for rule_from, rule_to, max_depth in _L2_RULES:
        if (from_agent == rule_from
                and to_agent == rule_to
                and depth <= max_depth
                and set(requested_caps).issubset(set(target_caps))):
            return True
    return False


# ---------------------------------------------------------------------------
# Hypothesis strategies
# ---------------------------------------------------------------------------

_from_agent_st = st.sampled_from(_FROM_AGENTS)
_to_agent_st = st.sampled_from(_TO_AGENTS)
_depth_st = st.integers(min_value=0, max_value=6)
_caps_st = st.lists(st.sampled_from(_ALL_CAPABILITIES), min_size=0, max_size=3, unique=True)


# ---------------------------------------------------------------------------
# Property test
# ---------------------------------------------------------------------------

@settings(max_examples=100)
@given(
    from_agent=_from_agent_st,
    to_agent=_to_agent_st,
    depth=_depth_st,
    target_caps=_caps_st,
    requested_caps=_caps_st,
)
def test_layer2_permit_iff_matching_rule(
    from_agent: str,
    to_agent: str,
    depth: int,
    target_caps: list[str],
    requested_caps: list[str],
) -> None:
    """Property 2 — L2 returns PERMIT iff matching rule, depth within limit, and caps contained.

    **Validates: Requirements 1.2**
    """
    entities = [
        make_agent_entity(from_agent),
        make_agent_entity(to_agent),
    ]
    context = {
        "delegation_depth": depth,
        "target_capabilities": sorted(target_caps),
        "requested_capabilities": sorted(requested_caps),
    }
    request = make_delegate_request(from_agent, to_agent, context=context)

    result = cedarpy.is_authorized(request, _L2_PERMIT_POLICIES, entities)
    expected = _should_permit(from_agent, to_agent, depth, target_caps, requested_caps)

    assert result.allowed is expected, (
        f"Expected {'PERMIT' if expected else 'DENY'} but got "
        f"{'PERMIT' if result.allowed else 'DENY'} for "
        f"from={from_agent}, to={to_agent}, depth={depth}, "
        f"target_caps={target_caps}, requested_caps={requested_caps}"
    )
