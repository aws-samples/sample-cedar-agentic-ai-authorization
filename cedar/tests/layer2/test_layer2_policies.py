# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Unit tests for Layer 2 (agent-to-agent delegation) Cedar policies.

Tests verify:
- L2-001 through L2-003 permit valid delegations
- L2-004 denies delegation depth > 5
- L2-999 denies unmatched delegation requests

Requirements: 1.1, 1.2, 1.3
"""

import sys
from pathlib import Path

_tests_dir = Path(__file__).resolve().parent.parent
if str(_tests_dir) not in sys.path:
    sys.path.insert(0, str(_tests_dir))

import cedarpy

from helpers import (
    make_agent_entity,
    make_delegate_request,
)


# ── L2-001: orchestrator → finance-agent ─────────────────────────


class TestL2001OrchestratorFinance:
    """L2-001: Orchestrator can delegate to finance agent."""

    def test_permit_valid_delegation(self, layer2_permit_policies):
        """Orchestrator delegates to finance-agent within depth limit."""
        entities = [
            make_agent_entity("orchestrator", trust_level=5, namespace="core"),
            make_agent_entity("finance-agent", trust_level=3, namespace="payments"),
        ]
        context = {
            "delegation_depth": 1,
            "target_capabilities": ["process_payment", "process_refund"],
            "requested_capabilities": ["process_payment"],
        }
        request = make_delegate_request("orchestrator", "finance-agent", context)
        result = cedarpy.is_authorized(request, layer2_permit_policies, entities)
        assert result.allowed is True

    def test_deny_depth_exceeds_limit(self, layer2_permit_policies):
        """Orchestrator denied when delegation_depth > 3."""
        entities = [
            make_agent_entity("orchestrator", trust_level=5, namespace="core"),
            make_agent_entity("finance-agent", trust_level=3, namespace="payments"),
        ]
        context = {
            "delegation_depth": 4,
            "target_capabilities": ["process_payment"],
            "requested_capabilities": ["process_payment"],
        }
        request = make_delegate_request("orchestrator", "finance-agent", context)
        result = cedarpy.is_authorized(request, layer2_permit_policies, entities)
        assert result.allowed is False

    def test_deny_missing_capabilities(self, layer2_permit_policies):
        """Denied when target lacks requested capabilities."""
        entities = [
            make_agent_entity("orchestrator", trust_level=5, namespace="core"),
            make_agent_entity("finance-agent", trust_level=3, namespace="payments"),
        ]
        context = {
            "delegation_depth": 1,
            "target_capabilities": ["process_payment"],
            "requested_capabilities": ["process_payment", "process_refund"],
        }
        request = make_delegate_request("orchestrator", "finance-agent", context)
        result = cedarpy.is_authorized(request, layer2_permit_policies, entities)
        assert result.allowed is False

    def test_permit_at_depth_boundary(self, layer2_permit_policies):
        """Orchestrator permitted at exactly depth 3 (the limit)."""
        entities = [
            make_agent_entity("orchestrator", trust_level=5, namespace="core"),
            make_agent_entity("finance-agent", trust_level=3, namespace="payments"),
        ]
        context = {
            "delegation_depth": 3,
            "target_capabilities": ["process_payment"],
            "requested_capabilities": ["process_payment"],
        }
        request = make_delegate_request("orchestrator", "finance-agent", context)
        result = cedarpy.is_authorized(request, layer2_permit_policies, entities)
        assert result.allowed is True


# ── L2-002: orchestrator → data-bot ──────────────────────────────


class TestL2002OrchestratorData:
    """L2-002: Orchestrator can delegate to data agent."""

    def test_permit_valid_delegation(self, layer2_permit_policies):
        """Orchestrator delegates to data-bot within depth limit."""
        entities = [
            make_agent_entity("orchestrator", trust_level=5, namespace="core"),
            make_agent_entity("data-bot", trust_level=4, namespace="data"),
        ]
        context = {
            "delegation_depth": 1,
            "target_capabilities": ["read_records", "delete_records"],
            "requested_capabilities": ["read_records"],
        }
        request = make_delegate_request("orchestrator", "data-bot", context)
        result = cedarpy.is_authorized(request, layer2_permit_policies, entities)
        assert result.allowed is True

    def test_deny_depth_exceeds_limit(self, layer2_permit_policies):
        """Orchestrator denied when delegation_depth > 3 for data-bot."""
        entities = [
            make_agent_entity("orchestrator", trust_level=5, namespace="core"),
            make_agent_entity("data-bot", trust_level=4, namespace="data"),
        ]
        context = {
            "delegation_depth": 4,
            "target_capabilities": ["read_records"],
            "requested_capabilities": ["read_records"],
        }
        request = make_delegate_request("orchestrator", "data-bot", context)
        result = cedarpy.is_authorized(request, layer2_permit_policies, entities)
        assert result.allowed is False


# ── L2-003: orchestrator → support-agent ─────────────────────────


class TestL2003OrchestratorSupport:
    """L2-003: Orchestrator can delegate to support agent."""

    def test_permit_valid_delegation(self, layer2_permit_policies):
        """Orchestrator delegates to support-agent within depth limit."""
        entities = [
            make_agent_entity("orchestrator", trust_level=5, namespace="core"),
            make_agent_entity("support-agent", trust_level=1, namespace="support"),
        ]
        context = {
            "delegation_depth": 1,
            "target_capabilities": ["read_tickets"],
            "requested_capabilities": ["read_tickets"],
        }
        request = make_delegate_request("orchestrator", "support-agent", context)
        result = cedarpy.is_authorized(request, layer2_permit_policies, entities)
        assert result.allowed is True

    def test_deny_depth_exceeds_support_limit(self, layer2_permit_policies):
        """Support agent has stricter depth limit (2). Depth 3 denied."""
        entities = [
            make_agent_entity("orchestrator", trust_level=5, namespace="core"),
            make_agent_entity("support-agent", trust_level=1, namespace="support"),
        ]
        context = {
            "delegation_depth": 3,
            "target_capabilities": ["read_tickets"],
            "requested_capabilities": ["read_tickets"],
        }
        request = make_delegate_request("orchestrator", "support-agent", context)
        result = cedarpy.is_authorized(request, layer2_permit_policies, entities)
        assert result.allowed is False

    def test_permit_at_depth_boundary(self, layer2_permit_policies):
        """Support delegation permitted at exactly depth 2."""
        entities = [
            make_agent_entity("orchestrator", trust_level=5, namespace="core"),
            make_agent_entity("support-agent", trust_level=1, namespace="support"),
        ]
        context = {
            "delegation_depth": 2,
            "target_capabilities": ["read_tickets"],
            "requested_capabilities": ["read_tickets"],
        }
        request = make_delegate_request("orchestrator", "support-agent", context)
        result = cedarpy.is_authorized(request, layer2_permit_policies, entities)
        assert result.allowed is True


# ── L2-004: Delegation depth hard limit ──────────────────────────


class TestL2004DelegationDepthLimit:
    """L2-004: Hard limit on delegation depth (> 5 forbidden)."""

    def test_deny_depth_6(self, layer2_forbid_depth):
        """Delegation at depth 6 is forbidden by hard limit."""
        entities = [
            make_agent_entity("orchestrator", trust_level=5, namespace="core"),
            make_agent_entity("finance-agent", trust_level=3, namespace="payments"),
        ]
        context = {
            "delegation_depth": 6,
            "target_capabilities": ["process_payment"],
            "requested_capabilities": ["process_payment"],
        }
        request = make_delegate_request("orchestrator", "finance-agent", context)
        result = cedarpy.is_authorized(request, layer2_forbid_depth, entities)
        assert result.allowed is False

    def test_deny_depth_100(self, layer2_forbid_depth):
        """Extreme delegation depth is forbidden."""
        entities = [
            make_agent_entity("orchestrator", trust_level=5, namespace="core"),
            make_agent_entity("data-bot", trust_level=4, namespace="data"),
        ]
        context = {
            "delegation_depth": 100,
            "target_capabilities": ["read_records"],
            "requested_capabilities": ["read_records"],
        }
        request = make_delegate_request("orchestrator", "data-bot", context)
        result = cedarpy.is_authorized(request, layer2_forbid_depth, entities)
        assert result.allowed is False

    def test_no_forbid_at_depth_5(self, layer2_forbid_depth):
        """Depth exactly 5 does NOT trigger the hard limit forbid.

        Note: L2-004 only forbids depth > 5. At depth 5, this forbid
        does not fire, so Cedar's default (no matching policy) is deny.
        """
        entities = [
            make_agent_entity("orchestrator", trust_level=5, namespace="core"),
            make_agent_entity("finance-agent", trust_level=3, namespace="payments"),
        ]
        context = {
            "delegation_depth": 5,
            "target_capabilities": ["process_payment"],
            "requested_capabilities": ["process_payment"],
        }
        request = make_delegate_request("orchestrator", "finance-agent", context)
        # L2-004 alone: forbid only fires when depth > 5.
        # At depth 5, no policy matches → Cedar default deny.
        result = cedarpy.is_authorized(request, layer2_forbid_depth, entities)
        assert result.allowed is False


# ── L2-999: Default deny delegation ──────────────────────────────


class TestL2999DefaultDenyDelegation:
    """L2-999: Default deny for all unmatched delegation requests."""

    def test_deny_non_orchestrator(self, layer2_deny_policy):
        """Non-orchestrator agent is denied delegation."""
        entities = [
            make_agent_entity("finance-agent", trust_level=3, namespace="payments"),
            make_agent_entity("data-bot", trust_level=4, namespace="data"),
        ]
        context = {
            "delegation_depth": 1,
            "target_capabilities": ["read_records"],
            "requested_capabilities": ["read_records"],
        }
        request = make_delegate_request("finance-agent", "data-bot", context)
        result = cedarpy.is_authorized(request, layer2_deny_policy, entities)
        assert result.allowed is False

    def test_deny_unknown_target(self, layer2_deny_policy):
        """Delegation to unknown agent is denied."""
        entities = [
            make_agent_entity("orchestrator", trust_level=5, namespace="core"),
            make_agent_entity("rogue-agent", trust_level=1, namespace="unknown"),
        ]
        context = {
            "delegation_depth": 1,
            "target_capabilities": [],
            "requested_capabilities": [],
        }
        request = make_delegate_request("orchestrator", "rogue-agent", context)
        result = cedarpy.is_authorized(request, layer2_deny_policy, entities)
        assert result.allowed is False
