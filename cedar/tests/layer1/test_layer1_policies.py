# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Unit tests for Layer 1 (agent-to-tool) Cedar policies.

Tests verify:
- L1-001 through L1-005 permit correct agent/tool pairs
- L1-999 denies unmatched requests

Requirements: 1.1, 1.2, 1.3
"""

import sys
from pathlib import Path

# Ensure helpers module is importable
_tests_dir = Path(__file__).resolve().parent.parent
if str(_tests_dir) not in sys.path:
    sys.path.insert(0, str(_tests_dir))

import cedarpy

from helpers import (
    make_agent_entity,
    make_invoke_request,
    make_tool_entity,
)


# ── L1-001: finance-agent → process_payment ──────────────────────


class TestL1001FinancePayments:
    """L1-001: Finance agent can invoke payment tools."""

    def test_permit_finance_agent_process_payment(self, layer1_permit_policies):
        """Finance agent with correct attrs can invoke process_payment."""
        entities = [
            make_agent_entity("finance-agent", trust_level=3, namespace="payments", lifecycle_stage="production"),
            make_tool_entity("process_payment", namespace="payments", risk_level="high"),
        ]
        request = make_invoke_request("finance-agent", "process_payment")
        result = cedarpy.is_authorized(request, layer1_permit_policies, entities)
        assert result.allowed is True

    def test_deny_low_trust_level(self, layer1_permit_policies):
        """Finance agent with trust_level < 3 is denied."""
        entities = [
            make_agent_entity("finance-agent", trust_level=2, namespace="payments", lifecycle_stage="production"),
            make_tool_entity("process_payment", namespace="payments", risk_level="high"),
        ]
        request = make_invoke_request("finance-agent", "process_payment")
        result = cedarpy.is_authorized(request, layer1_permit_policies, entities)
        assert result.allowed is False

    def test_deny_wrong_namespace(self, layer1_permit_policies):
        """Finance agent with wrong namespace is denied."""
        entities = [
            make_agent_entity("finance-agent", trust_level=3, namespace="data", lifecycle_stage="production"),
            make_tool_entity("process_payment", namespace="payments", risk_level="high"),
        ]
        request = make_invoke_request("finance-agent", "process_payment")
        result = cedarpy.is_authorized(request, layer1_permit_policies, entities)
        assert result.allowed is False

    def test_deny_non_production(self, layer1_permit_policies):
        """Finance agent not in production lifecycle is denied."""
        entities = [
            make_agent_entity("finance-agent", trust_level=3, namespace="payments", lifecycle_stage="staging"),
            make_tool_entity("process_payment", namespace="payments", risk_level="high"),
        ]
        request = make_invoke_request("finance-agent", "process_payment")
        result = cedarpy.is_authorized(request, layer1_permit_policies, entities)
        assert result.allowed is False


# ── L1-002: finance-agent → process_refund ───────────────────────


class TestL1002FinanceRefunds:
    """L1-002: Finance agent can invoke refund tools."""

    def test_permit_finance_agent_process_refund(self, layer1_permit_policies):
        """Finance agent with correct attrs can invoke process_refund."""
        entities = [
            make_agent_entity("finance-agent", trust_level=3, namespace="payments", lifecycle_stage="production"),
            make_tool_entity("process_refund", namespace="payments", risk_level="high"),
        ]
        request = make_invoke_request("finance-agent", "process_refund")
        result = cedarpy.is_authorized(request, layer1_permit_policies, entities)
        assert result.allowed is True

    def test_deny_low_trust_level(self, layer1_permit_policies):
        """Finance agent with trust_level < 3 is denied for refunds."""
        entities = [
            make_agent_entity("finance-agent", trust_level=2, namespace="payments", lifecycle_stage="production"),
            make_tool_entity("process_refund", namespace="payments", risk_level="high"),
        ]
        request = make_invoke_request("finance-agent", "process_refund")
        result = cedarpy.is_authorized(request, layer1_permit_policies, entities)
        assert result.allowed is False


# ── L1-003: data-bot → read_records ──────────────────────────────


class TestL1003DataRead:
    """L1-003: Data agent can read records."""

    def test_permit_data_bot_read_records(self, layer1_permit_policies):
        """Data-bot with correct attrs can invoke read_records."""
        entities = [
            make_agent_entity("data-bot", trust_level=2, namespace="data", lifecycle_stage="production"),
            make_tool_entity("read_records", namespace="data", risk_level="low"),
        ]
        request = make_invoke_request("data-bot", "read_records")
        result = cedarpy.is_authorized(request, layer1_permit_policies, entities)
        assert result.allowed is True

    def test_deny_low_trust_level(self, layer1_permit_policies):
        """Data-bot with trust_level < 2 is denied."""
        entities = [
            make_agent_entity("data-bot", trust_level=1, namespace="data", lifecycle_stage="production"),
            make_tool_entity("read_records", namespace="data", risk_level="low"),
        ]
        request = make_invoke_request("data-bot", "read_records")
        result = cedarpy.is_authorized(request, layer1_permit_policies, entities)
        assert result.allowed is False

    def test_deny_wrong_namespace(self, layer1_permit_policies):
        """Data-bot with wrong namespace is denied."""
        entities = [
            make_agent_entity("data-bot", trust_level=2, namespace="payments", lifecycle_stage="production"),
            make_tool_entity("read_records", namespace="data", risk_level="low"),
        ]
        request = make_invoke_request("data-bot", "read_records")
        result = cedarpy.is_authorized(request, layer1_permit_policies, entities)
        assert result.allowed is False


# ── L1-004: data-bot → delete_records (high-risk) ────────────────


class TestL1004DataDelete:
    """L1-004: Data agent can delete records (high-risk)."""

    def test_permit_data_bot_delete_records(self, layer1_permit_policies):
        """Data-bot with trust_level >= 4 and correct attrs can delete."""
        entities = [
            make_agent_entity("data-bot", trust_level=4, namespace="data", lifecycle_stage="production"),
            make_tool_entity("delete_records", namespace="data", risk_level="critical"),
        ]
        request = make_invoke_request("data-bot", "delete_records")
        result = cedarpy.is_authorized(request, layer1_permit_policies, entities)
        assert result.allowed is True

    def test_deny_trust_level_3(self, layer1_permit_policies):
        """Data-bot with trust_level 3 (< 4) is denied for delete."""
        entities = [
            make_agent_entity("data-bot", trust_level=3, namespace="data", lifecycle_stage="production"),
            make_tool_entity("delete_records", namespace="data", risk_level="critical"),
        ]
        request = make_invoke_request("data-bot", "delete_records")
        result = cedarpy.is_authorized(request, layer1_permit_policies, entities)
        assert result.allowed is False

    def test_deny_non_production(self, layer1_permit_policies):
        """Data-bot not in production is denied for delete."""
        entities = [
            make_agent_entity("data-bot", trust_level=4, namespace="data", lifecycle_stage="staging"),
            make_tool_entity("delete_records", namespace="data", risk_level="critical"),
        ]
        request = make_invoke_request("data-bot", "delete_records")
        result = cedarpy.is_authorized(request, layer1_permit_policies, entities)
        assert result.allowed is False


# ── L1-005: support-agent → read_tickets ─────────────────────────


class TestL1005SupportTickets:
    """L1-005: Support agent can read tickets."""

    def test_permit_support_agent_read_tickets(self, layer1_permit_policies):
        """Support agent with correct attrs can read tickets."""
        entities = [
            make_agent_entity("support-agent", trust_level=1, namespace="support", lifecycle_stage="production"),
            make_tool_entity("read_tickets", namespace="support", risk_level="low"),
        ]
        request = make_invoke_request("support-agent", "read_tickets")
        result = cedarpy.is_authorized(request, layer1_permit_policies, entities)
        assert result.allowed is True

    def test_deny_wrong_namespace(self, layer1_permit_policies):
        """Support agent with wrong namespace is denied."""
        entities = [
            make_agent_entity("support-agent", trust_level=1, namespace="data", lifecycle_stage="production"),
            make_tool_entity("read_tickets", namespace="support", risk_level="low"),
        ]
        request = make_invoke_request("support-agent", "read_tickets")
        result = cedarpy.is_authorized(request, layer1_permit_policies, entities)
        assert result.allowed is False


# ── L1-999: Default deny ─────────────────────────────────────────


class TestL1999DefaultDeny:
    """L1-999: Default deny for unmatched invoke_tool requests."""

    def test_deny_unknown_agent(self, layer1_deny_policy):
        """Unknown agent is denied by default deny."""
        entities = [
            make_agent_entity("rogue-agent", trust_level=5, namespace="payments", lifecycle_stage="production"),
            make_tool_entity("process_payment", namespace="payments", risk_level="high"),
        ]
        request = make_invoke_request("rogue-agent", "process_payment")
        result = cedarpy.is_authorized(request, layer1_deny_policy, entities)
        assert result.allowed is False

    def test_deny_unknown_tool(self, layer1_deny_policy):
        """Known agent invoking unknown tool is denied."""
        entities = [
            make_agent_entity("finance-agent", trust_level=3, namespace="payments", lifecycle_stage="production"),
            make_tool_entity("unknown_tool", namespace="unknown", risk_level="low"),
        ]
        request = make_invoke_request("finance-agent", "unknown_tool")
        result = cedarpy.is_authorized(request, layer1_deny_policy, entities)
        assert result.allowed is False

    def test_deny_cross_agent_tool(self, layer1_deny_policy):
        """Agent trying to use another agent's tool is denied."""
        entities = [
            make_agent_entity("support-agent", trust_level=1, namespace="support", lifecycle_stage="production"),
            make_tool_entity("process_payment", namespace="payments", risk_level="high"),
        ]
        request = make_invoke_request("support-agent", "process_payment")
        result = cedarpy.is_authorized(request, layer1_deny_policy, entities)
        assert result.allowed is False
