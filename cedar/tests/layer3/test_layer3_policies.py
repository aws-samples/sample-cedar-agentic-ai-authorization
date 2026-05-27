# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Unit tests for Layer 3 (originating user auth) Cedar policies.

Tests verify:
- L3-001 through L3-005 permit correct user role/MFA combinations
- L3-999 denies when originating user context is missing

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
    make_invoke_request,
    make_tool_entity,
)


def _user_context(
    role: str = "admin",
    mfa_verified: bool = True,
    user_id: str = "user-001",
    authentication_method: str = "sso",
    session_id: str = "sess-001",
) -> dict:
    """Build an originating_user context dict."""
    return {
        "user_id": user_id,
        "role": role,
        "mfa_verified": mfa_verified,
        "authentication_method": authentication_method,
        "session_id": session_id,
    }


# ── L3-001: delete_records requires admin + MFA ──────────────────


class TestL3001AdminDeleteRecords:
    """L3-001: High-risk tool requires admin + MFA + depth <= 2."""

    def test_permit_admin_mfa_low_depth(self, layer3_permit_policies):
        """Admin with MFA at depth 1 can delete records."""
        entities = [
            make_agent_entity("data-bot", trust_level=4, namespace="data"),
            make_tool_entity("delete_records", namespace="data", risk_level="critical"),
        ]
        context = {
            "originating_user": _user_context(role="admin", mfa_verified=True),
            "delegation_depth": 1,
        }
        request = make_invoke_request("data-bot", "delete_records", context)
        result = cedarpy.is_authorized(request, layer3_permit_policies, entities)
        assert result.allowed is True

    def test_deny_non_admin_role(self, layer3_permit_policies):
        """Support user cannot delete records even with MFA."""
        entities = [
            make_agent_entity("data-bot", trust_level=4, namespace="data"),
            make_tool_entity("delete_records", namespace="data", risk_level="critical"),
        ]
        context = {
            "originating_user": _user_context(role="support", mfa_verified=True),
            "delegation_depth": 1,
        }
        request = make_invoke_request("data-bot", "delete_records", context)
        result = cedarpy.is_authorized(request, layer3_permit_policies, entities)
        assert result.allowed is False

    def test_deny_no_mfa(self, layer3_permit_policies):
        """Admin without MFA cannot delete records."""
        entities = [
            make_agent_entity("data-bot", trust_level=4, namespace="data"),
            make_tool_entity("delete_records", namespace="data", risk_level="critical"),
        ]
        context = {
            "originating_user": _user_context(role="admin", mfa_verified=False),
            "delegation_depth": 1,
        }
        request = make_invoke_request("data-bot", "delete_records", context)
        result = cedarpy.is_authorized(request, layer3_permit_policies, entities)
        assert result.allowed is False

    def test_deny_depth_exceeds_limit(self, layer3_permit_policies):
        """Admin with MFA denied when depth > 2."""
        entities = [
            make_agent_entity("data-bot", trust_level=4, namespace="data"),
            make_tool_entity("delete_records", namespace="data", risk_level="critical"),
        ]
        context = {
            "originating_user": _user_context(role="admin", mfa_verified=True),
            "delegation_depth": 3,
        }
        request = make_invoke_request("data-bot", "delete_records", context)
        result = cedarpy.is_authorized(request, layer3_permit_policies, entities)
        assert result.allowed is False

    def test_permit_at_depth_boundary(self, layer3_permit_policies):
        """Admin with MFA permitted at exactly depth 2."""
        entities = [
            make_agent_entity("data-bot", trust_level=4, namespace="data"),
            make_tool_entity("delete_records", namespace="data", risk_level="critical"),
        ]
        context = {
            "originating_user": _user_context(role="admin", mfa_verified=True),
            "delegation_depth": 2,
        }
        request = make_invoke_request("data-bot", "delete_records", context)
        result = cedarpy.is_authorized(request, layer3_permit_policies, entities)
        assert result.allowed is True


# ── L3-002: process_payment requires admin/finance_manager + MFA ─


class TestL3002FinancePayments:
    """L3-002: Payment processing requires admin or finance_manager + MFA."""

    def test_permit_admin_mfa(self, layer3_permit_policies):
        """Admin with MFA can process payments."""
        entities = [
            make_agent_entity("finance-agent", trust_level=3, namespace="payments"),
            make_tool_entity("process_payment", namespace="payments", risk_level="high"),
        ]
        context = {
            "originating_user": _user_context(role="admin", mfa_verified=True),
            "delegation_depth": 1,
        }
        request = make_invoke_request("finance-agent", "process_payment", context)
        result = cedarpy.is_authorized(request, layer3_permit_policies, entities)
        assert result.allowed is True

    def test_permit_finance_manager_mfa(self, layer3_permit_policies):
        """Finance manager with MFA can process payments."""
        entities = [
            make_agent_entity("finance-agent", trust_level=3, namespace="payments"),
            make_tool_entity("process_payment", namespace="payments", risk_level="high"),
        ]
        context = {
            "originating_user": _user_context(role="finance_manager", mfa_verified=True),
            "delegation_depth": 1,
        }
        request = make_invoke_request("finance-agent", "process_payment", context)
        result = cedarpy.is_authorized(request, layer3_permit_policies, entities)
        assert result.allowed is True

    def test_deny_support_role(self, layer3_permit_policies):
        """Support user cannot process payments."""
        entities = [
            make_agent_entity("finance-agent", trust_level=3, namespace="payments"),
            make_tool_entity("process_payment", namespace="payments", risk_level="high"),
        ]
        context = {
            "originating_user": _user_context(role="support", mfa_verified=True),
            "delegation_depth": 1,
        }
        request = make_invoke_request("finance-agent", "process_payment", context)
        result = cedarpy.is_authorized(request, layer3_permit_policies, entities)
        assert result.allowed is False

    def test_deny_no_mfa(self, layer3_permit_policies):
        """Admin without MFA cannot process payments."""
        entities = [
            make_agent_entity("finance-agent", trust_level=3, namespace="payments"),
            make_tool_entity("process_payment", namespace="payments", risk_level="high"),
        ]
        context = {
            "originating_user": _user_context(role="admin", mfa_verified=False),
            "delegation_depth": 1,
        }
        request = make_invoke_request("finance-agent", "process_payment", context)
        result = cedarpy.is_authorized(request, layer3_permit_policies, entities)
        assert result.allowed is False

    def test_deny_depth_exceeds_limit(self, layer3_permit_policies):
        """Admin with MFA denied when depth > 3."""
        entities = [
            make_agent_entity("finance-agent", trust_level=3, namespace="payments"),
            make_tool_entity("process_payment", namespace="payments", risk_level="high"),
        ]
        context = {
            "originating_user": _user_context(role="admin", mfa_verified=True),
            "delegation_depth": 4,
        }
        request = make_invoke_request("finance-agent", "process_payment", context)
        result = cedarpy.is_authorized(request, layer3_permit_policies, entities)
        assert result.allowed is False


# ── L3-003: process_refund requires finance roles + MFA ──────────


class TestL3003FinanceRefunds:
    """L3-003: Refund processing requires admin/finance_manager/support_lead + MFA."""

    def test_permit_admin_mfa(self, layer3_permit_policies):
        """Admin with MFA can process refunds."""
        entities = [
            make_agent_entity("finance-agent", trust_level=3, namespace="payments"),
            make_tool_entity("process_refund", namespace="payments", risk_level="high"),
        ]
        context = {
            "originating_user": _user_context(role="admin", mfa_verified=True),
            "delegation_depth": 1,
        }
        request = make_invoke_request("finance-agent", "process_refund", context)
        result = cedarpy.is_authorized(request, layer3_permit_policies, entities)
        assert result.allowed is True

    def test_permit_support_lead_mfa(self, layer3_permit_policies):
        """Support lead with MFA can process refunds."""
        entities = [
            make_agent_entity("finance-agent", trust_level=3, namespace="payments"),
            make_tool_entity("process_refund", namespace="payments", risk_level="high"),
        ]
        context = {
            "originating_user": _user_context(role="support_lead", mfa_verified=True),
            "delegation_depth": 1,
        }
        request = make_invoke_request("finance-agent", "process_refund", context)
        result = cedarpy.is_authorized(request, layer3_permit_policies, entities)
        assert result.allowed is True

    def test_deny_analyst_role(self, layer3_permit_policies):
        """Analyst cannot process refunds."""
        entities = [
            make_agent_entity("finance-agent", trust_level=3, namespace="payments"),
            make_tool_entity("process_refund", namespace="payments", risk_level="high"),
        ]
        context = {
            "originating_user": _user_context(role="analyst", mfa_verified=True),
            "delegation_depth": 1,
        }
        request = make_invoke_request("finance-agent", "process_refund", context)
        result = cedarpy.is_authorized(request, layer3_permit_policies, entities)
        assert result.allowed is False

    def test_deny_no_mfa(self, layer3_permit_policies):
        """Finance manager without MFA cannot process refunds."""
        entities = [
            make_agent_entity("finance-agent", trust_level=3, namespace="payments"),
            make_tool_entity("process_refund", namespace="payments", risk_level="high"),
        ]
        context = {
            "originating_user": _user_context(role="finance_manager", mfa_verified=False),
            "delegation_depth": 1,
        }
        request = make_invoke_request("finance-agent", "process_refund", context)
        result = cedarpy.is_authorized(request, layer3_permit_policies, entities)
        assert result.allowed is False


# ── L3-004: read_records requires analyst role ───────────────────


class TestL3004AnalystReadRecords:
    """L3-004: Read records requires admin/analyst/data_engineer role."""

    def test_permit_analyst(self, layer3_permit_policies):
        """Analyst can read records (no MFA required)."""
        entities = [
            make_agent_entity("data-bot", trust_level=2, namespace="data"),
            make_tool_entity("read_records", namespace="data", risk_level="low"),
        ]
        context = {
            "originating_user": _user_context(role="analyst", mfa_verified=False),
            "delegation_depth": 1,
        }
        request = make_invoke_request("data-bot", "read_records", context)
        result = cedarpy.is_authorized(request, layer3_permit_policies, entities)
        assert result.allowed is True

    def test_permit_data_engineer(self, layer3_permit_policies):
        """Data engineer can read records."""
        entities = [
            make_agent_entity("data-bot", trust_level=2, namespace="data"),
            make_tool_entity("read_records", namespace="data", risk_level="low"),
        ]
        context = {
            "originating_user": _user_context(role="data_engineer", mfa_verified=False),
            "delegation_depth": 1,
        }
        request = make_invoke_request("data-bot", "read_records", context)
        result = cedarpy.is_authorized(request, layer3_permit_policies, entities)
        assert result.allowed is True

    def test_deny_support_role(self, layer3_permit_policies):
        """Support user cannot read records."""
        entities = [
            make_agent_entity("data-bot", trust_level=2, namespace="data"),
            make_tool_entity("read_records", namespace="data", risk_level="low"),
        ]
        context = {
            "originating_user": _user_context(role="support", mfa_verified=True),
            "delegation_depth": 1,
        }
        request = make_invoke_request("data-bot", "read_records", context)
        result = cedarpy.is_authorized(request, layer3_permit_policies, entities)
        assert result.allowed is False

    def test_deny_depth_exceeds_limit(self, layer3_permit_policies):
        """Analyst denied when depth > 3."""
        entities = [
            make_agent_entity("data-bot", trust_level=2, namespace="data"),
            make_tool_entity("read_records", namespace="data", risk_level="low"),
        ]
        context = {
            "originating_user": _user_context(role="analyst", mfa_verified=False),
            "delegation_depth": 4,
        }
        request = make_invoke_request("data-bot", "read_records", context)
        result = cedarpy.is_authorized(request, layer3_permit_policies, entities)
        assert result.allowed is False


# ── L3-005: read_tickets — relaxed for support roles ─────────────


class TestL3005SupportReadTickets:
    """L3-005: Read tickets relaxed for support roles."""

    def test_permit_support_role(self, layer3_permit_policies):
        """Support user can read tickets."""
        entities = [
            make_agent_entity("support-agent", trust_level=1, namespace="support"),
            make_tool_entity("read_tickets", namespace="support", risk_level="low"),
        ]
        context = {
            "originating_user": _user_context(role="support", mfa_verified=False),
            "delegation_depth": 1,
        }
        request = make_invoke_request("support-agent", "read_tickets", context)
        result = cedarpy.is_authorized(request, layer3_permit_policies, entities)
        assert result.allowed is True

    def test_permit_support_lead(self, layer3_permit_policies):
        """Support lead can read tickets."""
        entities = [
            make_agent_entity("support-agent", trust_level=1, namespace="support"),
            make_tool_entity("read_tickets", namespace="support", risk_level="low"),
        ]
        context = {
            "originating_user": _user_context(role="support_lead", mfa_verified=False),
            "delegation_depth": 1,
        }
        request = make_invoke_request("support-agent", "read_tickets", context)
        result = cedarpy.is_authorized(request, layer3_permit_policies, entities)
        assert result.allowed is True

    def test_permit_admin(self, layer3_permit_policies):
        """Admin can read tickets."""
        entities = [
            make_agent_entity("support-agent", trust_level=1, namespace="support"),
            make_tool_entity("read_tickets", namespace="support", risk_level="low"),
        ]
        context = {
            "originating_user": _user_context(role="admin", mfa_verified=False),
            "delegation_depth": 1,
        }
        request = make_invoke_request("support-agent", "read_tickets", context)
        result = cedarpy.is_authorized(request, layer3_permit_policies, entities)
        assert result.allowed is True

    def test_deny_analyst_role(self, layer3_permit_policies):
        """Analyst cannot read tickets."""
        entities = [
            make_agent_entity("support-agent", trust_level=1, namespace="support"),
            make_tool_entity("read_tickets", namespace="support", risk_level="low"),
        ]
        context = {
            "originating_user": _user_context(role="analyst", mfa_verified=False),
            "delegation_depth": 1,
        }
        request = make_invoke_request("support-agent", "read_tickets", context)
        result = cedarpy.is_authorized(request, layer3_permit_policies, entities)
        assert result.allowed is False

    def test_deny_depth_exceeds_limit(self, layer3_permit_policies):
        """Support user denied when depth > 2."""
        entities = [
            make_agent_entity("support-agent", trust_level=1, namespace="support"),
            make_tool_entity("read_tickets", namespace="support", risk_level="low"),
        ]
        context = {
            "originating_user": _user_context(role="support", mfa_verified=False),
            "delegation_depth": 3,
        }
        request = make_invoke_request("support-agent", "read_tickets", context)
        result = cedarpy.is_authorized(request, layer3_permit_policies, entities)
        assert result.allowed is False


# ── L3-999: Default deny when no originating user context ────────


class TestL3999DefaultDenyNoUser:
    """L3-999: Default deny when originating_user context is missing."""

    def test_deny_missing_user_context(self, layer3_deny_policy):
        """Request without originating_user is denied."""
        entities = [
            make_agent_entity("data-bot", trust_level=4, namespace="data"),
            make_tool_entity("delete_records", namespace="data", risk_level="critical"),
        ]
        # No originating_user in context
        context = {"delegation_depth": 1}
        request = make_invoke_request("data-bot", "delete_records", context)
        result = cedarpy.is_authorized(request, layer3_deny_policy, entities)
        assert result.allowed is False

    def test_deny_empty_context(self, layer3_deny_policy):
        """Request with empty context is denied (no originating_user)."""
        entities = [
            make_agent_entity("finance-agent", trust_level=3, namespace="payments"),
            make_tool_entity("process_payment", namespace="payments", risk_level="high"),
        ]
        request = make_invoke_request("finance-agent", "process_payment", {})
        result = cedarpy.is_authorized(request, layer3_deny_policy, entities)
        assert result.allowed is False

    def test_no_deny_when_user_present(self, layer3_deny_policy):
        """L3-999 forbid does NOT fire when originating_user is present.

        The forbid only triggers when !(context has originating_user).
        When user context is present, no policy matches → Cedar default deny.
        """
        entities = [
            make_agent_entity("data-bot", trust_level=4, namespace="data"),
            make_tool_entity("delete_records", namespace="data", risk_level="critical"),
        ]
        context = {
            "originating_user": _user_context(role="admin", mfa_verified=True),
            "delegation_depth": 1,
        }
        request = make_invoke_request("data-bot", "delete_records", context)
        # L3-999 alone: forbid only fires when originating_user is absent.
        # With user present, no policy matches → Cedar default deny (not forbid).
        result = cedarpy.is_authorized(request, layer3_deny_policy, entities)
        assert result.allowed is False
