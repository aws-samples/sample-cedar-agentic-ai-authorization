# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""End-to-end tests against the deployed API Gateway.

Sends real MCP requests to the deployed API endpoint and verifies
the Cedar policy evaluation results match expected outcomes for
the three blog walkthrough scenarios.
"""

from __future__ import annotations

import json
import os
import uuid

import boto3
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials
import requests

import pytest


# ---------------------------------------------------------------------------
# Configuration
# Set API_ENDPOINT environment variable after deployment
# ---------------------------------------------------------------------------

API_ENDPOINT = os.environ.get(
    "API_ENDPOINT",
    "https://<your-api-id>.execute-api.us-east-1.amazonaws.com/prod/evaluate",
)
REGION = "us-east-1"


def _sign_request(url: str, body: str) -> dict:
    """Sign an HTTP request with SigV4 for IAM-authorized API Gateway."""
    session = boto3.Session()
    credentials = session.get_credentials().get_frozen_credentials()

    request = AWSRequest(
        method="POST",
        url=url,
        data=body,
        headers={"Content-Type": "application/json"},
    )
    SigV4Auth(credentials, "execute-api", REGION).add_auth(request)
    return dict(request.headers)


def _make_mcp_request(
    tool_name: str = "delete_records",
    agent_id: str = "data-bot",
    trust_level: int = 4,
    namespace: str = "data",
    lifecycle_stage: str = "production",
    user_role: str = "admin",
    mfa_verified: bool = True,
    delegation_depth: int = 1,
    registered_capabilities: list | None = None,
) -> dict:
    """Build a valid MCP JSON-RPC 2.0 tool call message."""
    if registered_capabilities is None:
        registered_capabilities = [tool_name]
    return {
        "jsonrpc": "2.0",
        "id": str(uuid.uuid4()),
        "method": "tools/call",
        "params": {
            "name": tool_name,
            "arguments": {"record_id": "rec-e2e-001"},
            "_meta": {
                "agent_id": agent_id,
                "trust_level": trust_level,
                "namespace": namespace,
                "lifecycle_stage": lifecycle_stage,
                "registered_capabilities": registered_capabilities,
                "user_context": {
                    "user_id": "user-e2e-001",
                    "role": user_role,
                    "mfa_verified": mfa_verified,
                    "authentication_method": "sso",
                    "session_id": "sess-e2e-001",
                },
                "delegation_chain": [
                    {
                        "hop": 0,
                        "agent_id": "orchestrator",
                        "capabilities_granted": registered_capabilities,
                        "timestamp": "2026-04-13T12:00:00Z",
                    }
                ],
                "delegation_depth": delegation_depth,
            },
        },
    }


def _send_request(mcp_body: dict) -> dict:
    """Send a signed request to the deployed API and return the response."""
    body_str = json.dumps(mcp_body)
    headers = _sign_request(API_ENDPOINT, body_str)
    resp = requests.post(API_ENDPOINT, data=body_str, headers=headers, timeout=30)
    return {"status_code": resp.status_code, "body": resp.json()}


# ---------------------------------------------------------------------------
# E2E Tests
# ---------------------------------------------------------------------------


class TestScenarioAPrivilegeEscalation:
    """Scenario A: Support user → data-bot → delete_records → DENY at L3."""

    def test_support_user_delete_records_denied(self):
        """Support user trying to delete records is denied by L3."""
        mcp = _make_mcp_request(
            tool_name="delete_records",
            agent_id="data-bot",
            trust_level=4,
            namespace="data",
            user_role="support",
            mfa_verified=False,
            delegation_depth=1,
        )
        result = _send_request(mcp)
        print(f"Response: {json.dumps(result, indent=2)}")

        assert result["status_code"] == 200
        body = result["body"]
        assert body["decision"] == "DENY"
        assert body["denying_layer"] == "L3"


class TestScenarioBLegitimateAdmin:
    """Scenario B: Admin + MFA → data-bot → delete_records → PERMIT."""

    def test_admin_mfa_delete_records_permitted(self):
        """Admin with MFA can delete records through all three layers."""
        mcp = _make_mcp_request(
            tool_name="delete_records",
            agent_id="data-bot",
            trust_level=4,
            namespace="data",
            user_role="admin",
            mfa_verified=True,
            delegation_depth=1,
        )
        result = _send_request(mcp)
        print(f"Response: {json.dumps(result, indent=2)}")

        assert result["status_code"] == 200
        body = result["body"]
        assert body["decision"] == "PERMIT"


class TestScenarioCDelegationDepth:
    """Scenario C: Delegation depth > 5 → DENY at L2."""

    def test_deep_delegation_denied(self):
        """Delegation depth 6 is denied by L2 hard limit."""
        mcp = _make_mcp_request(
            tool_name="delete_records",
            agent_id="data-bot",
            trust_level=4,
            namespace="data",
            user_role="admin",
            mfa_verified=True,
            delegation_depth=6,
        )
        result = _send_request(mcp)
        print(f"Response: {json.dumps(result, indent=2)}")

        assert result["status_code"] == 200
        body = result["body"]
        assert body["decision"] == "DENY"
        assert body["denying_layer"] == "L2"


class TestAdditionalScenarios:
    """Additional E2E scenarios for coverage."""

    def test_finance_agent_payment_admin_permitted(self):
        """Admin + MFA + finance-agent → process_payment → PERMIT."""
        mcp = _make_mcp_request(
            tool_name="process_payment",
            agent_id="finance-agent",
            trust_level=3,
            namespace="payments",
            user_role="admin",
            mfa_verified=True,
            delegation_depth=1,
            registered_capabilities=["process_payment"],
        )
        result = _send_request(mcp)
        print(f"Response: {json.dumps(result, indent=2)}")

        assert result["status_code"] == 200
        body = result["body"]
        assert body["decision"] == "PERMIT"

    def test_unknown_agent_denied_at_l1(self):
        """Unknown agent is denied at L1."""
        mcp = _make_mcp_request(
            tool_name="delete_records",
            agent_id="rogue-agent",
            trust_level=5,
            namespace="data",
            user_role="admin",
            mfa_verified=True,
            delegation_depth=1,
        )
        result = _send_request(mcp)
        print(f"Response: {json.dumps(result, indent=2)}")

        assert result["status_code"] == 200
        body = result["body"]
        assert body["decision"] == "DENY"
        assert body["denying_layer"] == "L1"

    def test_support_agent_read_tickets_permitted(self):
        """Support user + support-agent → read_tickets → PERMIT."""
        mcp = _make_mcp_request(
            tool_name="read_tickets",
            agent_id="support-agent",
            trust_level=1,
            namespace="support",
            user_role="support",
            mfa_verified=False,
            delegation_depth=1,
            registered_capabilities=["read_tickets"],
        )
        result = _send_request(mcp)
        print(f"Response: {json.dumps(result, indent=2)}")

        assert result["status_code"] == 200
        body = result["body"]
        assert body["decision"] == "PERMIT"
