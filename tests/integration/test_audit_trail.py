# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Integration tests for audit trail.

Verifies that every policy evaluation (permit and deny) produces an
OCSF 99001 event with all required fields, and that Amazon CloudWatch metrics
are emitted for each evaluation.

Uses the real Cedar policy evaluation engine and OCSF event builder,
with mocked Amazon CloudWatch and SQS clients.

Validates: Requirements 4.1, 4.2, 4.4
"""

from __future__ import annotations

import importlib
import json
from dataclasses import asdict
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch, call

import pytest

_evaluator_mod = importlib.import_module("cedar_evaluator.policy_evaluator")
_audit_mod = importlib.import_module("cedar_evaluator.audit_emitter")
_ocsf_mod = importlib.import_module("shared.ocsf_event_builder")
_types_mod = importlib.import_module("shared.types")

evaluate = _evaluator_mod.evaluate
reset_cache = _evaluator_mod.reset_cache
emit_audit_event = _audit_mod.emit_audit_event
build_ocsf_event = _ocsf_mod.build_ocsf_event
Decision = _types_mod.Decision


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_envelope(
    agent_id: str = "data-bot",
    trust_level: int = 4,
    namespace: str = "data",
    lifecycle_stage: str = "production",
    target_resource: str = "delete_records",
    delegation_depth: int = 1,
    user_role: str = "admin",
    mfa_verified: bool = True,
    user_id: str = "user-audit-001",
    session_id: str = "sess-audit-001",
    delegation_chain: list | None = None,
) -> dict:
    """Build a Request Envelope for audit trail tests."""
    if delegation_chain is None:
        delegation_chain = [
            {
                "hop": 0,
                "agent_id": "orchestrator",
                "capabilities_granted": [target_resource],
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
            "registered_capabilities": [target_resource],
            "lifecycle_stage": lifecycle_stage,
        },
        "action": {
            "type": "invoke_tool",
            "target_resource": target_resource,
            "requested_capabilities": [target_resource],
        },
        "delegation_chain": delegation_chain,
        "delegation_depth": delegation_depth,
        "originating_user": {
            "user_id": user_id,
            "role": user_role,
            "mfa_verified": mfa_verified,
            "authentication_method": "sso",
            "session_id": session_id,
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


@pytest.fixture()
def mock_aws_clients():
    """Mock all AWS clients used by audit_emitter."""
    mock_logs = MagicMock()
    mock_cw = MagicMock()
    mock_sqs = MagicMock()

    _audit_mod.reset_clients()

    with patch.object(_audit_mod, "_get_logs_client", return_value=mock_logs), \
         patch.object(_audit_mod, "_get_cw_client", return_value=mock_cw), \
         patch.object(_audit_mod, "_get_sqs_client", return_value=mock_sqs):
        yield {
            "logs": mock_logs,
            "cloudwatch": mock_cw,
            "sqs": mock_sqs,
        }

    _audit_mod.reset_clients()


# ---------------------------------------------------------------------------
# OCSF 99001 event completeness tests
# ---------------------------------------------------------------------------


class TestOcsfEventOnPermit:
    """Verify PERMIT evaluation produces OCSF 99001 event with all fields.

    Validates: Requirements 4.1, 4.2
    """

    def test_permit_produces_ocsf_99001_event(self):
        """PERMIT decision → OCSF event with class_uid 99001."""
        envelope = _make_envelope(
            user_role="admin",
            mfa_verified=True,
            user_id="user-permit-001",
            session_id="sess-permit-001",
        )
        decision = evaluate(envelope)
        assert decision.decision == Decision.PERMIT

        ocsf = build_ocsf_event(envelope, decision, evaluation_latency_ms=0.5)

        assert ocsf.class_uid == 99001
        assert ocsf.class_name == "Agent Policy Evaluation"
        assert ocsf.category_uid == 3
        assert ocsf.activity_id == 1

    def test_permit_ocsf_has_actor_fields(self):
        """PERMIT OCSF event includes actor (user + session)."""
        envelope = _make_envelope(
            user_id="user-actor-test",
            user_role="admin",
            mfa_verified=True,
            session_id="sess-actor-test",
        )
        decision = evaluate(envelope)
        ocsf = build_ocsf_event(envelope, decision, evaluation_latency_ms=0.3)

        assert ocsf.actor.user.uid == "user-actor-test"
        assert ocsf.actor.user.role == "admin"
        assert ocsf.actor.user.mfa_enabled is True
        assert ocsf.actor.session.uid == "sess-actor-test"

    def test_permit_ocsf_has_agent_list(self):
        """PERMIT OCSF event includes delegation chain agents."""
        envelope = _make_envelope(
            delegation_chain=[
                {
                    "hop": 0,
                    "agent_id": "orchestrator",
                    "capabilities_granted": ["delete_records"],
                    "timestamp": "2026-04-13T12:00:00Z",
                }
            ],
        )
        decision = evaluate(envelope)
        ocsf = build_ocsf_event(envelope, decision, evaluation_latency_ms=0.4)

        agent_ids = [a.uid for a in ocsf.src_endpoint.agent_list]
        assert "orchestrator" in agent_ids
        assert "data-bot" in agent_ids  # source agent appended

    def test_permit_ocsf_has_authorization_decision(self):
        """PERMIT OCSF event has authorization.decision = 'Permitted'."""
        envelope = _make_envelope(user_role="admin", mfa_verified=True)
        decision = evaluate(envelope)
        ocsf = build_ocsf_event(envelope, decision, evaluation_latency_ms=0.5)

        assert ocsf.authorization.decision == "Permitted"

    def test_permit_ocsf_has_resource(self):
        """PERMIT OCSF event includes the target resource."""
        envelope = _make_envelope(target_resource="delete_records")
        decision = evaluate(envelope)
        ocsf = build_ocsf_event(envelope, decision, evaluation_latency_ms=0.5)

        assert len(ocsf.resources) == 1
        assert ocsf.resources[0].type == "Tool"
        assert "delete_records" in ocsf.resources[0].name

    def test_permit_ocsf_has_unmapped_fields(self):
        """PERMIT OCSF event has all unmapped fields."""
        envelope = _make_envelope(
            delegation_depth=1,
            user_role="admin",
            mfa_verified=True,
        )
        decision = evaluate(envelope)
        ocsf = build_ocsf_event(envelope, decision, evaluation_latency_ms=0.6)

        assert ocsf.unmapped.delegation_depth == 1
        assert ocsf.unmapped.request_id == envelope["request_id"]
        assert ocsf.unmapped.evaluation_latency_ms == 0.6
        assert ocsf.unmapped.content_filter_score == 0
        assert ocsf.unmapped.layer_results == {
            "L1": "PERMIT",
            "L2": "PERMIT",
            "L3": "PERMIT",
        }
        assert ocsf.unmapped.denying_layer is None

    def test_permit_ocsf_has_metadata(self):
        """PERMIT OCSF event has metadata with product info."""
        envelope = _make_envelope(user_role="admin", mfa_verified=True)
        decision = evaluate(envelope)
        ocsf = build_ocsf_event(envelope, decision, evaluation_latency_ms=0.5)

        assert ocsf.metadata.version == "1.3.0"
        assert ocsf.metadata.product.name == "AgentAuthzProtection"
        assert ocsf.metadata.product.vendor_name == "Custom"

    def test_permit_ocsf_has_timestamp(self):
        """PERMIT OCSF event has a valid ISO timestamp."""
        envelope = _make_envelope(user_role="admin", mfa_verified=True)
        decision = evaluate(envelope)
        ocsf = build_ocsf_event(envelope, decision, evaluation_latency_ms=0.5)

        assert ocsf.time  # non-empty
        assert "T" in ocsf.time  # ISO format


class TestOcsfEventOnDeny:
    """Verify DENY evaluation produces OCSF 99001 event with all fields.

    Validates: Requirements 4.1, 4.2
    """

    def test_deny_produces_ocsf_99001_event(self):
        """DENY decision → OCSF event with class_uid 99001."""
        envelope = _make_envelope(
            user_role="support",
            mfa_verified=False,
        )
        decision = evaluate(envelope)
        assert decision.decision == Decision.DENY

        ocsf = build_ocsf_event(envelope, decision, evaluation_latency_ms=0.4)

        assert ocsf.class_uid == 99001
        assert ocsf.class_name == "Agent Policy Evaluation"

    def test_deny_ocsf_has_denied_authorization(self):
        """DENY OCSF event has authorization.decision = 'Denied'."""
        envelope = _make_envelope(user_role="support", mfa_verified=False)
        decision = evaluate(envelope)
        ocsf = build_ocsf_event(envelope, decision, evaluation_latency_ms=0.4)

        assert ocsf.authorization.decision == "Denied"

    def test_deny_ocsf_has_denying_layer(self):
        """DENY OCSF event includes the denying layer in unmapped."""
        envelope = _make_envelope(user_role="support", mfa_verified=False)
        decision = evaluate(envelope)
        ocsf = build_ocsf_event(envelope, decision, evaluation_latency_ms=0.4)

        assert ocsf.unmapped.denying_layer == "L3"
        assert ocsf.unmapped.layer_results["L1"] == "PERMIT"
        assert ocsf.unmapped.layer_results["L3"] == "DENY"

    def test_deny_ocsf_has_higher_severity(self):
        """DENY OCSF event has severity_id > 1 (elevated)."""
        envelope = _make_envelope(user_role="support", mfa_verified=False)
        decision = evaluate(envelope)
        ocsf = build_ocsf_event(envelope, decision, evaluation_latency_ms=0.4)

        assert ocsf.severity_id > 1

    def test_deny_ocsf_has_all_required_fields(self):
        """DENY OCSF event has all required fields populated."""
        envelope = _make_envelope(
            user_role="support",
            mfa_verified=False,
            user_id="user-deny-check",
            session_id="sess-deny-check",
        )
        decision = evaluate(envelope)
        ocsf = build_ocsf_event(envelope, decision, evaluation_latency_ms=0.7)

        # Actor
        assert ocsf.actor.user.uid == "user-deny-check"
        assert ocsf.actor.session.uid == "sess-deny-check"
        # Resource
        assert len(ocsf.resources) >= 1
        # Unmapped
        assert ocsf.unmapped.request_id == envelope["request_id"]
        assert ocsf.unmapped.evaluation_latency_ms == 0.7
        # Timestamp
        assert ocsf.time


# ---------------------------------------------------------------------------
# Amazon CloudWatch metrics emission tests
# ---------------------------------------------------------------------------


class TestCloudWatchMetricsEmission:
    """Verify Amazon CloudWatch metrics are emitted for each evaluation.

    Validates: Requirements 4.4
    """

    def test_permit_emits_cloudwatch_logs_and_metrics(self, mock_aws_clients):
        """PERMIT evaluation emits to Amazon CloudWatch Logs and publishes metrics."""
        envelope = _make_envelope(user_role="admin", mfa_verified=True)
        decision = evaluate(envelope)
        assert decision.decision == Decision.PERMIT

        emit_audit_event(envelope, decision, evaluation_latency_ms=0.5)

        # Amazon CloudWatch Logs should have been called
        mock_aws_clients["logs"].put_log_events.assert_called_once()
        log_call = mock_aws_clients["logs"].put_log_events.call_args
        log_events = log_call.kwargs.get("logEvents") or log_call[1].get("logEvents")
        assert len(log_events) == 1
        event_json = json.loads(log_events[0]["message"])
        assert event_json["class_uid"] == 99001

        # Amazon CloudWatch Metrics should have been called
        mock_aws_clients["cloudwatch"].put_metric_data.assert_called_once()

    def test_deny_emits_cloudwatch_logs_and_metrics(self, mock_aws_clients):
        """DENY evaluation emits to Amazon CloudWatch Logs and publishes metrics."""
        envelope = _make_envelope(user_role="support", mfa_verified=False)
        decision = evaluate(envelope)
        assert decision.decision == Decision.DENY

        emit_audit_event(envelope, decision, evaluation_latency_ms=0.4)

        mock_aws_clients["logs"].put_log_events.assert_called_once()
        mock_aws_clients["cloudwatch"].put_metric_data.assert_called_once()

    def test_metrics_include_per_layer_data(self, mock_aws_clients):
        """Metrics include per-layer evaluation count and latency."""
        envelope = _make_envelope(user_role="admin", mfa_verified=True)
        decision = evaluate(envelope)

        emit_audit_event(envelope, decision, evaluation_latency_ms=0.6)

        cw_call = mock_aws_clients["cloudwatch"].put_metric_data.call_args
        metric_data = cw_call.kwargs.get("MetricData") or cw_call[1].get("MetricData")

        # Should have metrics for L1, L2, L3 layers + global metrics
        metric_names = [m["MetricName"] for m in metric_data]
        assert "PolicyEvaluationLatency" in metric_names
        assert "PolicyEvaluationCount" in metric_names
        assert "DenialRate" in metric_names
        assert "SignatureVerificationFailure" in metric_names
        assert "DelegationDepthExceeded" in metric_names
        assert "ContentFilterScore" in metric_names

    def test_metrics_namespace_is_correct(self, mock_aws_clients):
        """Metrics are published under the AgentAuthzProtection namespace."""
        envelope = _make_envelope(user_role="admin", mfa_verified=True)
        decision = evaluate(envelope)

        emit_audit_event(envelope, decision, evaluation_latency_ms=0.5)

        cw_call = mock_aws_clients["cloudwatch"].put_metric_data.call_args
        namespace = cw_call.kwargs.get("Namespace") or cw_call[1].get("Namespace")
        assert namespace == "AgentAuthzProtection"

    def test_deny_metrics_show_denial_rate(self, mock_aws_clients):
        """DENY evaluation metrics include 100% denial rate for denying layer."""
        envelope = _make_envelope(user_role="support", mfa_verified=False)
        decision = evaluate(envelope)
        assert decision.decision == Decision.DENY

        emit_audit_event(envelope, decision, evaluation_latency_ms=0.4)

        cw_call = mock_aws_clients["cloudwatch"].put_metric_data.call_args
        metric_data = cw_call.kwargs.get("MetricData") or cw_call[1].get("MetricData")

        denial_metrics = [
            m for m in metric_data
            if m["MetricName"] == "DenialRate" and m["Value"] == 100.0
        ]
        assert len(denial_metrics) > 0  # At least one layer shows 100% denial

    def test_ocsf_event_serializable_to_json(self, mock_aws_clients):
        """OCSF event emitted to Amazon CloudWatch Logs is valid JSON."""
        envelope = _make_envelope(user_role="admin", mfa_verified=True)
        decision = evaluate(envelope)

        emit_audit_event(envelope, decision, evaluation_latency_ms=0.5)

        log_call = mock_aws_clients["logs"].put_log_events.call_args
        log_events = log_call.kwargs.get("logEvents") or log_call[1].get("logEvents")
        event_json = json.loads(log_events[0]["message"])

        # Verify key OCSF fields are present in the serialized JSON
        assert event_json["class_uid"] == 99001
        assert "actor" in event_json
        assert "authorization" in event_json
        assert "unmapped" in event_json
        assert "resources" in event_json
