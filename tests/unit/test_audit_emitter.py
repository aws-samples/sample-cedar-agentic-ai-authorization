# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Unit tests for the audit emitter module.

Tests OCSF event construction, Amazon CloudWatch Logs emission, CloudWatch metrics
publishing, retry logic, and SQS dead-letter queue fallback.

Requirements: 4.1, 4.2, 4.4, 9.1
"""

from __future__ import annotations

import importlib
import json
from dataclasses import asdict
from unittest.mock import MagicMock, patch, call

import pytest
from botocore.exceptions import ClientError

_types = importlib.import_module("shared.types")
AuthzDecision = _types.AuthzDecision
Decision = _types.Decision
LayerResult = _types.LayerResult
LayerResults = _types.LayerResults

_emitter = importlib.import_module("cedar_evaluator.audit_emitter")
build_ocsf_event = _emitter.build_ocsf_event
emit_audit_event = _emitter.emit_audit_event
_retry_with_backoff = _emitter._retry_with_backoff


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def sample_envelope():
    """A minimal valid Request Envelope dict."""
    return {
        "request_id": "req-001",
        "timestamp": "2026-04-13T12:00:00.000Z",
        "source_protocol": "MCP",
        "source_agent": {
            "agent_id": "finance-agent",
            "trust_level": 3,
            "namespace": "payments",
            "registered_capabilities": ["process_payment"],
            "lifecycle_stage": "production",
        },
        "action": {
            "type": "invoke_tool",
            "target_resource": "process_payment",
            "requested_capabilities": [],
        },
        "delegation_chain": [
            {
                "hop": 0,
                "agent_id": "orchestrator",
                "capabilities_granted": ["process_payment"],
                "timestamp": "2026-04-13T11:59:59.000Z",
            }
        ],
        "delegation_depth": 1,
        "originating_user": {
            "user_id": "user-12345",
            "role": "admin",
            "mfa_verified": True,
            "authentication_method": "SSO",
            "session_id": "session-abc",
            "signature": "aabbccdd",
        },
        "content_filter_result": {
            "injection_score": 5,
            "filter_applied": True,
            "filter_source": "bedrock-guardrails",
        },
    }


@pytest.fixture()
def permit_decision():
    return AuthzDecision(
        decision=Decision.PERMIT,
        denying_layer=None,
        layer_results=LayerResults(
            L1=LayerResult(decision=Decision.PERMIT),
            L2=LayerResult(decision=Decision.PERMIT),
            L3=LayerResult(decision=Decision.PERMIT),
        ),
    )


@pytest.fixture()
def deny_decision():
    return AuthzDecision(
        decision=Decision.DENY,
        denying_layer="L3",
        layer_results=LayerResults(
            L1=LayerResult(decision=Decision.PERMIT),
            L2=LayerResult(decision=Decision.PERMIT),
            L3=LayerResult(decision=Decision.DENY, evaluation_details="role mismatch"),
        ),
    )


# ---------------------------------------------------------------------------
# OCSF event builder tests
# ---------------------------------------------------------------------------


class TestBuildOcsfEvent:
    """Tests for build_ocsf_event."""

    def test_class_uid_is_99001(self, sample_envelope, permit_decision):
        event = build_ocsf_event(sample_envelope, permit_decision, 0.6)
        assert event.class_uid == 99001

    def test_class_name(self, sample_envelope, permit_decision):
        event = build_ocsf_event(sample_envelope, permit_decision, 0.6)
        assert event.class_name == "Agent Policy Evaluation"

    def test_actor_user_fields(self, sample_envelope, permit_decision):
        event = build_ocsf_event(sample_envelope, permit_decision, 0.6)
        assert event.actor.user.uid == "user-12345"
        assert event.actor.user.role == "admin"
        assert event.actor.user.mfa_enabled is True
        assert event.actor.session.uid == "session-abc"

    def test_agent_list_includes_chain_and_source(self, sample_envelope, permit_decision):
        event = build_ocsf_event(sample_envelope, permit_decision, 0.6)
        agent_ids = [a.uid for a in event.src_endpoint.agent_list]
        assert "orchestrator" in agent_ids
        assert "finance-agent" in agent_ids

    def test_authorization_permitted(self, sample_envelope, permit_decision):
        event = build_ocsf_event(sample_envelope, permit_decision, 0.6)
        assert event.authorization.decision == "Permitted"

    def test_authorization_denied(self, sample_envelope, deny_decision):
        event = build_ocsf_event(sample_envelope, deny_decision, 0.6)
        assert event.authorization.decision == "Denied"
        assert "L3" in event.authorization.policy.name

    def test_resource_populated(self, sample_envelope, permit_decision):
        event = build_ocsf_event(sample_envelope, permit_decision, 0.6)
        assert len(event.resources) == 1
        assert event.resources[0].name == "process_payment"
        assert event.resources[0].type == "Tool"

    def test_unmapped_fields(self, sample_envelope, permit_decision):
        event = build_ocsf_event(sample_envelope, permit_decision, 0.6)
        assert event.unmapped.delegation_depth == 1
        assert event.unmapped.delegation_chain == ["orchestrator"]
        assert event.unmapped.content_filter_score == 5
        assert event.unmapped.request_id == "req-001"
        assert event.unmapped.evaluation_latency_ms == 0.6

    def test_layer_results_in_unmapped(self, sample_envelope, permit_decision):
        event = build_ocsf_event(sample_envelope, permit_decision, 0.6)
        assert event.unmapped.layer_results == {
            "L1": "PERMIT", "L2": "PERMIT", "L3": "PERMIT",
        }

    def test_deny_severity_is_higher(self, sample_envelope, deny_decision):
        event = build_ocsf_event(sample_envelope, deny_decision, 0.6)
        assert event.severity_id == 4
        assert event.status_id == 2

    def test_event_serialisable_to_json(self, sample_envelope, permit_decision):
        event = build_ocsf_event(sample_envelope, permit_decision, 0.6)
        result = json.dumps(asdict(event), default=str)
        parsed = json.loads(result)
        assert parsed["class_uid"] == 99001


# ---------------------------------------------------------------------------
# Retry logic tests
# ---------------------------------------------------------------------------


class TestRetryWithBackoff:
    """Tests for _retry_with_backoff."""

    @patch("cedar_evaluator.audit_emitter.time.sleep")
    def test_succeeds_on_first_try(self, mock_sleep):
        func = MagicMock(return_value="ok")
        result = _retry_with_backoff(func, max_retries=3)
        assert result == "ok"
        func.assert_called_once()
        mock_sleep.assert_not_called()

    @patch("cedar_evaluator.audit_emitter.time.sleep")
    def test_retries_on_failure_then_succeeds(self, mock_sleep):
        func = MagicMock(side_effect=[RuntimeError("fail"), "ok"])
        result = _retry_with_backoff(func, max_retries=3)
        assert result == "ok"
        assert func.call_count == 2
        assert mock_sleep.call_count == 1

    @patch("cedar_evaluator.audit_emitter.time.sleep")
    def test_raises_after_all_retries_exhausted(self, mock_sleep):
        func = MagicMock(side_effect=RuntimeError("persistent"))
        with pytest.raises(RuntimeError, match="persistent"):
            _retry_with_backoff(func, max_retries=2)
        # initial attempt + 2 retries = 3 calls
        assert func.call_count == 3

    @patch("cedar_evaluator.audit_emitter.time.sleep")
    def test_exponential_backoff_timing(self, mock_sleep):
        func = MagicMock(side_effect=[RuntimeError, RuntimeError, "ok"])
        _retry_with_backoff(func, max_retries=3)
        # Backoff: 0.1 * 2^0 = 0.1, 0.1 * 2^1 = 0.2
        calls = mock_sleep.call_args_list
        assert len(calls) == 2
        assert abs(calls[0][0][0] - 0.1) < 0.01
        assert abs(calls[1][0][0] - 0.2) < 0.01


# ---------------------------------------------------------------------------
# emit_audit_event integration tests (mocked AWS clients)
# ---------------------------------------------------------------------------


class TestEmitAuditEvent:
    """Tests for the emit_audit_event public API with mocked boto3 clients."""

    @pytest.fixture(autouse=True)
    def _reset(self):
        _emitter.reset_clients()
        yield
        _emitter.reset_clients()

    @patch("cedar_evaluator.audit_emitter._get_cw_client")
    @patch("cedar_evaluator.audit_emitter._get_logs_client")
    def test_emits_to_cloudwatch_logs(
        self, mock_logs_factory, mock_cw_factory,
        sample_envelope, permit_decision,
    ):
        mock_logs = MagicMock()
        mock_logs_factory.return_value = mock_logs
        mock_cw = MagicMock()
        mock_cw_factory.return_value = mock_cw

        emit_audit_event(sample_envelope, permit_decision, 0.6)

        mock_logs.put_log_events.assert_called_once()
        call_kwargs = mock_logs.put_log_events.call_args[1]
        assert call_kwargs["logGroupName"] == "/cedar-evaluator/audit"
        msg = call_kwargs["logEvents"][0]["message"]
        parsed = json.loads(msg)
        assert parsed["class_uid"] == 99001

    @patch("cedar_evaluator.audit_emitter._get_cw_client")
    @patch("cedar_evaluator.audit_emitter._get_logs_client")
    def test_publishes_cloudwatch_metrics(
        self, mock_logs_factory, mock_cw_factory,
        sample_envelope, permit_decision,
    ):
        mock_logs = MagicMock()
        mock_logs_factory.return_value = mock_logs
        mock_cw = MagicMock()
        mock_cw_factory.return_value = mock_cw

        emit_audit_event(sample_envelope, permit_decision, 0.6)

        mock_cw.put_metric_data.assert_called_once()
        call_kwargs = mock_cw.put_metric_data.call_args[1]
        assert call_kwargs["Namespace"] == "AgentAuthzProtection"
        metric_names = [m["MetricName"] for m in call_kwargs["MetricData"]]
        assert "PolicyEvaluationLatency" in metric_names
        assert "PolicyEvaluationCount" in metric_names
        assert "DenialRate" in metric_names
        assert "SignatureVerificationFailure" in metric_names
        assert "DelegationDepthExceeded" in metric_names
        assert "ContentFilterScore" in metric_names

    @patch("cedar_evaluator.audit_emitter.time.sleep")
    @patch("cedar_evaluator.audit_emitter._get_sqs_client")
    @patch("cedar_evaluator.audit_emitter._get_cw_client")
    @patch("cedar_evaluator.audit_emitter._get_logs_client")
    def test_falls_back_to_dlq_on_logs_failure(
        self, mock_logs_factory, mock_cw_factory, mock_sqs_factory,
        mock_sleep, sample_envelope, permit_decision,
    ):
        mock_logs = MagicMock()
        mock_logs.put_log_events.side_effect = ClientError(
            {"Error": {"Code": "ServiceUnavailable", "Message": "down"}},
            "PutLogEvents",
        )
        mock_logs_factory.return_value = mock_logs

        mock_cw = MagicMock()
        mock_cw_factory.return_value = mock_cw

        mock_sqs = MagicMock()
        mock_sqs_factory.return_value = mock_sqs

        _emitter._DLQ_URL = "https://sqs.us-east-1.amazonaws.com/123/audit-dlq"
        try:
            emit_audit_event(sample_envelope, permit_decision, 0.6)
        finally:
            _emitter._DLQ_URL = ""

        # Logs retried 3+1 times then DLQ called
        assert mock_logs.put_log_events.call_count == 4
        mock_sqs.send_message.assert_called_once()
        body = json.loads(mock_sqs.send_message.call_args[1]["MessageBody"])
        assert body["class_uid"] == 99001

    @patch("cedar_evaluator.audit_emitter._get_cw_client")
    @patch("cedar_evaluator.audit_emitter._get_logs_client")
    def test_delegation_depth_exceeded_metric(
        self, mock_logs_factory, mock_cw_factory, sample_envelope,
    ):
        mock_logs = MagicMock()
        mock_logs_factory.return_value = mock_logs
        mock_cw = MagicMock()
        mock_cw_factory.return_value = mock_cw

        depth_decision = AuthzDecision(
            decision=Decision.DENY,
            denying_layer="L2",
            layer_results=LayerResults(
                L1=LayerResult(decision=Decision.PERMIT),
                L2=LayerResult(
                    decision=Decision.DENY,
                    evaluation_details="Delegation depth exceeds hard limit (L2-004)",
                ),
                L3=LayerResult(decision=Decision.DENY, evaluation_details="Not evaluated"),
            ),
        )

        emit_audit_event(sample_envelope, depth_decision, 0.3)

        call_kwargs = mock_cw.put_metric_data.call_args[1]
        depth_metrics = [
            m for m in call_kwargs["MetricData"]
            if m["MetricName"] == "DelegationDepthExceeded"
        ]
        assert len(depth_metrics) == 1
        assert depth_metrics[0]["Value"] == 1

    @patch("cedar_evaluator.audit_emitter._get_cw_client")
    @patch("cedar_evaluator.audit_emitter._get_logs_client")
    def test_content_filter_score_metric(
        self, mock_logs_factory, mock_cw_factory,
        sample_envelope, permit_decision,
    ):
        mock_logs = MagicMock()
        mock_logs_factory.return_value = mock_logs
        mock_cw = MagicMock()
        mock_cw_factory.return_value = mock_cw

        emit_audit_event(sample_envelope, permit_decision, 0.6)

        call_kwargs = mock_cw.put_metric_data.call_args[1]
        score_metrics = [
            m for m in call_kwargs["MetricData"]
            if m["MetricName"] == "ContentFilterScore"
        ]
        assert len(score_metrics) == 1
        assert score_metrics[0]["Value"] == 5
