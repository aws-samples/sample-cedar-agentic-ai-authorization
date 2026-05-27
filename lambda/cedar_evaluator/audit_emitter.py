# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Audit event emission for Cedar policy evaluations.

Constructs OCSF 99001 events, emits them to Amazon CloudWatch Logs, publishes
CloudWatch metrics, and falls back to an SQS dead-letter queue on
persistent failures.

Requirements: 4.1, 4.2, 4.4, 9.1
"""

from __future__ import annotations

import importlib
import json
import logging
import os
import time
from dataclasses import asdict
from typing import Optional

import boto3
from botocore.exceptions import ClientError

_types = importlib.import_module("shared.types")
AuthzDecision = _types.AuthzDecision
Decision = _types.Decision

_ocsf_builder = importlib.import_module("shared.ocsf_event_builder")
build_ocsf_event = _ocsf_builder.build_ocsf_event

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration from environment
# ---------------------------------------------------------------------------

_LOG_GROUP_NAME = os.environ.get(
    "AUDIT_LOG_GROUP", "/cedar-evaluator/audit"
)
_LOG_STREAM_NAME = os.environ.get(
    "AUDIT_LOG_STREAM", "ocsf-99001"
)
_METRIC_NAMESPACE = os.environ.get(
    "METRIC_NAMESPACE", "AgentAuthzProtection"
)
_DLQ_URL = os.environ.get("AUDIT_DLQ_URL", "")

# Retry configuration
_MAX_RETRIES = 3
_BASE_BACKOFF_SECONDS = 0.1


# ---------------------------------------------------------------------------
# boto3 client helpers — lazy-initialised for Lambda warm reuse
# ---------------------------------------------------------------------------

_logs_client = None
_cw_client = None
_sqs_client = None


def _get_logs_client():
    """Return a cached CloudWatch Logs client."""
    global _logs_client
    if _logs_client is None:
        _logs_client = boto3.client("logs")
    return _logs_client


def _get_cw_client():
    """Return a cached CloudWatch Metrics client."""
    global _cw_client
    if _cw_client is None:
        _cw_client = boto3.client("cloudwatch")
    return _cw_client


def _get_sqs_client():
    """Return a cached SQS client."""
    global _sqs_client
    if _sqs_client is None:
        _sqs_client = boto3.client("sqs")
    return _sqs_client


def reset_clients() -> None:
    """Reset cached boto3 clients. Useful for testing."""
    global _logs_client, _cw_client, _sqs_client
    _logs_client = None
    _cw_client = None
    _sqs_client = None


# ---------------------------------------------------------------------------
# Retry helper
# ---------------------------------------------------------------------------


def _retry_with_backoff(func, *args, max_retries: int = _MAX_RETRIES, **kwargs):
    """Execute *func* with exponential backoff retries.

    Returns the function result on success, or raises the last exception
    after exhausting all retries.
    """
    last_exc: Optional[Exception] = None
    for attempt in range(max_retries + 1):
        try:
            return func(*args, **kwargs)
        except Exception as exc:
            last_exc = exc
            if attempt < max_retries:
                sleep_time = _BASE_BACKOFF_SECONDS * (2 ** attempt)
                func_name = getattr(func, "__name__", repr(func))
                logger.warning(
                    "Retry %d/%d for %s after %.2fs: %s",
                    attempt + 1, max_retries, func_name,
                    sleep_time, exc,
                )
                time.sleep(sleep_time)
    raise last_exc  # type: ignore[misc]


# ---------------------------------------------------------------------------
# CloudWatch Logs emission
# ---------------------------------------------------------------------------


def _emit_to_cloudwatch_logs(event_json: str) -> None:
    """Put the OCSF event JSON into CloudWatch Logs."""
    client = _get_logs_client()
    client.put_log_events(
        logGroupName=_LOG_GROUP_NAME,
        logStreamName=_LOG_STREAM_NAME,
        logEvents=[
            {
                "timestamp": int(time.time() * 1000),
                "message": event_json,
            }
        ],
    )


# ---------------------------------------------------------------------------
# CloudWatch Metrics emission
# ---------------------------------------------------------------------------


def _publish_metrics(
    envelope: dict,
    decision: AuthzDecision,
    evaluation_latency_ms: float,
) -> None:
    """Publish CloudWatch metrics for the policy evaluation.

    Metrics emitted:
      - PolicyEvaluationLatency (ms, per layer)
      - PolicyEvaluationCount (count, per layer and decision)
      - DenialRate (percent, per layer)
      - SignatureVerificationFailure (count)
      - DelegationDepthExceeded (count)
      - ContentFilterScore (count)
    """
    client = _get_cw_client()
    metric_data = []

    layers = ["L1", "L2", "L3"]
    layer_results = {}
    if decision.layer_results:
        layer_results = {
            "L1": decision.layer_results.L1,
            "L2": decision.layer_results.L2,
            "L3": decision.layer_results.L3,
        }

    for layer in layers:
        lr = layer_results.get(layer)
        if lr is None:
            continue

        layer_decision = lr.decision.value

        # PolicyEvaluationLatency — overall latency attributed per layer
        metric_data.append({
            "MetricName": "PolicyEvaluationLatency",
            "Dimensions": [{"Name": "Layer", "Value": layer}],
            "Value": evaluation_latency_ms,
            "Unit": "Milliseconds",
        })

        # PolicyEvaluationCount — per layer and decision
        metric_data.append({
            "MetricName": "PolicyEvaluationCount",
            "Dimensions": [
                {"Name": "Layer", "Value": layer},
                {"Name": "Decision", "Value": layer_decision},
            ],
            "Value": 1,
            "Unit": "Count",
        })

        # DenialRate — 100% if denied, 0% if permitted
        denial_pct = 100.0 if layer_decision == "DENY" else 0.0
        metric_data.append({
            "MetricName": "DenialRate",
            "Dimensions": [{"Name": "Layer", "Value": layer}],
            "Value": denial_pct,
            "Unit": "Percent",
        })

    # SignatureVerificationFailure
    sig_fail = 0
    if decision.layer_results:
        l1_details = decision.layer_results.L1.evaluation_details or ""
        if "signature" in l1_details.lower():
            sig_fail = 1
    metric_data.append({
        "MetricName": "SignatureVerificationFailure",
        "Value": sig_fail,
        "Unit": "Count",
    })

    # DelegationDepthExceeded
    depth_exceeded = 0
    if decision.layer_results:
        l2_details = decision.layer_results.L2.evaluation_details or ""
        if "depth" in l2_details.lower() and "exceed" in l2_details.lower():
            depth_exceeded = 1
    metric_data.append({
        "MetricName": "DelegationDepthExceeded",
        "Value": depth_exceeded,
        "Unit": "Count",
    })

    # ContentFilterScore
    cfr = envelope.get("content_filter_result", {})
    content_score = cfr.get("injection_score", 0)
    metric_data.append({
        "MetricName": "ContentFilterScore",
        "Value": content_score,
        "Unit": "Count",
    })

    client.put_metric_data(
        Namespace=_METRIC_NAMESPACE,
        MetricData=metric_data,
    )


# ---------------------------------------------------------------------------
# SQS dead-letter queue fallback
# ---------------------------------------------------------------------------


def _send_to_dlq(event_json: str) -> None:
    """Send a failed audit event to the SQS dead-letter queue."""
    if not _DLQ_URL:
        logger.error("AUDIT_DLQ_URL not configured; dropping failed audit event")
        return
    client = _get_sqs_client()
    client.send_message(
        QueueUrl=_DLQ_URL,
        MessageBody=event_json,
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def emit_audit_event(
    envelope: dict,
    decision: AuthzDecision,
    evaluation_latency_ms: float,
) -> None:
    """Emit an OCSF 99001 audit event and publish CloudWatch metrics.

    This is the main entry point called by the Cedar Evaluator handler
    after every policy evaluation.

    The function:
      1. Builds the OCSF 99001 event.
      2. Emits the event to CloudWatch Logs (with retry).
      3. Publishes CloudWatch metrics (with retry).
      4. On persistent CloudWatch Logs failure, falls back to SQS DLQ.

    Audit failures never block the authorization decision.

    Args:
        envelope: The original Request Envelope dict.
        decision: The AuthzDecision from the policy evaluator.
        evaluation_latency_ms: Wall-clock evaluation time in milliseconds.
    """
    ocsf_event = build_ocsf_event(envelope, decision, evaluation_latency_ms)
    event_json = json.dumps(asdict(ocsf_event), default=str)

    # --- Emit to CloudWatch Logs with retry + DLQ fallback ---
    try:
        _retry_with_backoff(_emit_to_cloudwatch_logs, event_json)
    except Exception as exc:
        logger.error("CloudWatch Logs emission failed after retries: %s", exc)
        try:
            _send_to_dlq(event_json)
        except Exception as dlq_exc:
            logger.error("DLQ fallback also failed: %s", dlq_exc)

    # --- Publish CloudWatch metrics with retry (best-effort) ---
    try:
        _retry_with_backoff(_publish_metrics, envelope, decision, evaluation_latency_ms)
    except Exception as exc:
        logger.error("CloudWatch metrics emission failed after retries: %s", exc)
