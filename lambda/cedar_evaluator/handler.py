# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Cedar Policy Evaluator Lambda handler.

Entry point that wires together envelope validation → signature
verification → three-layer Cedar evaluation → audit emission.

Validates: Requirements 3.1, 3.6, 6.1, 6.2, 6.4, 7.5
"""

from __future__ import annotations

import importlib
import json
import logging
import os
import time
from dataclasses import asdict
from typing import Any

# ``lambda`` is a Python keyword — use importlib for intra-package imports.
_envelope_schema_mod = importlib.import_module("shared.envelope_schema")
_types_mod = importlib.import_module("shared.types")
_sig_mod = importlib.import_module("cedar_evaluator.signature_verifier")
_eval_mod = importlib.import_module("cedar_evaluator.policy_evaluator")
_audit_mod = importlib.import_module("cedar_evaluator.audit_emitter")

validate_envelope = _envelope_schema_mod.validate_envelope

Decision = _types_mod.Decision
AuthzDecision = _types_mod.AuthzDecision
LayerResult = _types_mod.LayerResult
LayerResults = _types_mod.LayerResults

verify_user_context = _sig_mod.verify_user_context
SignatureVerificationError = _sig_mod.SignatureVerificationError

evaluate = _eval_mod.evaluate

emit_audit_event = _audit_mod.emit_audit_event

logger = logging.getLogger(__name__)
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))


# ---------------------------------------------------------------------------
# Helper: build a DENY AuthzDecision
# ---------------------------------------------------------------------------

def _deny_decision(reason: str) -> AuthzDecision:
    """Build a DENY AuthzDecision with the given reason in all layers."""
    detail = LayerResult(decision=Decision.DENY, evaluation_details=reason)
    not_eval = LayerResult(decision=Decision.DENY, evaluation_details="Not evaluated")
    return AuthzDecision(
        decision=Decision.DENY,
        denying_layer="pre-evaluation",
        layer_results=LayerResults(L1=detail, L2=not_eval, L3=not_eval),
    )


def _decision_to_dict(decision: AuthzDecision) -> dict[str, Any]:
    """Serialise an AuthzDecision to a JSON-safe dict."""
    result: dict[str, Any] = {
        "decision": decision.decision.value,
        "denying_layer": decision.denying_layer,
    }
    if decision.layer_results is not None:
        result["layer_results"] = {
            "L1": {
                "decision": decision.layer_results.L1.decision.value,
                "evaluation_details": decision.layer_results.L1.evaluation_details,
            },
            "L2": {
                "decision": decision.layer_results.L2.decision.value,
                "evaluation_details": decision.layer_results.L2.evaluation_details,
            },
            "L3": {
                "decision": decision.layer_results.L3.decision.value,
                "evaluation_details": decision.layer_results.L3.evaluation_details,
            },
        }
    return result


# ---------------------------------------------------------------------------
# Lightweight user-context adapter for signature verification
# ---------------------------------------------------------------------------

class _UserContextAdapter:
    """Adapts a dict-based originating_user to the structural type
    expected by ``signature_verifier.verify_user_context``."""

    __slots__ = ("user_id", "role", "mfa_verified",
                 "authentication_method", "session_id")

    def __init__(self, data: dict) -> None:
        self.user_id = data["user_id"]
        self.role = data["role"]
        self.mfa_verified = data["mfa_verified"]
        self.authentication_method = data["authentication_method"]
        self.session_id = data["session_id"]


# ---------------------------------------------------------------------------
# Lambda handler
# ---------------------------------------------------------------------------

def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """Lambda handler for the Cedar Policy Evaluator.

    Receives a Request Envelope dict (from the MCP Adapter Lambda),
    validates it, verifies the HMAC signature, evaluates all three
    Cedar policy layers, emits an OCSF 99001 audit event, and returns
    the authorization decision as a JSON dict.

    Args:
        event: Request Envelope dict.
        context: Lambda context (unused).

    Returns:
        Authorization decision dict with ``decision``, ``denying_layer``,
        and ``layer_results``.
    """
    start_ns = time.perf_counter_ns()

    # ── 1. Validate envelope against JSON schema ──────────────────
    try:
        validate_envelope(event)
    except Exception as exc:
        logger.warning("Invalid envelope: %s", exc)
        decision = _deny_decision("invalid_envelope")
        _safe_emit_audit(event, decision, start_ns)
        return _decision_to_dict(decision)

    # ── 2. Verify HMAC-SHA256 signature of originating_user ───────
    try:
        ou = event.get("originating_user", {})
        user_adapter = _UserContextAdapter(ou)
        verify_user_context(user_adapter, ou.get("signature", ""))
    except SignatureVerificationError:
        logger.warning("Signature verification failed for user %s",
                       ou.get("user_id", "unknown"))
        decision = _deny_decision("signature_verification_failed")
        _safe_emit_audit(event, decision, start_ns)
        return _decision_to_dict(decision)
    except Exception as exc:
        logger.error("Unexpected error during signature verification: %s", exc)
        decision = _deny_decision("signature_verification_failed")
        _safe_emit_audit(event, decision, start_ns)
        return _decision_to_dict(decision)

    # ── 3. Evaluate all three Cedar policy layers ─────────────────
    try:
        decision = evaluate(event)
    except Exception as exc:
        logger.error("Cedar evaluation error: %s", exc)
        decision = _deny_decision("cedar_evaluation_error")
        _safe_emit_audit(event, decision, start_ns)
        return _decision_to_dict(decision)

    # ── 3.5. Apply enforcement mode (gradual rollout) ─────────────
    from cedar_evaluator.enforcement_mode import get_enforcement_mode, EnforcementMode

    mode = get_enforcement_mode()

    if decision.decision == Decision.DENY and mode != EnforcementMode.ENFORCE:
        if mode == EnforcementMode.LOG_ONLY:
            logger.info(
                "LOG_ONLY mode: would have denied (layer=%s) but allowing. request_id=%s",
                decision.denying_layer,
                event.get("request_id"),
            )
            _safe_emit_audit(event, decision, start_ns)
            result = _decision_to_dict(decision)
            result["decision"] = Decision.PERMIT.value
            result["enforcement_mode"] = "LOG_ONLY"
            result["shadow_decision"] = "DENY"
            result["shadow_denying_layer"] = decision.denying_layer
            return result

        elif mode == EnforcementMode.WARN:
            logger.warning(
                "WARN mode: denied by %s but allowing with warning. request_id=%s",
                decision.denying_layer,
                event.get("request_id"),
            )
            _safe_emit_audit(event, decision, start_ns)
            result = _decision_to_dict(decision)
            result["decision"] = Decision.PERMIT.value
            result["enforcement_mode"] = "WARN"
            result["warning"] = (
                f"This request would be DENIED by {decision.denying_layer} "
                f"in ENFORCE mode."
            )
            return result

    # ── 4. Emit OCSF 99001 audit event ───────────────────────────
    _safe_emit_audit(event, decision, start_ns)

    # ── 5. Return AuthzDecision as JSON dict ──────────────────────
    return _decision_to_dict(decision)


def _safe_emit_audit(
    envelope: dict[str, Any],
    decision: AuthzDecision,
    start_ns: int,
) -> None:
    """Emit audit event, swallowing any errors so they never block
    the authorization decision."""
    elapsed_ms = (time.perf_counter_ns() - start_ns) / 1_000_000
    try:
        emit_audit_event(envelope, decision, elapsed_ms)
    except Exception as exc:
        logger.error("Audit emission failed (non-blocking): %s", exc)
