# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""OCSF 99001 event builder for Cedar policy evaluations.

Constructs OCSF-formatted audit events (class_uid 99001 — Agent Policy
Evaluation) from a Request Envelope and an authorization decision.

This is a shared module used by the Cedar Evaluator Lambda's audit emitter.

Requirements: 4.1, 4.2, 4.5, 8.1
"""

from __future__ import annotations

import importlib
from datetime import datetime, timezone

_types = importlib.import_module("shared.types")
AuthzDecision = _types.AuthzDecision
Decision = _types.Decision
OcsfEvent = _types.OcsfEvent
OcsfActor = _types.OcsfActor
OcsfUser = _types.OcsfUser
OcsfSession = _types.OcsfSession
OcsfSrcEndpoint = _types.OcsfSrcEndpoint
OcsfAgentEntry = _types.OcsfAgentEntry
OcsfAuthorization = _types.OcsfAuthorization
OcsfPolicy = _types.OcsfPolicy
OcsfResource = _types.OcsfResource
OcsfMetadata = _types.OcsfMetadata
OcsfProduct = _types.OcsfProduct
OcsfUnmapped = _types.OcsfUnmapped


def build_ocsf_event(
    envelope: dict,
    decision: AuthzDecision,
    evaluation_latency_ms: float,
) -> OcsfEvent:
    """Build an OCSF 99001 Agent Policy Evaluation event.

    Args:
        envelope: The original Request Envelope dict.
        decision: The AuthzDecision from the policy evaluator.
        evaluation_latency_ms: Wall-clock evaluation time in milliseconds.

    Returns:
        A populated OcsfEvent dataclass.
    """
    ou = envelope.get("originating_user", {})
    actor = OcsfActor(
        user=OcsfUser(
            uid=ou.get("user_id", ""),
            role=ou.get("role", ""),
            mfa_enabled=ou.get("mfa_verified", False),
        ),
        session=OcsfSession(uid=ou.get("session_id", "")),
    )

    # Build agent list from delegation chain + source agent
    chain = envelope.get("delegation_chain", [])
    agent_list = [
        OcsfAgentEntry(name=hop.get("agent_id", ""), uid=hop.get("agent_id", ""))
        for hop in chain
    ]
    sa = envelope.get("source_agent", {})
    agent_list.append(
        OcsfAgentEntry(name=sa.get("agent_id", ""), uid=sa.get("agent_id", ""))
    )
    src_endpoint = OcsfSrcEndpoint(agent_list=agent_list)

    # Authorization block
    decision_str = "Permitted" if decision.decision == Decision.PERMIT else "Denied"
    denying_layer = decision.denying_layer or ""
    authorization = OcsfAuthorization(
        decision=decision_str,
        policy=OcsfPolicy(
            name=f"denying_layer:{denying_layer}" if denying_layer else "all-layers-permit",
            uid=denying_layer or "all",
        ),
    )

    # Resource
    action = envelope.get("action", {})
    target = action.get("target_resource", "")
    resource_type = "Tool" if action.get("type") == "invoke_tool" else "Agent"
    resources = [OcsfResource(name=target, type=resource_type, uid=target)]

    # Layer results for unmapped
    layer_results_map: dict[str, str] = {}
    if decision.layer_results:
        layer_results_map = {
            "L1": decision.layer_results.L1.decision.value,
            "L2": decision.layer_results.L2.decision.value,
            "L3": decision.layer_results.L3.decision.value,
        }

    chain_ids = [hop.get("agent_id", "") for hop in chain]
    cfr = envelope.get("content_filter_result", {})

    unmapped = OcsfUnmapped(
        delegation_depth=envelope.get("delegation_depth", 0),
        delegation_chain=chain_ids,
        content_filter_score=cfr.get("injection_score", 0),
        layer_results=layer_results_map,
        denying_layer=decision.denying_layer,
        request_id=envelope.get("request_id", ""),
        evaluation_latency_ms=evaluation_latency_ms,
    )

    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    severity = 1 if decision.decision == Decision.PERMIT else 4
    status = 1 if decision.decision == Decision.PERMIT else 2

    return OcsfEvent(
        class_uid=99001,
        class_name="Agent Policy Evaluation",
        category_uid=3,
        activity_id=1,
        time=now_iso,
        severity_id=severity,
        status_id=status,
        message="Cedar policy evaluation completed",
        actor=actor,
        src_endpoint=src_endpoint,
        authorization=authorization,
        resources=resources,
        metadata=OcsfMetadata(product=OcsfProduct()),
        unmapped=unmapped,
    )
