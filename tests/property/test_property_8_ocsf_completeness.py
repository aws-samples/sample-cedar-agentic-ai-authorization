# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Property 8: OCSF audit event completeness.

For any policy evaluation result (permit or deny) with any combination of
delegation chain, agent identities, action, resource, and layer results,
the OCSF event builder SHALL produce an event with class_uid 99001 containing
all required fields: request_id, timestamp, originating user identity, full
delegation chain, agent identities, action, resource, policy decision,
denying layer (if denied), delegation depth, content_filter_score,
layer_results, and evaluation latency.

**Validates: Requirements 4.1, 4.2**

Feature: agent-authz-protection
Property 8: OCSF audit event completeness
"""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

from hypothesis import given, settings
from hypothesis import strategies as st

_project_root = Path(__file__).resolve().parent.parent.parent
_lambda_dir = _project_root / "lambda"
if str(_lambda_dir) not in sys.path:
    sys.path.insert(0, str(_lambda_dir))

_builder = importlib.import_module("shared.ocsf_event_builder")
_types = importlib.import_module("shared.types")

build_ocsf_event = _builder.build_ocsf_event
AuthzDecision = _types.AuthzDecision
Decision = _types.Decision
LayerResult = _types.LayerResult
LayerResults = _types.LayerResults

# ---------------------------------------------------------------------------
# Hypothesis strategies
# ---------------------------------------------------------------------------

_nonempty_text = st.text(
    alphabet=st.characters(whitelist_categories=("L", "N")),
    min_size=1,
    max_size=32,
).filter(lambda s: s.strip())

_decision_st = st.sampled_from([Decision.PERMIT, Decision.DENY])

_layer_result_st = _decision_st.map(lambda d: LayerResult(decision=d))

_layer_results_st = st.builds(
    LayerResults,
    L1=_layer_result_st,
    L2=_layer_result_st,
    L3=_layer_result_st,
)

_delegation_hop_st = st.fixed_dictionaries({
    "hop": st.integers(min_value=0, max_value=20),
    "agent_id": _nonempty_text,
    "capabilities_granted": st.lists(_nonempty_text, min_size=0, max_size=3),
    "timestamp": st.just("2025-01-01T00:00:00Z"),
})

_denying_layers = st.sampled_from(["L1", "L2", "L3"])


@st.composite
def _authz_decision_st(draw: st.DrawFn) -> AuthzDecision:
    """Generate a random AuthzDecision with layer results."""
    layer_results = draw(_layer_results_st)
    overall = draw(_decision_st)
    denying_layer = draw(_denying_layers) if overall == Decision.DENY else None
    return AuthzDecision(
        decision=overall,
        denying_layer=denying_layer,
        layer_results=layer_results,
    )


@st.composite
def _envelope_st(draw: st.DrawFn) -> dict:
    """Generate a random Request Envelope dict."""
    chain = draw(st.lists(_delegation_hop_st, min_size=0, max_size=5))
    depth = draw(st.integers(min_value=0, max_value=10))
    action_type = draw(st.sampled_from(["invoke_tool", "delegate_task"]))
    return {
        "request_id": draw(_nonempty_text),
        "timestamp": "2025-01-01T00:00:00Z",
        "source_protocol": "MCP",
        "source_agent": {
            "agent_id": draw(_nonempty_text),
            "trust_level": draw(st.integers(min_value=1, max_value=5)),
            "namespace": draw(_nonempty_text),
            "registered_capabilities": draw(
                st.lists(_nonempty_text, min_size=0, max_size=3)
            ),
            "lifecycle_stage": draw(
                st.sampled_from(["production", "staging", "development"])
            ),
        },
        "action": {
            "type": action_type,
            "target_resource": draw(_nonempty_text),
            "requested_capabilities": draw(
                st.lists(_nonempty_text, min_size=0, max_size=3)
            ),
        },
        "delegation_chain": chain,
        "delegation_depth": depth,
        "originating_user": {
            "user_id": draw(_nonempty_text),
            "role": draw(_nonempty_text),
            "mfa_verified": draw(st.booleans()),
            "authentication_method": draw(_nonempty_text),
            "session_id": draw(_nonempty_text),
        },
        "content_filter_result": {
            "injection_score": draw(st.integers(min_value=0, max_value=100)),
            "filter_applied": draw(st.booleans()),
            "filter_source": "bedrock-guardrails",
        },
    }



@settings(max_examples=100)
@given(
    envelope=_envelope_st(),
    decision=_authz_decision_st(),
    latency_ms=st.floats(min_value=0.0, max_value=10000.0, allow_nan=False, allow_infinity=False),
)
def test_ocsf_audit_event_completeness(
    envelope: dict,
    decision: AuthzDecision,
    latency_ms: float,
) -> None:
    """Property 8 — OCSF audit event completeness.

    **Validates: Requirements 4.1, 4.2**
    """
    event = build_ocsf_event(envelope, decision, latency_ms)

    # --- class_uid must be 99001 ---
    assert event.class_uid == 99001, f"Expected class_uid 99001, got {event.class_uid}"

    # --- request_id ---
    assert event.unmapped.request_id == envelope["request_id"]

    # --- timestamp present ---
    assert event.time, "time must be a non-empty string"

    # --- originating user identity ---
    ou = envelope["originating_user"]
    assert event.actor.user.uid == ou["user_id"]
    assert event.actor.user.role == ou["role"]
    assert event.actor.user.mfa_enabled == ou["mfa_verified"]
    assert event.actor.session.uid == ou["session_id"]

    # --- delegation chain: all hop agent_ids present in agent_list ---
    chain = envelope["delegation_chain"]
    chain_agent_ids = [hop["agent_id"] for hop in chain]
    event_agent_uids = [a.uid for a in event.src_endpoint.agent_list]
    for aid in chain_agent_ids:
        assert aid in event_agent_uids, (
            f"Delegation chain agent '{aid}' missing from src_endpoint.agent_list"
        )

    # --- source agent identity in agent_list ---
    sa_id = envelope["source_agent"]["agent_id"]
    assert sa_id in event_agent_uids, (
        f"Source agent '{sa_id}' missing from src_endpoint.agent_list"
    )

    # --- action / resource ---
    target = envelope["action"]["target_resource"]
    assert len(event.resources) >= 1, "resources must not be empty"
    assert event.resources[0].name == target
    assert event.resources[0].uid == target

    # --- decision ---
    expected_decision_str = (
        "Permitted" if decision.decision == Decision.PERMIT else "Denied"
    )
    assert event.authorization.decision == expected_decision_str

    # --- denying_layer (if denied) ---
    if decision.decision == Decision.DENY:
        assert event.unmapped.denying_layer == decision.denying_layer
    else:
        assert event.unmapped.denying_layer is None

    # --- delegation_depth ---
    assert event.unmapped.delegation_depth == envelope["delegation_depth"]

    # --- content_filter_score ---
    assert event.unmapped.content_filter_score == envelope["content_filter_result"]["injection_score"]

    # --- layer_results ---
    lr = event.unmapped.layer_results
    assert "L1" in lr, "layer_results must contain L1"
    assert "L2" in lr, "layer_results must contain L2"
    assert "L3" in lr, "layer_results must contain L3"
    assert lr["L1"] == decision.layer_results.L1.decision.value
    assert lr["L2"] == decision.layer_results.L2.decision.value
    assert lr["L3"] == decision.layer_results.L3.decision.value

    # --- evaluation_latency_ms ---
    assert event.unmapped.evaluation_latency_ms == latency_ms
