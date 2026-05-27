# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Three-layer Cedar policy evaluation engine.

Layer 1 (agent-to-tool) is evaluated locally using the cedarpy SDK for
sub-millisecond latency. Layers 2 and 3 are evaluated via Amazon Verified
Permissions (AVP) using the IsAuthorized API, which retrieves policies
from the deployed policy store.

Evaluation order: L1 → L2 → L3, short-circuiting on the first DENY.

Security:
- All data in transit uses TLS 1.2+ via AWS service endpoints.
- Authorization data at rest is encrypted using AWS KMS customer-managed keys.
- Signing keys are stored in AWS Secrets Manager with KMS encryption.
- Audit logs are encrypted at rest in Amazon CloudWatch Logs using AWS KMS.

Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 3.1, 3.2, 3.3, 3.6
"""

from __future__ import annotations

import logging
import os
import time
from pathlib import Path
from typing import Optional

import importlib

import boto3
import cedarpy
from botocore.exceptions import ClientError

_types = importlib.import_module("shared.types")
AuthzDecision = _types.AuthzDecision
Decision = _types.Decision
LayerResult = _types.LayerResult
LayerResults = _types.LayerResults

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

POLICY_STORE_ID: str = os.environ.get("POLICY_STORE_ID", "")

# ---------------------------------------------------------------------------
# Policy cache — module-level globals for warm Lambda reuse (L1 only)
# ---------------------------------------------------------------------------

_policy_cache: dict[str, str] = {}
_cache_loaded_at: float = 0.0

# Default TTL in seconds; overridable via POLICY_CACHE_TTL_SECONDS env var
_DEFAULT_TTL_SECONDS = 60

# Root of the cedar directory — try Lambda deployment root first,
# then fall back to project-relative path for local development.
_LAMBDA_ROOT = Path(__file__).resolve().parent.parent
_CEDAR_ROOT = _LAMBDA_ROOT / "cedar"
if not _CEDAR_ROOT.exists():
    _CEDAR_ROOT = _LAMBDA_ROOT.parent / "cedar"

LAYER1_DIR = _CEDAR_ROOT / "policies" / "layer1-agent-to-tool"
LAYER2_DIR = _CEDAR_ROOT / "policies" / "layer2-agent-to-agent"
LAYER3_DIR = _CEDAR_ROOT / "policies" / "layer3-originating-user-auth"

# ---------------------------------------------------------------------------
# AVP client — lazy-initialised for Lambda warm reuse
# ---------------------------------------------------------------------------

_avp_client = None


def _get_avp_client():
    """Return a cached Amazon Verified Permissions client."""
    global _avp_client
    if _avp_client is None:
        _avp_client = boto3.client("verifiedpermissions")
    return _avp_client


def reset_avp_client() -> None:
    """Reset the cached AVP client. Useful for testing."""
    global _avp_client
    _avp_client = None


# ---------------------------------------------------------------------------
# Policy loading (L1 local, L2/L3 fallback for local testing)
# ---------------------------------------------------------------------------


def _get_ttl() -> int:
    """Return the policy cache TTL from env or default."""
    return int(os.environ.get("POLICY_CACHE_TTL_SECONDS", _DEFAULT_TTL_SECONDS))


def _load_permit_policies(directory: Path) -> str:
    """Load only permit policy files (L*-00*.cedar) from a directory."""
    parts: list[str] = []
    for f in sorted(directory.glob("*.cedar")):
        name = f.stem
        # Skip default-deny and forbid-only policies (e.g. L1-999, L2-999, L3-999)
        if "-999-" in name:
            continue
        # Skip explicit forbid policies (e.g. L2-004 delegation depth limit)
        if "-004-" in name and "layer2" in str(directory):
            continue
        parts.append(f.read_text())
    return "\n".join(parts)


def _load_forbid_policies(directory: Path) -> str:
    """Load only forbid/deny policy files from a directory.

    These are the default-deny policies (L*-999) and explicit forbid
    policies like L2-004 (delegation depth hard limit).
    """
    parts: list[str] = []
    for f in sorted(directory.glob("*.cedar")):
        name = f.stem
        if "-999-" in name:
            parts.append(f.read_text())
        elif "-004-" in name and "layer2" in str(directory):
            parts.append(f.read_text())
    return "\n".join(parts)


def _refresh_cache_if_needed() -> None:
    """Reload L1 policies from disk if the cache TTL has expired.

    L1 policies are evaluated locally via cedarpy for sub-millisecond
    latency. L2 and L3 policies are evaluated via Amazon Verified
    Permissions (AVP) and do not need local caching.

    For local testing without AVP (POLICY_STORE_ID not set), L2 and L3
    policies are also loaded from disk as a fallback.
    """
    global _policy_cache, _cache_loaded_at

    now = time.monotonic()
    ttl = _get_ttl()

    if _policy_cache and (now - _cache_loaded_at) < ttl:
        return

    logger.info("Loading Cedar policies from disk (TTL=%ds)", ttl)
    _policy_cache = {
        "L1_permit": _load_permit_policies(LAYER1_DIR),
        "L1_forbid": _load_forbid_policies(LAYER1_DIR),
    }

    # Load L2/L3 locally only when AVP is not configured (local testing)
    if not POLICY_STORE_ID:
        _policy_cache["L2_permit"] = _load_permit_policies(LAYER2_DIR)
        _policy_cache["L2_forbid"] = _load_forbid_policies(LAYER2_DIR)
        _policy_cache["L3_permit"] = _load_permit_policies(LAYER3_DIR)
        _policy_cache["L3_forbid"] = _load_forbid_policies(LAYER3_DIR)

    _cache_loaded_at = now


def reset_cache() -> None:
    """Reset the policy cache. Useful for testing."""
    global _policy_cache, _cache_loaded_at
    _policy_cache = {}
    _cache_loaded_at = 0.0


# ---------------------------------------------------------------------------
# Entity and request construction from Request Envelope
# ---------------------------------------------------------------------------


def _build_agent_entity(envelope: dict) -> dict:
    """Build a Cedar Agent entity from the envelope's source_agent."""
    sa = envelope["source_agent"]
    return {
        "uid": {"type": "AgentAuthz::Agent", "id": sa["agent_id"]},
        "attrs": {
            "trust_level": sa["trust_level"],
            "namespace": sa["namespace"],
            "lifecycle_stage": sa["lifecycle_stage"],
            "registered_capabilities": sa.get("registered_capabilities", []),
        },
        "parents": [],
    }


def _build_tool_entity(tool_id: str, envelope: dict) -> dict:
    """Build a Cedar Tool entity with risk metadata from the tool registry.

    Looks up the tool in the registry for accurate risk_level and
    data_classification. Falls back to conservative defaults for
    unknown tools.
    """
    from cedar_evaluator.tool_registry import get_tool_metadata

    metadata = get_tool_metadata(tool_id)
    return {
        "uid": {"type": "AgentAuthz::Tool", "id": tool_id},
        "attrs": {
            "namespace": metadata.namespace,
            "risk_level": metadata.risk_level,
            "data_classification": metadata.data_classification,
        },
        "parents": [],
    }


def _build_target_agent_entity(agent_id: str) -> dict:
    """Build a Cedar Agent entity for a delegation target.

    Delegation targets are referenced by ID; attributes are
    populated with permissive defaults so that Cedar can match
    the entity UID in policy heads.
    """
    return {
        "uid": {"type": "AgentAuthz::Agent", "id": agent_id},
        "attrs": {
            "trust_level": 1,
            "namespace": "default",
            "lifecycle_stage": "production",
            "registered_capabilities": [],
        },
        "parents": [],
    }


def _extract_resource_id(target_resource: str) -> str:
    """Extract the bare resource ID from a Cedar-style reference.

    Handles ``AgentAuthz::Tool::"process_payment"``, ``Tool::"process_payment"``,
    and plain ``process_payment``.
    """
    if "::" in target_resource:
        # e.g. AgentAuthz::Tool::"process_payment" → process_payment
        # Split on last :: to get the quoted ID
        raw = target_resource.rsplit("::", 1)[1]
        return raw.strip('"')
    return target_resource


def _build_cedar_context(envelope: dict) -> dict:
    """Build the Cedar context record from the envelope."""
    ctx: dict = {}

    # Originating user context
    ou = envelope.get("originating_user")
    if ou:
        ctx["originating_user"] = {
            "user_id": ou["user_id"],
            "role": ou["role"],
            "mfa_verified": ou["mfa_verified"],
            "authentication_method": ou["authentication_method"],
            "session_id": ou["session_id"],
        }

    ctx["delegation_depth"] = envelope.get("delegation_depth", 0)

    # Capabilities for Layer 2 evaluation
    action = envelope.get("action", {})
    ctx["requested_capabilities"] = action.get("requested_capabilities", [])

    # target_capabilities: union of capabilities_granted across delegation chain
    chain = envelope.get("delegation_chain", [])
    all_caps: set[str] = set()
    for hop in chain:
        all_caps.update(hop.get("capabilities_granted", []))
    ctx["target_capabilities"] = sorted(all_caps)

    # Content filter score
    cfr = envelope.get("content_filter_result")
    if cfr:
        ctx["content_filter_score"] = cfr.get("injection_score", 0)

    return ctx


# ---------------------------------------------------------------------------
# Local cedarpy evaluation (L1 only)
# ---------------------------------------------------------------------------


def _evaluate_layer_local(
    layer_key: str,
    permit_policies: str,
    forbid_policies: str,
    request: dict,
    entities: list[dict],
) -> LayerResult:
    """Evaluate a single Cedar policy layer locally via cedarpy.

    Used for Layer 1 (agent-to-tool) for sub-millisecond latency.
    Cedar's default behaviour is DENY when no permit rule matches.
    """
    try:
        result = cedarpy.is_authorized(request, permit_policies, entities)
        if result.allowed:
            return LayerResult(decision=Decision.PERMIT, evaluation_details=None)
        return LayerResult(
            decision=Decision.DENY,
            evaluation_details=f"No matching permit rule in {layer_key}",
        )
    except Exception as exc:
        logger.error("Cedar evaluation error in %s: %s", layer_key, exc)
        return LayerResult(
            decision=Decision.DENY,
            evaluation_details=f"Evaluation error: {exc}",
        )


# ---------------------------------------------------------------------------
# Amazon Verified Permissions evaluation (L2 and L3)
# ---------------------------------------------------------------------------


def _build_avp_entity_item(entity: dict) -> dict:
    """Convert a local Cedar entity dict to AVP EntityItem format."""
    uid = entity["uid"]
    attrs = entity.get("attrs", {})

    avp_attrs: dict = {}
    for key, value in attrs.items():
        if isinstance(value, int):
            avp_attrs[key] = {"long": value}
        elif isinstance(value, str):
            avp_attrs[key] = {"string": value}
        elif isinstance(value, bool):
            avp_attrs[key] = {"boolean": value}
        elif isinstance(value, list):
            avp_attrs[key] = {"set": [{"string": str(v)} for v in value]}

    return {
        "identifier": {
            "entityType": uid["type"],
            "entityId": uid["id"],
        },
        "attributes": avp_attrs,
        "parents": [],
    }


def _build_avp_context(cedar_context: dict) -> dict:
    """Convert a Cedar context dict to AVP contextMap format.

    AVP expects context as a contextMap with typed attribute values.
    """
    context_map: dict = {}

    # delegation_depth
    if "delegation_depth" in cedar_context:
        context_map["delegation_depth"] = {"long": cedar_context["delegation_depth"]}

    # originating_user (nested record)
    ou = cedar_context.get("originating_user")
    if ou:
        ou_record: dict = {}
        for key, value in ou.items():
            if isinstance(value, bool):
                ou_record[key] = {"boolean": value}
            elif isinstance(value, str):
                ou_record[key] = {"string": value}
        context_map["originating_user"] = {"record": ou_record}

    # requested_capabilities (set of strings)
    if "requested_capabilities" in cedar_context:
        context_map["requested_capabilities"] = {
            "set": [{"string": v} for v in cedar_context["requested_capabilities"]]
        }

    # target_capabilities (set of strings)
    if "target_capabilities" in cedar_context:
        context_map["target_capabilities"] = {
            "set": [{"string": v} for v in cedar_context["target_capabilities"]]
        }

    # content_filter_score
    if "content_filter_score" in cedar_context:
        context_map["content_filter_score"] = {"long": cedar_context["content_filter_score"]}

    return context_map


def _evaluate_layer_avp(
    layer_key: str,
    principal_type: str,
    principal_id: str,
    action_type: str,
    action_id: str,
    resource_type: str,
    resource_id: str,
    cedar_context: dict,
    entities: list[dict],
) -> LayerResult:
    """Evaluate a Cedar policy layer via Amazon Verified Permissions.

    Calls the IsAuthorized API with the policy store ID, principal,
    action, resource, context, and entities. Used for L2 and L3.

    Args:
        layer_key: Layer identifier (e.g. "L2", "L3") for logging.
        principal_type: Cedar entity type for the principal.
        principal_id: Entity ID for the principal.
        action_type: Cedar action type (e.g. "AgentAuthz::Action").
        action_id: Action ID (e.g. "delegate_task").
        resource_type: Cedar entity type for the resource.
        resource_id: Entity ID for the resource.
        cedar_context: The Cedar context dict.
        entities: List of Cedar entity dicts.

    Returns:
        LayerResult with PERMIT or DENY decision.
    """
    try:
        client = _get_avp_client()

        # Build AVP request
        avp_request: dict = {
            "policyStoreId": POLICY_STORE_ID,
            "principal": {
                "entityType": principal_type,
                "entityId": principal_id,
            },
            "action": {
                "actionType": action_type,
                "actionId": action_id,
            },
            "resource": {
                "entityType": resource_type,
                "entityId": resource_id,
            },
            "context": {
                "contextMap": _build_avp_context(cedar_context),
            },
            "entities": {
                "entityList": [_build_avp_entity_item(e) for e in entities],
            },
        }

        response = client.is_authorized(**avp_request)

        decision = response.get("decision", "DENY")
        if decision == "ALLOW":
            return LayerResult(decision=Decision.PERMIT, evaluation_details=None)

        # Extract determining policies for diagnostics
        determining = response.get("determiningPolicies", [])
        errors = response.get("errors", [])
        details = f"AVP denied in {layer_key}"
        if determining:
            policy_ids = [p.get("policyId", "") for p in determining]
            details += f" (policies: {', '.join(policy_ids)})"
        if errors:
            error_msgs = [e.get("errorDescription", "") for e in errors]
            details += f" (errors: {'; '.join(error_msgs)})"

        return LayerResult(decision=Decision.DENY, evaluation_details=details)

    except ClientError as exc:
        error_code = exc.response.get("Error", {}).get("Code", "Unknown")
        logger.error("AVP ClientError in %s: %s - %s", layer_key, error_code, exc)
        return LayerResult(
            decision=Decision.DENY,
            evaluation_details=f"AVP error in {layer_key}: {error_code}",
        )
    except Exception as exc:
        logger.error("AVP evaluation error in %s: %s", layer_key, exc)
        return LayerResult(
            decision=Decision.DENY,
            evaluation_details=f"AVP evaluation error: {exc}",
        )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def _build_l2_request(
    envelope: dict,
    cedar_context: dict,
    source_agent_entity: dict,
) -> tuple[dict, list[dict]]:
    """Build the Cedar request and entities for Layer 2 evaluation.

    L2 policies evaluate ``delegate_task`` actions. For ``invoke_tool``
    requests, we reconstruct the delegation: the last agent in the
    delegation chain delegated to the current source agent.

    For ``delegate_task`` requests, the original request is used as-is.
    """
    action_type = envelope["action"]["type"]

    if action_type == "delegate_task":
        # Direct delegation — use the envelope as-is
        resource_id = _extract_resource_id(envelope["action"]["target_resource"])
        target_entity = _build_target_agent_entity(resource_id)
        request = {
            "principal": f'AgentAuthz::Agent::"{envelope["source_agent"]["agent_id"]}"',
            "action": 'AgentAuthz::Action::"delegate_task"',
            "resource": f'AgentAuthz::Agent::"{resource_id}"',
            "context": cedar_context,
        }
        return request, [source_agent_entity, target_entity]

    # invoke_tool — reconstruct the delegation from the chain
    chain = envelope.get("delegation_chain", [])
    source_agent_id = envelope["source_agent"]["agent_id"]

    if chain:
        # The last hop in the chain is the agent that delegated to source_agent
        last_hop = chain[-1]
        delegating_agent_id = last_hop["agent_id"]
    else:
        # No delegation chain — the source agent is acting directly.
        delegating_agent_id = source_agent_id

    delegating_entity = _build_target_agent_entity(delegating_agent_id)
    target_entity = _build_target_agent_entity(source_agent_id)

    request = {
        "principal": f'AgentAuthz::Agent::"{delegating_agent_id}"',
        "action": 'AgentAuthz::Action::"delegate_task"',
        "resource": f'AgentAuthz::Agent::"{source_agent_id}"',
        "context": cedar_context,
    }
    return request, [delegating_entity, target_entity]


def _evaluate_l2_avp(
    envelope: dict,
    cedar_context: dict,
    agent_entity: dict,
) -> LayerResult:
    """Evaluate Layer 2 via Amazon Verified Permissions.

    Reconstructs the delegation relationship and calls AVP IsAuthorized.
    """
    action_type = envelope["action"]["type"]
    source_agent_id = envelope["source_agent"]["agent_id"]

    if action_type == "delegate_task":
        resource_id = _extract_resource_id(envelope["action"]["target_resource"])
        principal_id = source_agent_id
        target_id = resource_id
    else:
        # invoke_tool — reconstruct delegation from chain
        chain = envelope.get("delegation_chain", [])
        if chain:
            principal_id = chain[-1]["agent_id"]
        else:
            principal_id = source_agent_id
        target_id = source_agent_id

    # Build entities for AVP
    delegating_entity = _build_target_agent_entity(principal_id)
    target_entity = _build_target_agent_entity(target_id)
    entities = [delegating_entity, target_entity]

    return _evaluate_layer_avp(
        layer_key="L2",
        principal_type="AgentAuthz::Agent",
        principal_id=principal_id,
        action_type="AgentAuthz::Action",
        action_id="delegate_task",
        resource_type="AgentAuthz::Agent",
        resource_id=target_id,
        cedar_context=cedar_context,
        entities=entities,
    )


def _evaluate_l3_avp(
    envelope: dict,
    cedar_context: dict,
    entities: list[dict],
) -> LayerResult:
    """Evaluate Layer 3 via Amazon Verified Permissions.

    Uses the same principal/action/resource as L1 (agent invoking tool)
    but AVP evaluates L3 policies that check context.originating_user.
    """
    action_type = envelope["action"]["type"]
    source_agent_id = envelope["source_agent"]["agent_id"]
    target_resource = envelope["action"]["target_resource"]
    resource_id = _extract_resource_id(target_resource)

    if action_type == "invoke_tool":
        resource_type = "AgentAuthz::Tool"
        action_id = "invoke_tool"
    else:
        resource_type = "AgentAuthz::Agent"
        action_id = "delegate_task"

    return _evaluate_layer_avp(
        layer_key="L3",
        principal_type="AgentAuthz::Agent",
        principal_id=source_agent_id,
        action_type="AgentAuthz::Action",
        action_id=action_id,
        resource_type=resource_type,
        resource_id=resource_id,
        cedar_context=cedar_context,
        entities=entities,
    )


def evaluate(envelope: dict) -> AuthzDecision:
    """Evaluate a Request Envelope against all three Cedar policy layers.

    Layer 1 is evaluated locally via cedarpy for sub-millisecond latency.
    Layers 2 and 3 are evaluated via Amazon Verified Permissions (AVP),
    which retrieves policies from the deployed policy store.

    When POLICY_STORE_ID is not configured (local testing), all layers
    fall back to local cedarpy evaluation.

    Evaluation order: L1 → L2 → L3, short-circuiting on first DENY.

    Args:
        envelope: A validated Request Envelope dict.

    Returns:
        AuthzDecision with the overall decision, denying layer (if any),
        and per-layer results.
    """
    _refresh_cache_if_needed()

    # ── Pre-check: Rate limiting (temporal constraints) ───────────
    from cedar_evaluator.rate_limiter import check_rate_limits, record_request

    rate_limit_result = check_rate_limits(envelope)
    if rate_limit_result is not None:
        return AuthzDecision(
            decision=Decision.DENY,
            denying_layer="rate-limit",
            layer_results=LayerResults(
                L1=rate_limit_result,
                L2=LayerResult(decision=Decision.DENY, evaluation_details="Not evaluated (rate-limited)"),
                L3=LayerResult(decision=Decision.DENY, evaluation_details="Not evaluated (rate-limited)"),
            ),
        )

    action_type = envelope["action"]["type"]
    target_resource = envelope["action"]["target_resource"]
    resource_id = _extract_resource_id(target_resource)
    source_agent_id = envelope["source_agent"]["agent_id"]

    # Build Cedar context (shared across layers)
    cedar_context = _build_cedar_context(envelope)

    # Build entities
    agent_entity = _build_agent_entity(envelope)
    entities: list[dict] = [agent_entity]

    # Determine Cedar action and resource strings based on action type
    if action_type == "invoke_tool":
        cedar_action = 'AgentAuthz::Action::"invoke_tool"'
        cedar_resource = f'AgentAuthz::Tool::"{resource_id}"'
        entities.append(_build_tool_entity(resource_id, envelope))
    elif action_type == "delegate_task":
        cedar_action = 'AgentAuthz::Action::"delegate_task"'
        cedar_resource = f'AgentAuthz::Agent::"{resource_id}"'
        entities.append(_build_target_agent_entity(resource_id))
    else:
        return AuthzDecision(
            decision=Decision.DENY,
            denying_layer="L1",
            layer_results=LayerResults(
                L1=LayerResult(decision=Decision.DENY, evaluation_details=f"Unknown action type: {action_type}"),
                L2=LayerResult(decision=Decision.DENY, evaluation_details="Not evaluated"),
                L3=LayerResult(decision=Decision.DENY, evaluation_details="Not evaluated"),
            ),
        )

    # Primary Cedar request (used for L1 local evaluation)
    cedar_request = {
        "principal": f'AgentAuthz::Agent::"{source_agent_id}"',
        "action": cedar_action,
        "resource": cedar_resource,
        "context": cedar_context,
    }

    # ── Layer 1: Agent-to-Tool (local cedarpy) ────────────────────
    l1_result = _evaluate_layer_local(
        "L1", _policy_cache["L1_permit"], _policy_cache["L1_forbid"],
        cedar_request, entities,
    )
    if l1_result.decision == Decision.DENY:
        return AuthzDecision(
            decision=Decision.DENY,
            denying_layer="L1",
            layer_results=LayerResults(
                L1=l1_result,
                L2=LayerResult(decision=Decision.DENY, evaluation_details="Not evaluated (short-circuit)"),
                L3=LayerResult(decision=Decision.DENY, evaluation_details="Not evaluated (short-circuit)"),
            ),
        )

    # ── Layer 2: Agent-to-Agent Delegation ────────────────────────
    # L2-004 hard limit: delegation depth > 5 is always denied.
    # This is enforced in Python as a pre-check before calling AVP,
    # since the L2-004 forbid policy is not deployed to AVP.
    delegation_depth = envelope.get("delegation_depth", 0)
    if delegation_depth > 5:
        l2_result = LayerResult(
            decision=Decision.DENY,
            evaluation_details="Delegation depth exceeds hard limit (L2-004)",
        )
        return AuthzDecision(
            decision=Decision.DENY,
            denying_layer="L2",
            layer_results=LayerResults(
                L1=l1_result,
                L2=l2_result,
                L3=LayerResult(decision=Decision.DENY, evaluation_details="Not evaluated (short-circuit)"),
            ),
        )

    # Evaluate L2 via AVP or local fallback
    if POLICY_STORE_ID:
        l2_result = _evaluate_l2_avp(envelope, cedar_context, agent_entity)
    else:
        # Local fallback for testing without AVP
        l2_request, l2_entities = _build_l2_request(envelope, cedar_context, agent_entity)
        l2_result = _evaluate_layer_local(
            "L2", _policy_cache["L2_permit"], _policy_cache["L2_forbid"],
            l2_request, l2_entities,
        )

    if l2_result.decision == Decision.DENY:
        return AuthzDecision(
            decision=Decision.DENY,
            denying_layer="L2",
            layer_results=LayerResults(
                L1=l1_result,
                L2=l2_result,
                L3=LayerResult(decision=Decision.DENY, evaluation_details="Not evaluated (short-circuit)"),
            ),
        )

    # ── Layer 3: Originating User Auth ───────────────────────────
    if POLICY_STORE_ID:
        l3_result = _evaluate_l3_avp(envelope, cedar_context, entities)
    else:
        # Local fallback for testing without AVP
        l3_result = _evaluate_layer_local(
            "L3", _policy_cache["L3_permit"], _policy_cache["L3_forbid"],
            cedar_request, entities,
        )

    if l3_result.decision == Decision.DENY:
        return AuthzDecision(
            decision=Decision.DENY,
            denying_layer="L3",
            layer_results=LayerResults(
                L1=l1_result,
                L2=l2_result,
                L3=l3_result,
            ),
        )

    # ── All three layers PERMIT ───────────────────────────────────
    record_request(envelope)

    return AuthzDecision(
        decision=Decision.PERMIT,
        denying_layer=None,
        layer_results=LayerResults(
            L1=l1_result,
            L2=l2_result,
            L3=l3_result,
        ),
    )
