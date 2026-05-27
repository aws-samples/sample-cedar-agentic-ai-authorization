# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Shared types for the Agent Authorization Protection system.

Pydantic models for request/response structures and dataclasses for
simpler internal data structures.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------------
# Pydantic models for Cedar entities and request envelope
# ---------------------------------------------------------------------------


class SourceAgent(BaseModel):
    """Source agent identity in the request envelope."""

    agent_id: str
    trust_level: int = Field(ge=1, le=5)
    namespace: str
    registered_capabilities: list[str] = Field(default_factory=list)
    lifecycle_stage: str


class Action(BaseModel):
    """Action being requested."""

    type: str = Field(pattern=r"^(invoke_tool|delegate_task)$")
    target_resource: str
    requested_capabilities: list[str] = Field(default_factory=list)


class DelegationHop(BaseModel):
    """A single hop in the delegation chain."""

    hop: int
    agent_id: str
    capabilities_granted: list[str] = Field(default_factory=list)
    timestamp: str


class OriginatingUserContext(BaseModel):
    """Originating user identity, cryptographically signed at the entry point."""

    user_id: str
    role: str
    mfa_verified: bool
    authentication_method: str
    session_id: str
    signature: str

    @field_validator("signature")
    @classmethod
    def validate_hex_signature(cls, v: str) -> str:
        """Validate that signature is a valid hex string."""
        try:
            int(v, 16)
        except ValueError as exc:
            raise ValueError("signature must be a valid hex string") from exc
        return v


class ContentFilterResult(BaseModel):
    """Amazon Bedrock Guardrails content filtering result."""

    injection_score: int = Field(ge=0, le=100)
    filter_applied: bool
    filter_source: str = "bedrock-guardrails"


class RequestEnvelope(BaseModel):
    """Normalized request envelope for Cedar policy evaluation."""

    request_id: str
    timestamp: str
    source_protocol: str = "MCP"
    source_agent: SourceAgent
    action: Action
    delegation_chain: list[DelegationHop] = Field(default_factory=list)
    delegation_depth: int = Field(ge=0)
    originating_user: OriginatingUserContext
    content_filter_result: ContentFilterResult


# ---------------------------------------------------------------------------
# Dataclasses for Cedar entity representations
# ---------------------------------------------------------------------------


@dataclass
class Agent:
    """Cedar Agent entity representation."""

    agent_id: str
    trust_level: int
    namespace: str
    registered_capabilities: list[str] = field(default_factory=list)
    lifecycle_stage: str = "production"
    trust_zone: Optional[str] = None


@dataclass
class Tool:
    """Cedar Tool entity representation."""

    tool_id: str
    namespace: str
    risk_level: str
    data_classification: Optional[str] = None


# ---------------------------------------------------------------------------
# Authorization decision types
# ---------------------------------------------------------------------------


class Decision(str, Enum):
    """Authorization decision."""

    PERMIT = "PERMIT"
    DENY = "DENY"


@dataclass
class LayerResult:
    """Result from a single Cedar policy layer evaluation."""

    decision: Decision
    evaluation_details: Optional[str] = None


@dataclass
class LayerResults:
    """Per-layer evaluation results."""

    L1: LayerResult
    L2: LayerResult
    L3: LayerResult


@dataclass
class AuthzDecision:
    """Final authorization decision with per-layer results."""

    decision: Decision
    denying_layer: Optional[str] = None
    layer_results: Optional[LayerResults] = None


# ---------------------------------------------------------------------------
# OCSF 99001 event structure
# ---------------------------------------------------------------------------


@dataclass
class OcsfUser:
    """OCSF actor user."""

    uid: str
    type: str = "User"
    role: str = ""
    mfa_enabled: bool = False


@dataclass
class OcsfSession:
    """OCSF actor session."""

    uid: str


@dataclass
class OcsfActor:
    """OCSF actor (originating user + session)."""

    user: OcsfUser
    session: OcsfSession


@dataclass
class OcsfAgentEntry:
    """Single agent in the OCSF src_endpoint agent_list."""

    name: str
    uid: str


@dataclass
class OcsfSrcEndpoint:
    """OCSF source endpoint with agent list."""

    agent_list: list[OcsfAgentEntry] = field(default_factory=list)


@dataclass
class OcsfPolicy:
    """OCSF authorization policy."""

    name: str
    uid: str


@dataclass
class OcsfAuthorization:
    """OCSF authorization block."""

    decision: str
    policy: OcsfPolicy


@dataclass
class OcsfResource:
    """OCSF resource."""

    name: str
    type: str
    uid: str


@dataclass
class OcsfProduct:
    """OCSF metadata product."""

    name: str = "AgentAuthzProtection"
    vendor_name: str = "Custom"


@dataclass
class OcsfMetadata:
    """OCSF metadata."""

    version: str = "1.3.0"
    product: OcsfProduct = field(default_factory=OcsfProduct)


@dataclass
class OcsfUnmapped:
    """OCSF unmapped fields for originating user auth specifics."""

    delegation_depth: int = 0
    delegation_chain: list[str] = field(default_factory=list)
    content_filter_score: int = 0
    layer_results: dict[str, str] = field(default_factory=dict)
    denying_layer: Optional[str] = None
    request_id: str = ""
    evaluation_latency_ms: float = 0.0


@dataclass
class OcsfEvent:
    """OCSF 99001 Agent Policy Evaluation event."""

    class_uid: int = 99001
    class_name: str = "Agent Policy Evaluation"
    category_uid: int = 3
    activity_id: int = 1
    time: str = ""
    severity_id: int = 1
    status_id: int = 1
    message: str = "Cedar policy evaluation completed"
    actor: OcsfActor = field(default_factory=lambda: OcsfActor(
        user=OcsfUser(uid=""), session=OcsfSession(uid="")
    ))
    src_endpoint: OcsfSrcEndpoint = field(default_factory=OcsfSrcEndpoint)
    authorization: OcsfAuthorization = field(default_factory=lambda: OcsfAuthorization(
        decision="", policy=OcsfPolicy(name="", uid="")
    ))
    resources: list[OcsfResource] = field(default_factory=list)
    metadata: OcsfMetadata = field(default_factory=OcsfMetadata)
    unmapped: OcsfUnmapped = field(default_factory=OcsfUnmapped)
