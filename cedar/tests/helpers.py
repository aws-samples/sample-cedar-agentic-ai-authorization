# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Shared helpers for Cedar policy unit tests."""

from pathlib import Path

# Root of the cedar directory
CEDAR_ROOT = Path(__file__).resolve().parent.parent

LAYER1_DIR = CEDAR_ROOT / "policies" / "layer1-agent-to-tool"
LAYER2_DIR = CEDAR_ROOT / "policies" / "layer2-agent-to-agent"
LAYER3_DIR = CEDAR_ROOT / "policies" / "layer3-originating-user-auth"


def load_policies(directory: Path) -> str:
    """Load and concatenate all .cedar files in a directory."""
    policies = []
    for f in sorted(directory.glob("*.cedar")):
        policies.append(f.read_text())
    return "\n".join(policies)


def load_single_policy(filepath: Path) -> str:
    """Load a single .cedar policy file."""
    return filepath.read_text()


def make_agent_entity(
    agent_id: str,
    trust_level: int = 3,
    namespace: str = "default",
    lifecycle_stage: str = "production",
    registered_capabilities: list | None = None,
) -> dict:
    """Build a Cedar Agent entity dict for cedarpy."""
    return {
        "uid": {"type": "AgentAuthz::Agent", "id": agent_id},
        "attrs": {
            "trust_level": trust_level,
            "namespace": namespace,
            "lifecycle_stage": lifecycle_stage,
            "registered_capabilities": registered_capabilities or [],
        },
        "parents": [],
    }


def make_tool_entity(
    tool_id: str,
    namespace: str = "default",
    risk_level: str = "low",
    data_classification: str = "",
) -> dict:
    """Build a Cedar Tool entity dict for cedarpy."""
    return {
        "uid": {"type": "AgentAuthz::Tool", "id": tool_id},
        "attrs": {
            "namespace": namespace,
            "risk_level": risk_level,
            "data_classification": data_classification,
        },
        "parents": [],
    }


def make_invoke_request(
    agent_id: str,
    tool_id: str,
    context: dict | None = None,
) -> dict:
    """Build a Cedar authorization request for invoke_tool."""
    return {
        "principal": f'AgentAuthz::Agent::"{agent_id}"',
        "action": 'AgentAuthz::Action::"invoke_tool"',
        "resource": f'AgentAuthz::Tool::"{tool_id}"',
        "context": context or {},
    }


def make_delegate_request(
    from_agent: str,
    to_agent: str,
    context: dict | None = None,
) -> dict:
    """Build a Cedar authorization request for delegate_task."""
    return {
        "principal": f'AgentAuthz::Agent::"{from_agent}"',
        "action": 'AgentAuthz::Action::"delegate_task"',
        "resource": f'AgentAuthz::Agent::"{to_agent}"',
        "context": context or {},
    }
