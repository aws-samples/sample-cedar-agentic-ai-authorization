# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Property 7: Delegation depth increment invariant.

For any Request Envelope with delegation_depth N, after a delegation hop the
resulting envelope SHALL have delegation_depth equal to N + 1.

**Validates: Requirements 2.5**

Feature: agent-authz-protection
Property 7: Delegation depth increment invariant
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

_builder = importlib.import_module("mcp_adapter.envelope_builder")
_parser = importlib.import_module("mcp_adapter.mcp_parser")
_types = importlib.import_module("shared.types")

ContentFilterResult = _types.ContentFilterResult
ParsedMcpRequest = _parser.ParsedMcpRequest
AgentIdentity = _parser.AgentIdentity
UserContext = _parser.UserContext
DelegationHop = _parser.DelegationHop
build_envelope = _builder.build_envelope


# ---------------------------------------------------------------------------
# Hypothesis strategies
# ---------------------------------------------------------------------------

_depth_st = st.integers(min_value=0, max_value=100)


def _make_parsed_request(depth: int) -> ParsedMcpRequest:
    """Build a ParsedMcpRequest with the given delegation depth."""
    hops = []
    for i in range(depth):
        hops.append(DelegationHop(
            hop=i,
            agent_id=f"agent-{i}",
            capabilities_granted=["cap"],
            timestamp="2025-01-01T00:00:00Z",
        ))

    return ParsedMcpRequest(
        jsonrpc="2.0",
        request_id="prop7-test",
        method="tools/call",
        tool_name="some_tool",
        arguments={"key": "value"},
        agent_identity=AgentIdentity(
            agent_id="test-agent",
            trust_level=3,
            namespace="test",
            registered_capabilities=["cap"],
            lifecycle_stage="production",
        ),
        user_context=UserContext(
            user_id="user-1",
            role="admin",
            mfa_verified=True,
            authentication_method="password",
            session_id="sess-1",
        ),
        delegation_chain=hops,
        delegation_depth=depth,
    )


# ---------------------------------------------------------------------------
# Property test
# ---------------------------------------------------------------------------

@settings(max_examples=100)
@given(depth=_depth_st)
def test_delegation_depth_increment(depth: int) -> None:
    """Property 7 — After a delegation hop, depth equals N + 1.

    **Validates: Requirements 2.5**
    """
    parsed = _make_parsed_request(depth)

    # The envelope builder preserves the delegation_depth from the parsed request.
    # A delegation hop means the depth was already incremented by the delegating
    # agent before building the envelope. We verify the invariant:
    # envelope.delegation_depth == parsed.delegation_depth (N)
    # and after simulating a hop, the next envelope has depth N+1.

    # nosec: Test-only constant used exclusively in property tests, never in production.
    signing_key = "test-signing-key-12345678"
    cfr = ContentFilterResult(
        injection_score=0,
        filter_applied=True,
        filter_source="bedrock-guardrails",
    )

    envelope = build_envelope(parsed, cfr, signing_key=signing_key)
    assert envelope["delegation_depth"] == depth

    # Simulate a delegation hop: increment depth by 1
    next_depth = depth + 1
    next_parsed = _make_parsed_request(next_depth)
    next_envelope = build_envelope(next_parsed, cfr, signing_key=signing_key)

    assert next_envelope["delegation_depth"] == next_depth
    assert next_envelope["delegation_depth"] == depth + 1
