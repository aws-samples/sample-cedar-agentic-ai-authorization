# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Property 5: User context extraction completeness.

For any valid MCP request containing user identity data, the Protocol
Adapter's extraction logic SHALL produce an OriginatingUserContext where
all five fields (user_id, role, mfa_verified, authentication_method,
session_id) are populated and match the corresponding values from the
input request.

**Validates: Requirements 2.1**

Feature: agent-authz-protection
Property 5: User context extraction completeness
"""

from __future__ import annotations

import importlib

from hypothesis import given, settings
from hypothesis import strategies as st

_parser_mod = importlib.import_module("mcp_adapter.mcp_parser")
parse_mcp_message = _parser_mod.parse_mcp_message


# Strategy: non-empty printable strings without pipe characters (pipes are
# used as delimiters in the canonical signing string, but the parser itself
# does not restrict them — we keep the generator simple and realistic).
_nonempty_text = st.text(
    alphabet=st.characters(whitelist_categories=("L", "N", "P", "S", "Z")),
    min_size=1,
    max_size=64,
).filter(lambda s: s.strip())


def _build_mcp_message(
    user_id: str,
    role: str,
    mfa_verified: bool,
    authentication_method: str,
    session_id: str,
) -> dict:
    """Build a minimal valid MCP tool call message with the given user context."""
    return {
        "jsonrpc": "2.0",
        "method": "tools/call",
        "id": "prop5-req",
        "params": {
            "name": "some_tool",
            "arguments": {},
            "_meta": {
                "user_context": {
                    "user_id": user_id,
                    "role": role,
                    "mfa_verified": mfa_verified,
                    "authentication_method": authentication_method,
                    "session_id": session_id,
                },
            },
        },
    }


@settings(max_examples=100)
@given(
    user_id=_nonempty_text,
    role=_nonempty_text,
    mfa_verified=st.booleans(),
    authentication_method=_nonempty_text,
    session_id=_nonempty_text,
)
def test_user_context_extraction_completeness(
    user_id: str,
    role: str,
    mfa_verified: bool,
    authentication_method: str,
    session_id: str,
) -> None:
    """Property 5 — User context extraction completeness.

    **Validates: Requirements 2.1**
    """
    msg = _build_mcp_message(user_id, role, mfa_verified, authentication_method, session_id)
    result = parse_mcp_message(msg)

    uc = result.user_context
    assert uc is not None, "user_context must not be None"

    # All five fields populated and matching input
    assert uc.user_id == user_id
    assert uc.role == role
    assert uc.mfa_verified is mfa_verified
    assert uc.authentication_method == authentication_method
    assert uc.session_id == session_id
