# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Property 6: HMAC-SHA256 signing round trip and tamper detection.

For any Originating_User_Context and for any signing key, signing the context
and then verifying the signature SHALL succeed (round trip). Furthermore, for
any modification to any single field of the Originating_User_Context after
signing, verification SHALL fail.

**Validates: Requirements 2.3, 2.4, 2.6, 7.1**

Feature: agent-authz-protection
Property 6: HMAC-SHA256 signing round trip and tamper detection
"""

from __future__ import annotations

import importlib
import sys
from dataclasses import dataclass
from pathlib import Path

from hypothesis import given, settings, assume
from hypothesis import strategies as st

_project_root = Path(__file__).resolve().parent.parent.parent
_lambda_dir = _project_root / "lambda"
if str(_lambda_dir) not in sys.path:
    sys.path.insert(0, str(_lambda_dir))

_signer = importlib.import_module("mcp_adapter.context_signer")
_verifier = importlib.import_module("cedar_evaluator.signature_verifier")

sign_user_context = _signer.sign_user_context
verify_signature = _verifier.verify_signature


# ---------------------------------------------------------------------------
# Lightweight user context dataclass for testing
# ---------------------------------------------------------------------------

@dataclass
class _UserCtx:
    user_id: str
    role: str
    mfa_verified: bool
    authentication_method: str
    session_id: str


# ---------------------------------------------------------------------------
# Hypothesis strategies
# ---------------------------------------------------------------------------

# Non-empty printable text without pipe characters (pipe is the delimiter)
_field_text = st.text(
    alphabet=st.characters(categories=("L", "N")),
    min_size=1,
    max_size=32,
).filter(lambda s: s.strip() and "|" not in s)

_signing_key = st.text(
    alphabet=st.characters(categories=("L", "N")),
    min_size=8,
    max_size=64,
).filter(lambda s: s.strip())

_mfa_st = st.booleans()

_tamper_field = st.sampled_from([
    "user_id", "role", "mfa_verified", "authentication_method", "session_id",
])


# ---------------------------------------------------------------------------
# Property test: round trip
# ---------------------------------------------------------------------------

@settings(max_examples=100)
@given(
    user_id=_field_text,
    role=_field_text,
    mfa=_mfa_st,
    auth_method=_field_text,
    session_id=_field_text,
    key=_signing_key,
)
def test_hmac_roundtrip_always_succeeds(
    user_id: str,
    role: str,
    mfa: bool,
    auth_method: str,
    session_id: str,
    key: str,
) -> None:
    """Property 6a — Sign then verify always succeeds.

    **Validates: Requirements 2.3, 2.4, 2.6, 7.1**
    """
    ctx = _UserCtx(user_id, role, mfa, auth_method, session_id)
    signature = sign_user_context(ctx, key)
    assert verify_signature(ctx, signature, key) is True


# ---------------------------------------------------------------------------
# Property test: tamper detection
# ---------------------------------------------------------------------------

@settings(max_examples=100)
@given(
    user_id=_field_text,
    role=_field_text,
    mfa=_mfa_st,
    auth_method=_field_text,
    session_id=_field_text,
    key=_signing_key,
    tamper=_tamper_field,
    tamper_value=_field_text,
)
def test_hmac_tamper_detection(
    user_id: str,
    role: str,
    mfa: bool,
    auth_method: str,
    session_id: str,
    key: str,
    tamper: str,
    tamper_value: str,
) -> None:
    """Property 6b — Mutating any single field after signing causes verification failure.

    **Validates: Requirements 2.3, 2.4, 2.6, 7.1**
    """
    ctx = _UserCtx(user_id, role, mfa, auth_method, session_id)
    signature = sign_user_context(ctx, key)

    # Create a tampered copy
    tampered = _UserCtx(user_id, role, mfa, auth_method, session_id)

    if tamper == "user_id":
        assume(tamper_value != user_id)
        tampered.user_id = tamper_value
    elif tamper == "role":
        assume(tamper_value != role)
        tampered.role = tamper_value
    elif tamper == "mfa_verified":
        tampered.mfa_verified = not mfa
    elif tamper == "authentication_method":
        assume(tamper_value != auth_method)
        tampered.authentication_method = tamper_value
    elif tamper == "session_id":
        assume(tamper_value != session_id)
        tampered.session_id = tamper_value

    assert verify_signature(tampered, signature, key) is False
