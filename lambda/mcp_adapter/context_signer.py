# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""HMAC-SHA256 context signing for Originating User Context.

Constructs a canonical string from user context fields and computes
an HMAC-SHA256 signature using a signing key retrieved from AWS
Secrets Manager (cached with a 5-minute TTL).

Validates: Requirements 2.1, 2.3, 7.1, 7.4
"""

from __future__ import annotations

import hashlib
import hmac
import os
import time
from typing import TYPE_CHECKING, Protocol, Union

if TYPE_CHECKING:
    pass

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SIGNING_KEY_SECRET_NAME: str = os.environ.get(
    "SIGNING_KEY_SECRET_NAME", "agent-authz/signing-key"
)

_KEY_CACHE_TTL_SECONDS: int = 300  # 5 minutes

# ---------------------------------------------------------------------------
# Module-level signing key cache
# ---------------------------------------------------------------------------

_cached_key: str | None = None
_cached_key_timestamp: float = 0.0


class _UserContextLike(Protocol):
    """Structural type for objects that carry user context fields."""

    user_id: str
    role: str
    mfa_verified: bool
    authentication_method: str
    session_id: str


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def build_canonical_string(user: _UserContextLike) -> str:
    """Build the canonical string for HMAC signing.

    Format: ``user_id|role|mfa_verified|authentication_method|session_id``
    """
    return (
        f"{user.user_id}|{user.role}|{user.mfa_verified}"
        f"|{user.authentication_method}|{user.session_id}"
    )


def sign_user_context(user: _UserContextLike, signing_key: str) -> str:
    """Compute HMAC-SHA256 over the canonical user context string.

    Args:
        user: An object with user_id, role, mfa_verified,
              authentication_method, and session_id attributes.
        signing_key: The secret key used for HMAC computation.

    Returns:
        Hex digest of the HMAC-SHA256 signature.
    """
    canonical = build_canonical_string(user)
    return hmac.new(
        signing_key.encode(), canonical.encode(), hashlib.sha256
    ).hexdigest()


def sign_user_context_with_secret(
    user: _UserContextLike,
    client: object | None = None,
) -> str:
    """Sign user context using the signing key from AWS Secrets Manager.

    Retrieves the signing key from AWS Secrets Manager (with 5-minute
    TTL caching) and computes the HMAC-SHA256 signature.

    Args:
        user: An object with the five user context fields.
        client: Optional boto3 AWS Secrets Manager client. If ``None``,
                a default client is created.

    Returns:
        Hex digest of the HMAC-SHA256 signature.
    """
    key = _get_signing_key(client)
    return sign_user_context(user, key)


# ---------------------------------------------------------------------------
# AWS Secrets Manager key retrieval with TTL cache
# ---------------------------------------------------------------------------


def _get_signing_key(client: object | None = None) -> str:
    """Retrieve the signing key from AWS Secrets Manager, using a TTL cache.

    The key is cached at module level for ``_KEY_CACHE_TTL_SECONDS``
    (default 5 minutes) to avoid repeated AWS Secrets Manager calls on
    warm Lambda invocations.
    """
    global _cached_key, _cached_key_timestamp  # noqa: PLW0603

    now = time.monotonic()
    if _cached_key is not None and (now - _cached_key_timestamp) < _KEY_CACHE_TTL_SECONDS:
        return _cached_key

    if client is None:
        import boto3

        client = boto3.client("secretsmanager")

    response = client.get_secret_value(SecretId=SIGNING_KEY_SECRET_NAME)  # type: ignore[union-attr]
    secret = response["SecretString"]

    _cached_key = secret
    _cached_key_timestamp = now
    return secret


def _invalidate_key_cache() -> None:
    """Invalidate the cached signing key (useful for testing)."""
    global _cached_key, _cached_key_timestamp  # noqa: PLW0603
    _cached_key = None
    _cached_key_timestamp = 0.0
