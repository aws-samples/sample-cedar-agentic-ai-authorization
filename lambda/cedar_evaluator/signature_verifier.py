# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""HMAC-SHA256 signature verification for Originating User Context.

Reconstructs the canonical string from user context fields, recomputes
the HMAC-SHA256 digest, and performs constant-time comparison using
``hmac.compare_digest``.  Supports key rotation by trying the current
key first and falling back to the previous key within a 24-hour grace
period.

Validates: Requirements 2.4, 2.6, 7.1, 7.4
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import time
from typing import Protocol

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SIGNING_KEY_SECRET_NAME: str = os.environ.get(
    "SIGNING_KEY_SECRET_NAME", "agent-authz/signing-key"
)

_KEY_CACHE_TTL_SECONDS: int = 300  # 5 minutes
_KEY_ROTATION_GRACE_SECONDS: int = 86_400  # 24 hours

# ---------------------------------------------------------------------------
# Module-level signing key cache
# ---------------------------------------------------------------------------

_cached_keys: _CachedKeys | None = None
_cached_keys_timestamp: float = 0.0


class _CachedKeys:
    """Holds the current and optional previous signing key."""

    __slots__ = ("current", "previous", "previous_expires_at")

    def __init__(
        self,
        current: str,
        previous: str | None = None,
        previous_expires_at: float = 0.0,
    ) -> None:
        self.current = current
        self.previous = previous
        self.previous_expires_at = previous_expires_at


class _UserContextLike(Protocol):
    """Structural type for objects that carry user context fields."""

    user_id: str
    role: str
    mfa_verified: bool
    authentication_method: str
    session_id: str


# ---------------------------------------------------------------------------
# Custom exception
# ---------------------------------------------------------------------------


class SignatureVerificationError(Exception):
    """Raised when HMAC-SHA256 signature verification fails."""



# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def build_canonical_string(user: _UserContextLike) -> str:
    """Build the canonical string for HMAC verification.

    Format: ``user_id|role|mfa_verified|authentication_method|session_id``

    This MUST match the format used by ``context_signer.build_canonical_string``.
    """
    return (
        f"{user.user_id}|{user.role}|{user.mfa_verified}"
        f"|{user.authentication_method}|{user.session_id}"
    )


def _compute_signature(canonical: str, signing_key: str) -> str:
    """Compute HMAC-SHA256 hex digest over a canonical string."""
    return hmac.new(
        signing_key.encode(), canonical.encode(), hashlib.sha256
    ).hexdigest()


def verify_signature(
    user: _UserContextLike,
    signature: str,
    signing_key: str,
) -> bool:
    """Verify the HMAC-SHA256 signature of a user context.

    Uses ``hmac.compare_digest`` for constant-time comparison to
    prevent timing side-channel attacks.

    Args:
        user: Object with the five user context fields.
        signature: The hex-encoded HMAC-SHA256 signature to verify.
        signing_key: The secret key used for HMAC computation.

    Returns:
        ``True`` if the signature is valid, ``False`` otherwise.
    """
    canonical = build_canonical_string(user)
    expected = _compute_signature(canonical, signing_key)
    return hmac.compare_digest(expected, signature)


def verify_user_context(
    user: _UserContextLike,
    signature: str,
    client: object | None = None,
) -> bool:
    """Verify user context signature using keys from AWS Secrets Manager.

    Tries the current signing key first.  If verification fails and a
    previous key exists within the 24-hour rotation grace period, retries
    with the previous key.

    Args:
        user: Object with the five user context fields.
        signature: The hex-encoded HMAC-SHA256 signature to verify.
        client: Optional boto3 AWS Secrets Manager client.

    Returns:
        ``True`` if the signature is valid with either key.

    Raises:
        SignatureVerificationError: If verification fails with all
            available keys.
    """
    keys = _get_signing_keys(client)

    # Try current key first
    if verify_signature(user, signature, keys.current):
        return True

    # Try previous key if within grace period
    if keys.previous is not None and time.time() < keys.previous_expires_at:
        if verify_signature(user, signature, keys.previous):
            logger.info("Signature verified with previous (rotated) key")
            return True

    logger.warning(
        "Signature verification failed for user_id=%s session_id=%s",
        user.user_id,
        user.session_id,
    )
    raise SignatureVerificationError(
        f"HMAC-SHA256 signature verification failed for user {user.user_id}"
    )


# ---------------------------------------------------------------------------
# AWS Secrets Manager key retrieval with TTL cache and rotation support
# ---------------------------------------------------------------------------


def _get_signing_keys(client: object | None = None) -> _CachedKeys:
    """Retrieve signing keys from AWS Secrets Manager with TTL cache.

    The secret value may be either:
    - A plain string (current key only)
    - A JSON object with ``current`` and optionally ``previous`` fields

    The keys are cached at module level for ``_KEY_CACHE_TTL_SECONDS``
    (default 5 minutes).
    """
    global _cached_keys, _cached_keys_timestamp  # noqa: PLW0603

    now = time.monotonic()
    if _cached_keys is not None and (now - _cached_keys_timestamp) < _KEY_CACHE_TTL_SECONDS:
        return _cached_keys

    if client is None:
        import boto3

        client = boto3.client("secretsmanager")

    response = client.get_secret_value(SecretId=SIGNING_KEY_SECRET_NAME)  # type: ignore[union-attr]
    secret = response["SecretString"]

    _cached_keys = _parse_secret(secret)
    _cached_keys_timestamp = now
    return _cached_keys


def _parse_secret(secret: str) -> _CachedKeys:
    """Parse an AWS Secrets Manager secret into current + previous keys.

    Supports two formats:
    1. Plain string → current key only
    2. JSON ``{"current": "...", "previous": "..."}`` → both keys
       with a 24-hour grace period for the previous key.
    """
    try:
        data = json.loads(secret)
        if isinstance(data, dict) and "current" in data:
            previous = data.get("previous")
            expires = time.time() + _KEY_ROTATION_GRACE_SECONDS if previous else 0.0
            return _CachedKeys(
                current=data["current"],
                previous=previous,
                previous_expires_at=expires,
            )
    except (json.JSONDecodeError, TypeError):
        pass

    # Plain string — current key only
    return _CachedKeys(current=secret)


def _invalidate_key_cache() -> None:
    """Invalidate the cached signing keys (useful for testing)."""
    global _cached_keys, _cached_keys_timestamp  # noqa: PLW0603
    _cached_keys = None
    _cached_keys_timestamp = 0.0
