# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Unit tests for the HMAC-SHA256 context signing module.

Tests cover:
- Canonical string construction from user context
- HMAC-SHA256 signing with known key
- Sign → verify round trip
- AWS Secrets Manager key retrieval with 5-minute TTL cache
- Cache invalidation and expiry

Validates: Requirements 2.1, 2.3, 7.1, 7.4
"""

from __future__ import annotations

import hashlib
import hmac as hmac_mod
import importlib
import time
from dataclasses import dataclass
from unittest.mock import MagicMock, patch

import pytest

_signer = importlib.import_module("mcp_adapter.context_signer")

build_canonical_string = _signer.build_canonical_string
sign_user_context = _signer.sign_user_context
sign_user_context_with_secret = _signer.sign_user_context_with_secret
_get_signing_key = _signer._get_signing_key
_invalidate_key_cache = _signer._invalidate_key_cache


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@dataclass
class FakeUserContext:
    user_id: str
    role: str
    mfa_verified: bool
    authentication_method: str
    session_id: str


def _make_user(**overrides) -> FakeUserContext:
    defaults = {
        "user_id": "user-123",
        "role": "admin",
        "mfa_verified": True,
        "authentication_method": "cognito",
        "session_id": "sess-abc",
    }
    defaults.update(overrides)
    return FakeUserContext(**defaults)


def _make_secrets_client(secret: str = "test-signing-key") -> MagicMock:
    client = MagicMock()
    client.get_secret_value.return_value = {"SecretString": secret}
    return client


# ---------------------------------------------------------------------------
# Tests: build_canonical_string
# ---------------------------------------------------------------------------


class TestBuildCanonicalString:
    def test_basic_canonical_string(self):
        user = _make_user()
        result = build_canonical_string(user)
        assert result == "user-123|admin|True|cognito|sess-abc"

    def test_mfa_false(self):
        user = _make_user(mfa_verified=False)
        result = build_canonical_string(user)
        assert result == "user-123|admin|False|cognito|sess-abc"

    def test_special_characters_in_fields(self):
        user = _make_user(user_id="user|pipe", role="role with spaces")
        result = build_canonical_string(user)
        assert result == "user|pipe|role with spaces|True|cognito|sess-abc"


# ---------------------------------------------------------------------------
# Tests: sign_user_context
# ---------------------------------------------------------------------------


class TestSignUserContext:
    def test_returns_hex_digest(self):
        user = _make_user()
        sig = sign_user_context(user, "my-secret-key")
        # Should be a 64-char hex string (SHA-256 = 32 bytes = 64 hex chars)
        assert len(sig) == 64
        int(sig, 16)  # Should not raise

    def test_deterministic(self):
        user = _make_user()
        sig1 = sign_user_context(user, "key")
        sig2 = sign_user_context(user, "key")
        assert sig1 == sig2

    def test_different_keys_produce_different_signatures(self):
        user = _make_user()
        sig1 = sign_user_context(user, "key-a")
        sig2 = sign_user_context(user, "key-b")
        assert sig1 != sig2

    def test_matches_manual_hmac(self):
        user = _make_user()
        key = "test-key"
        canonical = "user-123|admin|True|cognito|sess-abc"
        expected = hmac_mod.new(
            key.encode(), canonical.encode(), hashlib.sha256
        ).hexdigest()
        assert sign_user_context(user, key) == expected

    def test_different_user_produces_different_signature(self):
        user_a = _make_user(user_id="alice")
        user_b = _make_user(user_id="bob")
        key = "same-key"
        assert sign_user_context(user_a, key) != sign_user_context(user_b, key)


# ---------------------------------------------------------------------------
# Tests: AWS Secrets Manager key retrieval and caching
# ---------------------------------------------------------------------------


class TestGetSigningKey:
    def setup_method(self):
        _invalidate_key_cache()

    def teardown_method(self):
        _invalidate_key_cache()

    def test_retrieves_key_from_secrets_manager(self):
        client = _make_secrets_client("my-key")
        key = _get_signing_key(client)
        assert key == "my-key"
        client.get_secret_value.assert_called_once_with(
            SecretId=_signer.SIGNING_KEY_SECRET_NAME
        )

    def test_caches_key_on_second_call(self):
        client = _make_secrets_client("cached-key")
        _get_signing_key(client)
        _get_signing_key(client)
        # Only one call to AWS Secrets Manager
        assert client.get_secret_value.call_count == 1

    def test_cache_expires_after_ttl(self):
        client = _make_secrets_client("key-v1")
        _get_signing_key(client)

        # Simulate TTL expiry by manipulating the cached timestamp
        _signer._cached_key_timestamp = time.monotonic() - 301

        client.get_secret_value.return_value = {"SecretString": "key-v2"}
        key = _get_signing_key(client)
        assert key == "key-v2"
        assert client.get_secret_value.call_count == 2

    def test_invalidate_cache_forces_refresh(self):
        client = _make_secrets_client("first")
        _get_signing_key(client)
        _invalidate_key_cache()

        client.get_secret_value.return_value = {"SecretString": "second"}
        key = _get_signing_key(client)
        assert key == "second"


# ---------------------------------------------------------------------------
# Tests: sign_user_context_with_secret
# ---------------------------------------------------------------------------


class TestSignUserContextWithSecret:
    def setup_method(self):
        _invalidate_key_cache()

    def teardown_method(self):
        _invalidate_key_cache()

    def test_signs_using_secrets_manager_key(self):
        user = _make_user()
        client = _make_secrets_client("sm-key")
        sig = sign_user_context_with_secret(user, client=client)
        expected = sign_user_context(user, "sm-key")
        assert sig == expected

    def test_round_trip_verify(self):
        """Sign then verify: recomputing with same key should match."""
        user = _make_user()
        key = "round-trip-key"
        sig = sign_user_context(user, key)
        expected = sign_user_context(user, key)
        assert hmac_mod.compare_digest(sig, expected)
