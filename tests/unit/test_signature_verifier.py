# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Unit tests for the HMAC-SHA256 signature verification module.

Tests cover:
- Canonical string reconstruction
- Constant-time signature verification (hmac.compare_digest)
- Key rotation: current key succeeds, previous key within grace period
- AWS Secrets Manager key retrieval with 5-minute TTL cache
- SignatureVerificationError on tampered context
- JSON and plain-string secret formats

Validates: Requirements 2.4, 2.6, 7.1, 7.4
"""

from __future__ import annotations

import hashlib
import hmac as hmac_mod
import importlib
import json
import time
from dataclasses import dataclass
from unittest.mock import MagicMock

import pytest

_verifier = importlib.import_module("cedar_evaluator.signature_verifier")

build_canonical_string = _verifier.build_canonical_string
verify_signature = _verifier.verify_signature
verify_user_context = _verifier.verify_user_context
SignatureVerificationError = _verifier.SignatureVerificationError
_get_signing_keys = _verifier._get_signing_keys
_invalidate_key_cache = _verifier._invalidate_key_cache
_parse_secret = _verifier._parse_secret
_compute_signature = _verifier._compute_signature


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


def _sign(user: FakeUserContext, key: str) -> str:
    """Produce a valid HMAC-SHA256 signature (mirrors context_signer)."""
    canonical = build_canonical_string(user)
    return hmac_mod.new(
        key.encode(), canonical.encode(), hashlib.sha256
    ).hexdigest()


def _make_secrets_client(secret: str = "test-signing-key") -> MagicMock:
    client = MagicMock()
    client.get_secret_value.return_value = {"SecretString": secret}
    return client


# ---------------------------------------------------------------------------
# Tests: build_canonical_string
# ---------------------------------------------------------------------------


class TestBuildCanonicalString:
    def test_matches_signer_format(self):
        user = _make_user()
        result = build_canonical_string(user)
        assert result == "user-123|admin|True|cognito|sess-abc"

    def test_mfa_false(self):
        user = _make_user(mfa_verified=False)
        result = build_canonical_string(user)
        assert "False" in result


# ---------------------------------------------------------------------------
# Tests: verify_signature (constant-time comparison)
# ---------------------------------------------------------------------------


class TestVerifySignature:
    def test_valid_signature_passes(self):
        user = _make_user()
        key = "my-secret"
        sig = _sign(user, key)
        assert verify_signature(user, sig, key) is True

    def test_wrong_key_fails(self):
        user = _make_user()
        sig = _sign(user, "correct-key")
        assert verify_signature(user, sig, "wrong-key") is False

    def test_tampered_user_id_fails(self):
        user = _make_user()
        sig = _sign(user, "key")
        tampered = _make_user(user_id="evil-user")
        assert verify_signature(tampered, sig, "key") is False

    def test_tampered_role_fails(self):
        user = _make_user()
        sig = _sign(user, "key")
        tampered = _make_user(role="superadmin")
        assert verify_signature(tampered, sig, "key") is False

    def test_tampered_mfa_fails(self):
        user = _make_user(mfa_verified=True)
        sig = _sign(user, "key")
        tampered = _make_user(mfa_verified=False)
        assert verify_signature(tampered, sig, "key") is False

    def test_tampered_session_fails(self):
        user = _make_user()
        sig = _sign(user, "key")
        tampered = _make_user(session_id="hijacked-session")
        assert verify_signature(tampered, sig, "key") is False


# ---------------------------------------------------------------------------
# Tests: verify_user_context (with AWS Secrets Manager + key rotation)
# ---------------------------------------------------------------------------


class TestVerifyUserContext:
    def setup_method(self):
        _invalidate_key_cache()

    def teardown_method(self):
        _invalidate_key_cache()

    def test_valid_signature_with_plain_key(self):
        user = _make_user()
        key = "plain-key"
        sig = _sign(user, key)
        client = _make_secrets_client(key)
        assert verify_user_context(user, sig, client=client) is True

    def test_invalid_signature_raises(self):
        user = _make_user()
        client = _make_secrets_client("real-key")
        with pytest.raises(SignatureVerificationError):
            verify_user_context(user, "bad" * 16, client=client)

    def test_key_rotation_current_key_succeeds(self):
        user = _make_user()
        current = "new-key"
        previous = "old-key"
        sig = _sign(user, current)
        secret = json.dumps({"current": current, "previous": previous})
        client = _make_secrets_client(secret)
        assert verify_user_context(user, sig, client=client) is True

    def test_key_rotation_previous_key_succeeds(self):
        user = _make_user()
        current = "new-key"
        previous = "old-key"
        sig = _sign(user, previous)
        secret = json.dumps({"current": current, "previous": previous})
        client = _make_secrets_client(secret)
        assert verify_user_context(user, sig, client=client) is True

    def test_key_rotation_neither_key_raises(self):
        user = _make_user()
        sig = _sign(user, "unknown-key")
        secret = json.dumps({"current": "new-key", "previous": "old-key"})
        client = _make_secrets_client(secret)
        with pytest.raises(SignatureVerificationError):
            verify_user_context(user, sig, client=client)


# ---------------------------------------------------------------------------
# Tests: _parse_secret
# ---------------------------------------------------------------------------


class TestParseSecret:
    def test_plain_string(self):
        keys = _parse_secret("simple-key")
        assert keys.current == "simple-key"
        assert keys.previous is None

    def test_json_current_only(self):
        secret = json.dumps({"current": "cur-key"})
        keys = _parse_secret(secret)
        assert keys.current == "cur-key"
        assert keys.previous is None

    def test_json_current_and_previous(self):
        secret = json.dumps({"current": "cur", "previous": "prev"})
        keys = _parse_secret(secret)
        assert keys.current == "cur"
        assert keys.previous == "prev"
        assert keys.previous_expires_at > time.time()


# ---------------------------------------------------------------------------
# Tests: AWS Secrets Manager caching
# ---------------------------------------------------------------------------


class TestKeyCache:
    def setup_method(self):
        _invalidate_key_cache()

    def teardown_method(self):
        _invalidate_key_cache()

    def test_caches_key_on_second_call(self):
        client = _make_secrets_client("cached-key")
        _get_signing_keys(client)
        _get_signing_keys(client)
        assert client.get_secret_value.call_count == 1

    def test_cache_expires_after_ttl(self):
        client = _make_secrets_client("key-v1")
        _get_signing_keys(client)

        # Simulate TTL expiry
        _verifier._cached_keys_timestamp = time.monotonic() - 301

        client.get_secret_value.return_value = {"SecretString": "key-v2"}
        keys = _get_signing_keys(client)
        assert keys.current == "key-v2"
        assert client.get_secret_value.call_count == 2

    def test_invalidate_forces_refresh(self):
        client = _make_secrets_client("first")
        _get_signing_keys(client)
        _invalidate_key_cache()

        client.get_secret_value.return_value = {"SecretString": "second"}
        keys = _get_signing_keys(client)
        assert keys.current == "second"
