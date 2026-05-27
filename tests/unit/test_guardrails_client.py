# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Unit tests for the Amazon Bedrock Guardrails content filtering client.

Tests cover:
- Successful guardrail application with various response shapes
- Service unavailability handling (ClientError, EndpointConnectionError)
- Injection score extraction from different assessment types
- Dict and string request body handling

Validates: Requirements 5.3, 5.4
"""

from __future__ import annotations

import importlib
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError, EndpointConnectionError

# ``lambda`` is a Python keyword, so we use importlib to import from it.
_guardrails_mod = importlib.import_module("mcp_adapter.guardrails_client")
_types_mod = importlib.import_module("shared.types")

GuardrailsUnavailableError = _guardrails_mod.GuardrailsUnavailableError
_confidence_to_score = _guardrails_mod._confidence_to_score
_extract_injection_score = _guardrails_mod._extract_injection_score
_parse_guardrail_response = _guardrails_mod._parse_guardrail_response
apply_guardrail = _guardrails_mod.apply_guardrail
ContentFilterResult = _types_mod.ContentFilterResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_mock_client(response: dict):
    """Create a mock bedrock-runtime client returning the given response."""
    client = MagicMock()
    client.apply_guardrail.return_value = response
    return client


def _no_intervention_response() -> dict:
    return {"action": "NONE", "assessments": []}


def _intervened_response_with_topic() -> dict:
    return {
        "action": "GUARDRAIL_INTERVENED",
        "assessments": [
            {
                "topicPolicy": {
                    "topics": [{"name": "injection", "action": "BLOCKED"}]
                }
            }
        ],
    }


def _intervened_response_no_scores() -> dict:
    return {"action": "GUARDRAIL_INTERVENED", "assessments": []}


def _content_filter_response(confidence: str) -> dict:
    return {
        "action": "NONE",
        "assessments": [
            {
                "contentPolicy": {
                    "filters": [
                        {"type": "HATE", "confidence": confidence, "action": "NONE"}
                    ]
                }
            }
        ],
    }


# ---------------------------------------------------------------------------
# Tests: apply_guardrail
# ---------------------------------------------------------------------------


class TestApplyGuardrail:
    """Tests for the apply_guardrail function."""

    def test_returns_content_filter_result_no_intervention(self):
        client = _make_mock_client(_no_intervention_response())
        result = apply_guardrail(
            '{"jsonrpc":"2.0"}',
            guardrail_id="gr-123",
            guardrail_version="1",
            client=client,
        )
        assert isinstance(result, ContentFilterResult)
        assert result.filter_applied is False
        assert result.injection_score == 0
        assert result.filter_source == "bedrock-guardrails"

    def test_returns_filter_applied_on_intervention(self):
        client = _make_mock_client(_intervened_response_with_topic())
        result = apply_guardrail(
            '{"jsonrpc":"2.0"}',
            guardrail_id="gr-123",
            client=client,
        )
        assert result.filter_applied is True
        assert result.injection_score == 100

    def test_accepts_dict_request_body(self):
        client = _make_mock_client(_no_intervention_response())
        result = apply_guardrail(
            {"jsonrpc": "2.0", "method": "tools/call"},
            guardrail_id="gr-123",
            client=client,
        )
        assert isinstance(result, ContentFilterResult)
        # Verify the client was called with serialized JSON
        call_args = client.apply_guardrail.call_args
        content = call_args[1]["content"] if "content" in call_args[1] else call_args.kwargs["content"]
        assert content[0]["text"]["text"] == '{"jsonrpc": "2.0", "method": "tools/call"}'

    def test_accepts_string_request_body(self):
        client = _make_mock_client(_no_intervention_response())
        raw = '{"jsonrpc":"2.0"}'
        apply_guardrail(raw, guardrail_id="gr-123", client=client)
        call_args = client.apply_guardrail.call_args
        content = call_args.kwargs["content"]
        assert content[0]["text"]["text"] == raw

    def test_raises_on_client_error(self):
        client = MagicMock()
        client.apply_guardrail.side_effect = ClientError(
            {"Error": {"Code": "ServiceUnavailableException", "Message": "down"}},
            "ApplyGuardrail",
        )
        with pytest.raises(GuardrailsUnavailableError):
            apply_guardrail("body", guardrail_id="gr-123", client=client)

    def test_raises_on_endpoint_connection_error(self):
        client = MagicMock()
        client.apply_guardrail.side_effect = EndpointConnectionError(
            endpoint_url="https://bedrock-runtime.us-east-1.amazonaws.com"
        )
        with pytest.raises(GuardrailsUnavailableError):
            apply_guardrail("body", guardrail_id="gr-123", client=client)

    def test_uses_env_defaults(self):
        client = _make_mock_client(_no_intervention_response())
        original_id = _guardrails_mod.GUARDRAIL_ID
        original_version = _guardrails_mod.GUARDRAIL_VERSION
        try:
            _guardrails_mod.GUARDRAIL_ID = "env-gr-id"
            _guardrails_mod.GUARDRAIL_VERSION = "3"
            apply_guardrail("body", client=client)
            call_args = client.apply_guardrail.call_args.kwargs
            assert call_args["guardrailIdentifier"] == "env-gr-id"
            assert call_args["guardrailVersion"] == "3"
        finally:
            _guardrails_mod.GUARDRAIL_ID = original_id
            _guardrails_mod.GUARDRAIL_VERSION = original_version


# ---------------------------------------------------------------------------
# Tests: _parse_guardrail_response
# ---------------------------------------------------------------------------


class TestParseGuardrailResponse:
    """Tests for response parsing logic."""

    def test_no_intervention(self):
        result = _parse_guardrail_response(_no_intervention_response())
        assert result.filter_applied is False
        assert result.injection_score == 0

    def test_intervention_with_topic_blocked(self):
        result = _parse_guardrail_response(_intervened_response_with_topic())
        assert result.filter_applied is True
        assert result.injection_score == 100

    def test_intervention_no_granular_scores_defaults_to_100(self):
        result = _parse_guardrail_response(_intervened_response_no_scores())
        assert result.filter_applied is True
        assert result.injection_score == 100


# ---------------------------------------------------------------------------
# Tests: _extract_injection_score
# ---------------------------------------------------------------------------


class TestExtractInjectionScore:
    """Tests for injection score extraction from various assessment types."""

    def test_empty_assessments(self):
        assert _extract_injection_score({"action": "NONE", "assessments": []}) == 0

    def test_topic_blocked(self):
        resp = _intervened_response_with_topic()
        assert _extract_injection_score(resp) == 100

    def test_content_filter_high_confidence(self):
        resp = _content_filter_response("HIGH")
        assert _extract_injection_score(resp) == 75

    def test_content_filter_medium_confidence(self):
        resp = _content_filter_response("MEDIUM")
        assert _extract_injection_score(resp) == 50

    def test_content_filter_low_confidence(self):
        resp = _content_filter_response("LOW")
        assert _extract_injection_score(resp) == 25

    def test_word_policy_custom_words(self):
        resp = {
            "action": "GUARDRAIL_INTERVENED",
            "assessments": [{"wordPolicy": {"customWords": [{"match": "badword"}]}}],
        }
        assert _extract_injection_score(resp) == 100

    def test_sensitive_info_pii(self):
        resp = {
            "action": "NONE",
            "assessments": [
                {"sensitiveInformationPolicy": {"piiEntities": [{"type": "EMAIL"}]}}
            ],
        }
        assert _extract_injection_score(resp) == 75

    def test_contextual_grounding_low_score(self):
        resp = {
            "action": "NONE",
            "assessments": [
                {
                    "contextualGroundingPolicy": {
                        "filters": [{"type": "GROUNDING", "score": 0.2}]
                    }
                }
            ],
        }
        # 1 - 0.2 = 0.8 → 80
        assert _extract_injection_score(resp) == 80

    def test_intervention_no_scores_defaults_100(self):
        resp = {"action": "GUARDRAIL_INTERVENED", "assessments": []}
        assert _extract_injection_score(resp) == 100

    def test_max_score_capped_at_100(self):
        resp = {
            "action": "GUARDRAIL_INTERVENED",
            "assessments": [
                {
                    "topicPolicy": {
                        "topics": [{"name": "a", "action": "BLOCKED"}]
                    },
                    "contentPolicy": {
                        "filters": [{"confidence": "HIGH"}]
                    },
                }
            ],
        }
        assert _extract_injection_score(resp) <= 100


# ---------------------------------------------------------------------------
# Tests: _confidence_to_score
# ---------------------------------------------------------------------------


class TestConfidenceToScore:
    """Tests for confidence level mapping."""

    @pytest.mark.parametrize(
        "confidence,expected",
        [("NONE", 0), ("LOW", 25), ("MEDIUM", 50), ("HIGH", 75), ("UNKNOWN", 0)],
    )
    def test_mapping(self, confidence: str, expected: int):
        assert _confidence_to_score(confidence) == expected
