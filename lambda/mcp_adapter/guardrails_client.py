# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Amazon Bedrock Guardrails content filtering client.

Calls the Amazon Bedrock Runtime ApplyGuardrail API on raw MCP request bodies
to detect prompt injection and other content policy violations. Returns
a ContentFilterResult with injection_score, filter_applied, and filter_source.

Validates: Requirements 5.3, 5.4
"""

from __future__ import annotations

import json
import logging
import os
from typing import Union

import importlib

import boto3
from botocore.exceptions import ClientError, EndpointConnectionError

# ``lambda`` is a Python keyword — use importlib for intra-package imports.
_types_mod = importlib.import_module("shared.types")
ContentFilterResult = _types_mod.ContentFilterResult

logger = logging.getLogger(__name__)

# Environment-driven configuration
GUARDRAIL_ID = os.environ.get("GUARDRAIL_ID", "")
GUARDRAIL_VERSION = os.environ.get("GUARDRAIL_VERSION", "DRAFT")


class GuardrailsUnavailableError(Exception):
    """Raised when the Amazon Bedrock Guardrails service is unavailable.

    Callers should return a 503 response to the client.
    """

    def __init__(self, message: str = "Amazon Bedrock Guardrails service unavailable") -> None:
        self.message = message
        super().__init__(message)


def _get_bedrock_client():
    """Return a boto3 Amazon Bedrock Runtime client (module-level lazy singleton)."""
    return boto3.client("bedrock-runtime")


# Module-level lazy client
_client = None


def _bedrock_client():
    global _client
    if _client is None:
        _client = _get_bedrock_client()
    return _client


def apply_guardrail(
    request_body: Union[str, dict],
    *,
    guardrail_id: str | None = None,
    guardrail_version: str | None = None,
    client=None,
) -> ContentFilterResult:
    """Apply Amazon Bedrock Guardrails content filtering on a raw MCP request body.

    Args:
        request_body: The raw MCP request body as a string or dict.
        guardrail_id: Override the guardrail ID (defaults to GUARDRAIL_ID env var).
        guardrail_version: Override the guardrail version (defaults to GUARDRAIL_VERSION env var).
        client: Optional boto3 bedrock-runtime client for testing.

    Returns:
        ContentFilterResult with injection_score, filter_applied, and filter_source.

    Raises:
        GuardrailsUnavailableError: If the Amazon Bedrock Guardrails service is unavailable.
    """
    gid = guardrail_id or GUARDRAIL_ID
    gversion = guardrail_version or GUARDRAIL_VERSION
    bedrock = client or _bedrock_client()

    # Serialize dict to string if needed
    if isinstance(request_body, dict):
        body_text = json.dumps(request_body)
    else:
        body_text = request_body

    try:
        response = bedrock.apply_guardrail(
            guardrailIdentifier=gid,
            guardrailVersion=gversion,
            source="INPUT",
            content=[{"text": {"text": body_text}}],
        )
    except (ClientError, EndpointConnectionError) as exc:
        logger.error("Amazon Bedrock Guardrails unavailable: %s", exc)
        raise GuardrailsUnavailableError(
            f"Amazon Bedrock Guardrails service unavailable: {exc}"
        ) from exc

    return _parse_guardrail_response(response)


def _parse_guardrail_response(response: dict) -> ContentFilterResult:
    """Parse the ApplyGuardrail API response into a ContentFilterResult.

    The response action can be "GUARDRAIL_INTERVENED" (filter applied) or
    "NONE" (no filter applied). We extract the highest confidence score
    from any assessments as the injection_score (0-100).
    """
    action = response.get("action", "NONE")
    filter_applied = action == "GUARDRAIL_INTERVENED"

    injection_score = _extract_injection_score(response)

    return ContentFilterResult(
        injection_score=injection_score,
        filter_applied=filter_applied,
        filter_source="bedrock-guardrails",
    )


def _extract_injection_score(response: dict) -> int:
    """Extract the highest injection/content policy score from assessments.

    Scans all assessments for topicPolicy, contentPolicy, wordPolicy,
    sensitiveInformationPolicy, and contextualGroundingPolicy results.
    Returns the highest confidence score mapped to 0-100 range.
    Falls back to 0 if no scores are found, or 100 if the guardrail intervened
    but no granular scores are available.
    """
    max_score = 0
    assessments = response.get("assessments", [])

    for assessment in assessments:
        # Check topic policy
        topic_policy = assessment.get("topicPolicy", {})
        for topic in topic_policy.get("topics", []):
            if topic.get("action") == "BLOCKED":
                max_score = max(max_score, 100)

        # Check content policy (filters like HATE, INSULTS, etc.)
        content_policy = assessment.get("contentPolicy", {})
        for content_filter in content_policy.get("filters", []):
            confidence = _confidence_to_score(content_filter.get("confidence", "NONE"))
            max_score = max(max_score, confidence)

        # Check word policy
        word_policy = assessment.get("wordPolicy", {})
        if word_policy.get("customWords") or word_policy.get("managedWordLists"):
            max_score = max(max_score, 100)

        # Check sensitive information policy
        sensitive_policy = assessment.get("sensitiveInformationPolicy", {})
        if sensitive_policy.get("piiEntities") or sensitive_policy.get("regexes"):
            max_score = max(max_score, 75)

        # Check contextual grounding policy
        grounding_policy = assessment.get("contextualGroundingPolicy", {})
        for grounding_filter in grounding_policy.get("filters", []):
            score_val = grounding_filter.get("score", 0)
            # Grounding scores are 0-1 floats; invert since low grounding = high risk
            if isinstance(score_val, (int, float)):
                risk_score = int((1 - score_val) * 100)
                max_score = max(max_score, risk_score)

    # If guardrail intervened but we found no granular scores, default to 100
    action = response.get("action", "NONE")
    if action == "GUARDRAIL_INTERVENED" and max_score == 0:
        max_score = 100

    return min(max_score, 100)


def _confidence_to_score(confidence: str) -> int:
    """Map Amazon Bedrock confidence levels to a 0-100 score."""
    mapping = {
        "NONE": 0,
        "LOW": 25,
        "MEDIUM": 50,
        "HIGH": 75,
    }
    return mapping.get(confidence, 0)
