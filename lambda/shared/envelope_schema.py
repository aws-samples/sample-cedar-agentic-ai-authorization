# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""JSON schema for Request Envelope validation.

Uses jsonschema for validation of the normalized request envelope
before Cedar policy evaluation.
"""

from __future__ import annotations

import jsonschema

REQUEST_ENVELOPE_SCHEMA: dict = {
    "$schema": "https://json-schema.org/draft-07/schema#",
    "type": "object",
    "required": [
        "request_id",
        "timestamp",
        "source_protocol",
        "source_agent",
        "action",
        "delegation_chain",
        "delegation_depth",
        "originating_user",
        "content_filter_result",
    ],
    "properties": {
        "request_id": {
            "type": "string",
            "pattern": "^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
        },
        "timestamp": {
            "type": "string",
            "format": "date-time",
        },
        "source_protocol": {
            "type": "string",
            "const": "MCP",
        },
        "source_agent": {
            "type": "object",
            "required": [
                "agent_id",
                "trust_level",
                "namespace",
                "registered_capabilities",
                "lifecycle_stage",
            ],
            "properties": {
                "agent_id": {"type": "string"},
                "trust_level": {"type": "integer", "minimum": 1, "maximum": 5},
                "namespace": {"type": "string"},
                "registered_capabilities": {
                    "type": "array",
                    "items": {"type": "string"},
                },
                "lifecycle_stage": {"type": "string"},
            },
            "additionalProperties": False,
        },
        "action": {
            "type": "object",
            "required": ["type", "target_resource", "requested_capabilities"],
            "properties": {
                "type": {
                    "type": "string",
                    "enum": ["invoke_tool", "delegate_task"],
                },
                "target_resource": {"type": "string"},
                "requested_capabilities": {
                    "type": "array",
                    "items": {"type": "string"},
                },
            },
            "additionalProperties": False,
        },
        "delegation_chain": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["hop", "agent_id", "capabilities_granted", "timestamp"],
                "properties": {
                    "hop": {"type": "integer"},
                    "agent_id": {"type": "string"},
                    "capabilities_granted": {
                        "type": "array",
                        "items": {"type": "string"},
                    },
                    "timestamp": {"type": "string", "format": "date-time"},
                },
                "additionalProperties": False,
            },
        },
        "delegation_depth": {"type": "integer", "minimum": 0},
        "originating_user": {
            "type": "object",
            "required": [
                "user_id",
                "role",
                "mfa_verified",
                "authentication_method",
                "session_id",
                "signature",
            ],
            "properties": {
                "user_id": {"type": "string"},
                "role": {"type": "string"},
                "mfa_verified": {"type": "boolean"},
                "authentication_method": {"type": "string"},
                "session_id": {"type": "string"},
                "signature": {
                    "type": "string",
                    "pattern": "^[0-9a-fA-F]+$",
                },
            },
            "additionalProperties": False,
        },
        "content_filter_result": {
            "type": "object",
            "required": ["injection_score", "filter_applied", "filter_source"],
            "properties": {
                "injection_score": {
                    "type": "integer",
                    "minimum": 0,
                    "maximum": 100,
                },
                "filter_applied": {"type": "boolean"},
                "filter_source": {"type": "string"},
            },
            "additionalProperties": False,
        },
    },
    "additionalProperties": False,
}


def validate_envelope(envelope: dict) -> None:
    """Validate a request envelope against the JSON schema.

    Args:
        envelope: The request envelope dictionary to validate.

    Raises:
        jsonschema.ValidationError: If the envelope does not match the schema.
    """
    jsonschema.validate(instance=envelope, schema=REQUEST_ENVELOPE_SCHEMA)
