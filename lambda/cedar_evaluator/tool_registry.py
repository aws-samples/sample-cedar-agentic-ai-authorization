# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Tool risk registry for Cedar entity construction.

Maps tool IDs to their security metadata (risk_level, data_classification).
This metadata is used to build accurate Cedar Tool entities for L1 policy
evaluation, replacing the previous hardcoded "low" risk_level default.

In production, this could be backed by a DynamoDB table or SSM Parameter Store.
For the reference implementation, a static registry is used.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ToolMetadata:
    """Security metadata for a registered tool."""

    tool_id: str
    namespace: str
    risk_level: str  # "critical", "high", "medium", "low"
    data_classification: str  # "restricted", "confidential", "internal", "public"


# Static tool registry — in production, load from DynamoDB or SSM
TOOL_REGISTRY: dict[str, ToolMetadata] = {
    "process_payment": ToolMetadata(
        tool_id="process_payment",
        namespace="payments",
        risk_level="high",
        data_classification="restricted",
    ),
    "process_refund": ToolMetadata(
        tool_id="process_refund",
        namespace="payments",
        risk_level="high",
        data_classification="restricted",
    ),
    "delete_records": ToolMetadata(
        tool_id="delete_records",
        namespace="data",
        risk_level="critical",
        data_classification="restricted",
    ),
    "read_records": ToolMetadata(
        tool_id="read_records",
        namespace="data",
        risk_level="low",
        data_classification="internal",
    ),
    "read_tickets": ToolMetadata(
        tool_id="read_tickets",
        namespace="support",
        risk_level="low",
        data_classification="internal",
    ),
}

# Default for unknown tools — conservative (treat as high-risk)
_DEFAULT_METADATA = ToolMetadata(
    tool_id="unknown",
    namespace="unknown",
    risk_level="high",
    data_classification="confidential",
)


def get_tool_metadata(tool_id: str) -> ToolMetadata:
    """Look up tool metadata from the registry.

    Returns conservative defaults for unknown tools.

    Args:
        tool_id: The tool identifier to look up.

    Returns:
        ToolMetadata with risk_level and data_classification.
    """
    return TOOL_REGISTRY.get(tool_id, _DEFAULT_METADATA)
