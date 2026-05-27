# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Temporal rate-limiting layer for Cedar policy evaluation.

Cedar is stateless — it evaluates each request independently.
This module adds stateful rate-limiting using DynamoDB counters,
checked BEFORE Cedar evaluation to short-circuit obvious violations.

Design decisions:
- Fail open: DynamoDB errors do not block legitimate traffic.
- TTL-based expiry: Counters auto-expire after the window passes.
- Per-user/session scoping: Rate limits are scoped to user or session.
"""

from __future__ import annotations

import importlib
import logging
import os
import time
from dataclasses import dataclass
from typing import Optional

import boto3
from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError

_types = importlib.import_module("shared.types")
Decision = _types.Decision
LayerResult = _types.LayerResult

logger = logging.getLogger(__name__)

RATE_LIMIT_TABLE = os.environ.get("RATE_LIMIT_TABLE", "")
RATE_LIMIT_ENABLED = os.environ.get("RATE_LIMIT_ENABLED", "false").lower() == "true"


@dataclass(frozen=True)
class RateLimitRule:
    """A temporal rate-limiting rule."""

    rule_id: str
    description: str
    partition_key_template: str  # e.g., "user:{user_id}:tool:process_refund"
    max_count: int
    window_seconds: int
    deny_message: str
    tool_match: str  # Tool name to match, or "" for all


# Default rate limit rules
DEFAULT_RATE_LIMITS: list[RateLimitRule] = [
    RateLimitRule(
        rule_id="RL-001",
        description="Max 5 refunds per hour per user",
        partition_key_template="user:{user_id}:tool:process_refund",
        max_count=5,
        window_seconds=3600,
        deny_message="Rate limit exceeded: max 5 refunds per hour",
        tool_match="process_refund",
    ),
    RateLimitRule(
        rule_id="RL-002",
        description="Max 10 delegations per 10 minutes per session",
        partition_key_template="session:{session_id}:action:delegate_task",
        max_count=10,
        window_seconds=600,
        deny_message="Rate limit exceeded: max 10 delegations per 10 minutes",
        tool_match="",
    ),
    RateLimitRule(
        rule_id="RL-003",
        description="Max 3 delete operations per day per user",
        partition_key_template="user:{user_id}:tool:delete_records",
        max_count=3,
        window_seconds=86400,
        deny_message="Rate limit exceeded: max 3 delete operations per day",
        tool_match="delete_records",
    ),
]


_dynamodb = None


def _get_table():
    """Return a cached DynamoDB Table resource."""
    global _dynamodb
    if _dynamodb is None:
        _dynamodb = boto3.resource("dynamodb")
    return _dynamodb.Table(RATE_LIMIT_TABLE)


def _resolve_partition_key(rule: RateLimitRule, envelope: dict) -> str:
    """Resolve template variables in the partition key."""
    ou = envelope.get("originating_user", {})
    key = rule.partition_key_template
    key = key.replace("{user_id}", ou.get("user_id", "unknown"))
    key = key.replace("{session_id}", ou.get("session_id", "unknown"))
    key = key.replace(
        "{agent_id}",
        envelope.get("source_agent", {}).get("agent_id", "unknown"),
    )
    return key


def _extract_tool_name(envelope: dict) -> str:
    """Extract the bare tool name from the envelope action."""
    target = envelope.get("action", {}).get("target_resource", "")
    if "::" in target:
        return target.rsplit("::", 1)[-1].strip('"')
    return target


def check_rate_limits(envelope: dict) -> Optional[LayerResult]:
    """Check all rate limit rules against the current request.

    Returns None if all limits pass, or a DENY LayerResult if violated.
    Fails open on DynamoDB errors (does not block on infra failure).
    """
    if not RATE_LIMIT_ENABLED or not RATE_LIMIT_TABLE:
        return None

    action_type = envelope.get("action", {}).get("type", "")
    tool_name = _extract_tool_name(envelope)

    for rule in DEFAULT_RATE_LIMITS:
        # Only check rules relevant to this action
        if rule.tool_match and rule.tool_match != tool_name:
            continue
        if not rule.tool_match and action_type != "delegate_task":
            continue

        pk = _resolve_partition_key(rule, envelope)
        now = int(time.time())
        window_start = now - rule.window_seconds

        try:
            table = _get_table()
            response = table.query(
                KeyConditionExpression=(
                    Key("pk").eq(pk) & Key("timestamp").gte(window_start)
                ),
                Select="COUNT",
            )
            count = response.get("Count", 0)

            if count >= rule.max_count:
                logger.warning(
                    "Rate limit %s violated: %s has %d/%d in window",
                    rule.rule_id,
                    pk,
                    count,
                    rule.max_count,
                )
                return LayerResult(
                    decision=Decision.DENY,
                    evaluation_details=f"{rule.deny_message} (rule: {rule.rule_id})",
                )
        except ClientError as exc:
            # Fail open — don't block on rate-limiter infrastructure failure
            logger.error("DynamoDB rate limit check failed: %s", exc)
            continue

    return None


def record_request(envelope: dict) -> None:
    """Record a successful request for future rate-limit checks.

    Call this AFTER a PERMIT decision to increment counters.
    Fails silently on errors (non-blocking).
    """
    if not RATE_LIMIT_ENABLED or not RATE_LIMIT_TABLE:
        return

    now = int(time.time())
    table = _get_table()
    tool_name = _extract_tool_name(envelope)

    for rule in DEFAULT_RATE_LIMITS:
        # Only record for matching rules
        action_type = envelope.get("action", {}).get("type", "")
        if rule.tool_match and rule.tool_match != tool_name:
            continue
        if not rule.tool_match and action_type != "delegate_task":
            continue

        pk = _resolve_partition_key(rule, envelope)
        try:
            table.put_item(
                Item={
                    "pk": pk,
                    "timestamp": now,
                    "ttl": now + rule.window_seconds + 60,
                    "request_id": envelope.get("request_id", ""),
                }
            )
        except ClientError as exc:
            logger.error("Failed to record rate limit entry: %s", exc)
