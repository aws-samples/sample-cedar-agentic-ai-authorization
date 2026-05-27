# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Enforcement mode management for gradual policy rollout.

Supports three modes:
- ENFORCE: Hard enforcement (default, current behavior)
- LOG_ONLY: Evaluate policies but always return PERMIT (shadow mode)
- WARN: Evaluate policies, log denials, but return PERMIT with warning

Mode is read from SSM Parameter Store for hot-switching without redeployment.
Falls back to ENFORCEMENT_MODE environment variable.
"""

from __future__ import annotations

import logging
import os
import time
from enum import Enum
from typing import Optional

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)


class EnforcementMode(str, Enum):
    """Policy enforcement mode."""

    ENFORCE = "ENFORCE"
    LOG_ONLY = "LOG_ONLY"
    WARN = "WARN"


# Cache the mode to avoid hitting SSM on every request
_cached_mode: Optional[EnforcementMode] = None
_cached_at: float = 0.0
_MODE_CACHE_TTL = 30  # seconds

SSM_PARAMETER_NAME = os.environ.get(
    "ENFORCEMENT_MODE_PARAMETER",
    "/cedar-authz/enforcement-mode",
)

_ssm_client = None


def _get_ssm_client():
    """Return a cached SSM client."""
    global _ssm_client
    if _ssm_client is None:
        _ssm_client = boto3.client("ssm")
    return _ssm_client


def get_enforcement_mode() -> EnforcementMode:
    """Get the current enforcement mode.

    Priority:
    1. SSM Parameter Store (hot-switchable)
    2. ENFORCEMENT_MODE environment variable
    3. Default: ENFORCE
    """
    global _cached_mode, _cached_at

    now = time.monotonic()
    if _cached_mode and (now - _cached_at) < _MODE_CACHE_TTL:
        return _cached_mode

    # Try SSM Parameter Store first
    try:
        client = _get_ssm_client()
        response = client.get_parameter(Name=SSM_PARAMETER_NAME)
        value = response["Parameter"]["Value"].upper()
        _cached_mode = EnforcementMode(value)
        _cached_at = now
        return _cached_mode
    except (ClientError, ValueError, KeyError):
        pass

    # Fall back to environment variable
    env_mode = os.environ.get("ENFORCEMENT_MODE", "ENFORCE").upper()
    try:
        _cached_mode = EnforcementMode(env_mode)
    except ValueError:
        _cached_mode = EnforcementMode.ENFORCE

    _cached_at = now
    return _cached_mode


def reset_cache() -> None:
    """Reset the cached mode. Useful for testing."""
    global _cached_mode, _cached_at
    _cached_mode = None
    _cached_at = 0.0
