# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Shared fixtures for Cedar policy unit tests."""

import sys
from pathlib import Path

import pytest

# Ensure cedar/tests/ is on sys.path so helpers can be imported
_tests_dir = Path(__file__).resolve().parent
if str(_tests_dir) not in sys.path:
    sys.path.insert(0, str(_tests_dir))

from helpers import (  # noqa: E402
    LAYER1_DIR,
    LAYER2_DIR,
    LAYER3_DIR,
    load_policies,
    load_single_policy,
)


@pytest.fixture
def layer1_policies() -> str:
    """All Layer 1 policies concatenated."""
    return load_policies(LAYER1_DIR)


@pytest.fixture
def layer1_permit_policies() -> str:
    """Layer 1 permit policies only (L1-001 through L1-005)."""
    parts = []
    for f in sorted(LAYER1_DIR.glob("L1-00*.cedar")):
        parts.append(f.read_text())
    return "\n".join(parts)


@pytest.fixture
def layer1_deny_policy() -> str:
    """Layer 1 default deny policy only (L1-999)."""
    return load_single_policy(LAYER1_DIR / "L1-999-default-deny.cedar")


@pytest.fixture
def layer2_policies() -> str:
    """All Layer 2 policies concatenated."""
    return load_policies(LAYER2_DIR)


@pytest.fixture
def layer2_permit_policies() -> str:
    """Layer 2 permit policies only (L2-001 through L2-003)."""
    parts = []
    for f in sorted(LAYER2_DIR.glob("L2-00[1-3]*.cedar")):
        parts.append(f.read_text())
    return "\n".join(parts)


@pytest.fixture
def layer2_forbid_depth() -> str:
    """Layer 2 delegation depth limit (L2-004)."""
    return load_single_policy(LAYER2_DIR / "L2-004-delegation-depth-limit.cedar")


@pytest.fixture
def layer2_deny_policy() -> str:
    """Layer 2 default deny delegation (L2-999)."""
    return load_single_policy(LAYER2_DIR / "L2-999-default-deny-delegation.cedar")


@pytest.fixture
def layer3_policies() -> str:
    """All Layer 3 policies concatenated."""
    return load_policies(LAYER3_DIR)


@pytest.fixture
def layer3_permit_policies() -> str:
    """Layer 3 permit policies only (L3-001 through L3-005)."""
    parts = []
    for f in sorted(LAYER3_DIR.glob("L3-00*.cedar")):
        parts.append(f.read_text())
    return "\n".join(parts)


@pytest.fixture
def layer3_deny_policy() -> str:
    """Layer 3 default deny (L3-999)."""
    return load_single_policy(LAYER3_DIR / "L3-999-default-deny-no-user.cedar")
