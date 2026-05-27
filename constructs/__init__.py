# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

# Constructs package — local CDK constructs for the project.
#
# This package name shadows the pip "constructs" package used by aws-cdk-lib.
# We load the pip constructs package directly from site-packages and register
# it as the "constructs" module so aws_cdk can find constructs._jsii.

import importlib.util as _ilu
import sys as _sys
from pathlib import Path as _Path

# Find the pip-installed "constructs" package in site-packages
_site_packages = [p for p in _sys.path if "site-packages" in p]
for _sp in _site_packages:
    _candidate = _Path(_sp) / "constructs" / "__init__.py"
    if _candidate.exists():
        _spec = _ilu.spec_from_file_location(
            "constructs",
            _candidate,
            submodule_search_locations=[str(_candidate.parent)],
        )
        if _spec and _spec.loader:
            _mod = _ilu.module_from_spec(_spec)
            # Register as "constructs" BEFORE exec so relative imports work
            _sys.modules["constructs"] = _mod
            _spec.loader.exec_module(_mod)
            break

# Re-export key symbols for convenience
from constructs import Construct, Node  # noqa: F401,E402
