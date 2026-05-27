# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Root conftest — add the lambda directory to sys.path so that
modules inside ``lambda/`` can be imported directly (e.g. ``shared.types``
instead of ``lambda.shared.types``).  The ``lambda`` prefix cannot be used
as a Python module name because it is a reserved keyword.

IMPORTANT: The lambda/ directory is appended (not prepended) to sys.path
so that the venv's site-packages take priority over Lambda-bundled
dependencies (which are compiled for Linux x86_64).
"""

import sys
from pathlib import Path

_project_root = Path(__file__).resolve().parent.parent
_lambda_dir = _project_root / "lambda"

# Keep project root for any non-lambda imports (e.g. constructs)
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

# Append lambda/ dir so our source modules are importable, but venv
# site-packages (with macOS-native binaries) take priority.
if str(_lambda_dir) not in sys.path:
    sys.path.append(str(_lambda_dir))
