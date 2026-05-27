#!/usr/bin/env bash
# Install Lambda dependencies into the lambda/ directory for CDK bundling.
# Run this before `cdk deploy` to ensure pip packages are included in the
# Lambda deployment package created by Code.from_asset.
#
# Usage: ./scripts/bundle_lambda.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
LAMBDA_DIR="$PROJECT_DIR/lambda"

echo "Installing Lambda dependencies into $LAMBDA_DIR ..."

pip install \
  --platform manylinux2014_x86_64 \
  --implementation cp \
  --python-version 3.12 \
  --only-binary=:all: \
  --target "$LAMBDA_DIR" \
  --upgrade \
  --no-user \
  pydantic jsonschema cedarpy

# Clean up pip artifacts not needed in Lambda
rm -rf "$LAMBDA_DIR/bin"

echo "Done. Lambda dependencies bundled into $LAMBDA_DIR"
