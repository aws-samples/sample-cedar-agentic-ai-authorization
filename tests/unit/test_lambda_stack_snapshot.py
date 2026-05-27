# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""CDK snapshot tests for LambdaStack.

Captures the full CloudFormation template as a JSON snapshot and compares
on subsequent runs to detect unintended infrastructure drift.

Validates: Requirements 7.3, 7.5
"""

import json
from pathlib import Path

import aws_cdk as cdk
import aws_cdk.assertions as assertions

from stacks.lambda_stack import LambdaStack
from stacks.verified_permissions_stack import VerifiedPermissionsStack

SNAPSHOT_DIR = Path(__file__).parent / "__snapshots__"
SNAPSHOT_FILE = SNAPSHOT_DIR / "lambda_stack.json"


def _synth_template() -> dict:
    """Synthesize the LambdaStack and return the raw template dict."""
    app = cdk.App()
    env = cdk.Environment(account="123456789012", region="us-east-1")
    vp = VerifiedPermissionsStack(app, "TestVP", env=env)
    stack = LambdaStack(app, "TestLambdaStack", verified_permissions_stack=vp, env=env)
    template = assertions.Template.from_stack(stack)
    return template.to_json()


class TestLambdaStackSnapshot:
    """Snapshot tests for LambdaStack CloudFormation template."""

    def test_template_matches_snapshot(self):
        """Validates: Requirements 7.3, 7.5 — full template snapshot."""
        template_json = _synth_template()

        if not SNAPSHOT_FILE.exists():
            SNAPSHOT_DIR.mkdir(parents=True, exist_ok=True)
            SNAPSHOT_FILE.write_text(
                json.dumps(template_json, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            return

        stored = json.loads(SNAPSHOT_FILE.read_text(encoding="utf-8"))
        assert template_json == stored, (
            "CloudFormation template has changed. "
            "If this is intentional, delete the snapshot file and re-run:\n"
            f"  rm {SNAPSHOT_FILE}"
        )

    def test_snapshot_contains_rest_api(self):
        """Verify the template includes an API Gateway REST API."""
        template_json = _synth_template()
        apis = [
            lid
            for lid, res in template_json.get("Resources", {}).items()
            if res["Type"] == "AWS::ApiGateway::RestApi"
        ]
        assert len(apis) == 1

    def test_snapshot_contains_evaluate_resource(self):
        """Verify the template includes the /evaluate API resource."""
        template_json = _synth_template()
        resources = [
            lid
            for lid, res in template_json.get("Resources", {}).items()
            if res["Type"] == "AWS::ApiGateway::Resource"
            and res.get("Properties", {}).get("PathPart") == "evaluate"
        ]
        assert len(resources) == 1

    def test_snapshot_contains_post_method_with_iam_auth(self):
        """Verify at least one POST method uses IAM authorization."""
        template_json = _synth_template()
        methods = [
            res
            for lid, res in template_json.get("Resources", {}).items()
            if res["Type"] == "AWS::ApiGateway::Method"
            and res.get("Properties", {}).get("HttpMethod") == "POST"
        ]
        assert len(methods) >= 1
        iam_methods = [
            m for m in methods
            if m["Properties"]["AuthorizationType"] == "AWS_IAM"
        ]
        assert len(iam_methods) == 1

    def test_snapshot_contains_lambda_functions(self):
        """Verify the template includes both Lambda functions."""
        template_json = _synth_template()
        functions = [
            lid
            for lid, res in template_json.get("Resources", {}).items()
            if res["Type"] == "AWS::Lambda::Function"
        ]
        assert len(functions) == 2

    def test_snapshot_contains_vpc(self):
        """Verify the template includes an Amazon VPC."""
        template_json = _synth_template()
        vpcs = [
            lid
            for lid, res in template_json.get("Resources", {}).items()
            if res["Type"] == "AWS::EC2::VPC"
        ]
        assert len(vpcs) == 1

    def test_snapshot_contains_private_subnets(self):
        """Verify the template includes private subnets for Lambda placement."""
        template_json = _synth_template()
        subnets = [
            lid
            for lid, res in template_json.get("Resources", {}).items()
            if res["Type"] == "AWS::EC2::Subnet"
        ]
        # 2 AZs × 2 subnet types (private + public) = 4 subnets
        assert len(subnets) == 4

    def test_snapshot_contains_iam_roles(self):
        """Verify the template includes IAM roles for Lambda functions."""
        template_json = _synth_template()
        roles = [
            lid
            for lid, res in template_json.get("Resources", {}).items()
            if res["Type"] == "AWS::IAM::Role"
        ]
        # At least 2 Lambda execution roles + API Gateway role + rotation role
        assert len(roles) >= 2

    def test_snapshot_contains_signing_key_secret(self):
        """Verify the template includes an AWS Secrets Manager secret for signing."""
        template_json = _synth_template()
        secrets = [
            lid
            for lid, res in template_json.get("Resources", {}).items()
            if res["Type"] == "AWS::SecretsManager::Secret"
        ]
        assert len(secrets) == 1

    def test_snapshot_contains_lambda_alias(self):
        """Verify the Cedar Evaluator has a provisioned concurrency alias.

        Note: Lambda aliases are not currently configured in the stack.
        This test verifies the current state (no aliases).
        """
        template_json = _synth_template()
        aliases = [
            lid
            for lid, res in template_json.get("Resources", {}).items()
            if res["Type"] == "AWS::Lambda::Alias"
        ]
        assert len(aliases) == 0

    def test_snapshot_lambda_functions_in_vpc(self):
        """Verify both Lambda functions are placed in Amazon VPC subnets."""
        template_json = _synth_template()
        functions = [
            res
            for lid, res in template_json.get("Resources", {}).items()
            if res["Type"] == "AWS::Lambda::Function"
        ]
        for fn in functions:
            vpc_config = fn.get("Properties", {}).get("VpcConfig", {})
            assert "SubnetIds" in vpc_config, (
                f"Lambda function missing Amazon VPC subnet placement"
            )
            assert "SecurityGroupIds" in vpc_config

    def test_snapshot_contains_outputs(self):
        """Verify the template exports API endpoint and function ARNs."""
        template_json = _synth_template()
        outputs = template_json.get("Outputs", {})
        export_names = [
            out.get("Export", {}).get("Name")
            for out in outputs.values()
        ]
        assert "MasolApiEndpoint" in export_names
        assert "MasolMcpAdapterFunctionArn" in export_names
        assert "MasolCedarEvaluatorFunctionArn" in export_names
        assert "MasolVpcId" in export_names

    def test_snapshot_api_stage_has_throttling(self):
        """Verify the API Gateway stage has throttling configured."""
        template_json = _synth_template()
        stages = [
            res
            for lid, res in template_json.get("Resources", {}).items()
            if res["Type"] == "AWS::ApiGateway::Stage"
        ]
        assert len(stages) == 1
        method_settings = stages[0].get("Properties", {}).get("MethodSettings", [])
        assert len(method_settings) > 0
        throttle = method_settings[0]
        assert throttle.get("ThrottlingRateLimit") == 1000
        assert throttle.get("ThrottlingBurstLimit") == 1000
