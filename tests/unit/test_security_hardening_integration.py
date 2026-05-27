# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Integration tests for security hardening across all CDK stacks.

Synthesizes the full application (VerifiedPermissionsStack, LambdaStack,
SecurityLakeStack, MonitoringStack) and verifies cross-stack AWS KMS key wiring,
both API Gateway methods (IAM and Amazon Cognito), and CloudFormation outputs.

Validates: Requirements 5.2, 5.3, 6.1, 6.4, 6.5, 6.6
"""

import aws_cdk as cdk
import aws_cdk.assertions as assertions

from stacks.verified_permissions_stack import VerifiedPermissionsStack
from stacks.lambda_stack import LambdaStack
from stacks.security_lake_stack import SecurityLakeStack
from stacks.monitoring_stack import MonitoringStack


def _synth_all_stacks() -> dict[str, assertions.Template]:
    """Synthesize the full CDK app and return templates keyed by stack name."""
    app = cdk.App()
    env = cdk.Environment(account="123456789012", region="us-east-1")

    vp_stack = VerifiedPermissionsStack(app, "VerifiedPermissionsStack", env=env)

    lambda_stack = LambdaStack(
        app,
        "LambdaStack",
        verified_permissions_stack=vp_stack,
        env=env,
    )
    lambda_stack.add_dependency(vp_stack)

    security_lake_stack = SecurityLakeStack(
        app,
        "SecurityLakeStack",
        lambda_stack=lambda_stack,
        kms_key=lambda_stack.kms_key,
        env=env,
    )
    security_lake_stack.add_dependency(lambda_stack)

    monitoring_stack = MonitoringStack(
        app,
        "MonitoringStack",
        lambda_stack=lambda_stack,
        kms_key=lambda_stack.kms_key,
        env=env,
    )
    monitoring_stack.add_dependency(lambda_stack)

    return {
        "lambda": assertions.Template.from_stack(lambda_stack),
        "security_lake": assertions.Template.from_stack(security_lake_stack),
        "monitoring": assertions.Template.from_stack(monitoring_stack),
    }


class TestApiGatewayMethods:
    """Validates: Requirements 5.2, 5.3"""

    def test_iam_evaluate_method_exists(self):
        """Validates: Requirement 5.2 — POST /evaluate with IAM auth retained."""
        templates = _synth_all_stacks()
        templates["lambda"].has_resource_properties("AWS::ApiGateway::Method", {
            "HttpMethod": "POST",
            "AuthorizationType": "AWS_IAM",
        })

    def test_cognito_evaluate_method_exists(self):
        """Validates: Requirement 5.3 — POST /evaluate/cognito with Amazon Cognito auth."""
        templates = _synth_all_stacks()
        templates["lambda"].has_resource_properties("AWS::ApiGateway::Method", {
            "HttpMethod": "POST",
            "AuthorizationType": "COGNITO_USER_POOLS",
        })


class TestCrossStackKmsWiring:
    """Validates: Requirements 6.1, 6.4"""

    def test_lambda_stack_has_kms_key(self):
        """Validates: Requirement 6.1 — AWS KMS key created in LambdaStack."""
        templates = _synth_all_stacks()
        templates["lambda"].resource_count_is("AWS::KMS::Key", 1)

    def test_secrets_manager_uses_kms_key(self):
        """Validates: Requirement 6.1 — Signing_Key_Secret encrypted with AWS KMS key."""
        templates = _synth_all_stacks()
        templates["lambda"].has_resource_properties(
            "AWS::SecretsManager::Secret",
            {
                "KmsKeyId": assertions.Match.any_value(),
            },
        )

    def test_security_lake_log_group_uses_kms_key(self):
        """Validates: Requirement 6.1 — Audit_Log_Group encrypted with cross-stack AWS KMS key."""
        templates = _synth_all_stacks()
        templates["security_lake"].has_resource_properties(
            "AWS::Logs::LogGroup",
            {
                "KmsKeyId": assertions.Match.any_value(),
            },
        )

    def test_security_lake_dlq_uses_kms_key(self):
        """Validates: Requirement 6.1 — Audit_DLQ encrypted with cross-stack AWS KMS key."""
        templates = _synth_all_stacks()
        templates["security_lake"].has_resource_properties(
            "AWS::SQS::Queue",
            {
                # CloudFormation property name (AWS-defined, not author-controlled terminology)
                "KmsMasterKeyId": assertions.Match.any_value(),  # noqa: CloudFormation property name
            },
        )

    def test_monitoring_sns_topic_uses_kms_key(self):
        """Validates: Requirement 6.1 — Alarm_Topic encrypted with cross-stack AWS KMS key."""
        templates = _synth_all_stacks()
        templates["monitoring"].has_resource_properties(
            "AWS::SNS::Topic",
            {
                # CloudFormation property name (AWS-defined, not author-controlled terminology)
                "KmsMasterKeyId": assertions.Match.any_value(),  # noqa: CloudFormation property name
            },
        )

    def test_synth_produces_valid_templates(self):
        """Validates: Requirement 6.4 — cdk synth produces valid templates with no circular deps."""
        templates = _synth_all_stacks()
        # If we reach here, synthesis succeeded without circular dependency errors.
        assert "lambda" in templates
        assert "security_lake" in templates
        assert "monitoring" in templates


class TestCloudFormationOutputs:
    """Validates: Requirements 6.5, 6.6"""

    def test_user_pool_id_output_exists(self):
        """Validates: Requirement 6.5 — User Pool ID exported as CfnOutput."""
        templates = _synth_all_stacks()
        templates["lambda"].has_output("UserPoolId", {
            "Export": {"Name": "MasolUserPoolId"},
        })

    def test_app_client_id_output_exists(self):
        """Validates: Requirement 6.5 — App Client ID exported as CfnOutput."""
        templates = _synth_all_stacks()
        templates["lambda"].has_output("AppClientId", {
            "Export": {"Name": "MasolAppClientId"},
        })

    def test_web_acl_arn_output_exists(self):
        """Validates: Requirement 6.6 — WebACL ARN exported as CfnOutput."""
        templates = _synth_all_stacks()
        templates["lambda"].has_output("WebAclArn", {
            "Export": {"Name": "MasolWebAclArn"},
        })
