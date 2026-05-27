# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Unit tests for the KmsEncryptionKey CDK construct.

Verifies that the synthesized CloudFormation template contains the expected
AWS KMS key configuration: auto-rotation, alias, pending deletion window,
RETAIN removal policy, and service principal grants for Amazon CloudWatch Logs,
SNS, and SQS.

Validates: Requirements 1.1, 1.2, 1.3, 1.4, 1.5, 2.5, 2.6, 2.7
"""

import aws_cdk as cdk
import aws_cdk.assertions as assertions

from constructs.kms_encryption_key import KmsEncryptionKey


def _synth_template() -> assertions.Template:
    """Create a minimal stack with KmsEncryptionKey and return the template."""
    app = cdk.App()
    stack = cdk.Stack(app, "TestStack", env=cdk.Environment(
        account="123456789012", region="us-east-1",
    ))
    KmsEncryptionKey(stack, "TestKmsKey")
    return assertions.Template.from_stack(stack)


class TestKmsKeyProperties:
    """Validates: Requirements 1.1, 1.2, 1.4, 1.5"""

    def test_key_has_auto_rotation_enabled(self):
        """Validates: Requirement 1.2 — auto key rotation enabled."""
        template = _synth_template()
        template.has_resource_properties("AWS::KMS::Key", {
            "EnableKeyRotation": True,
        })

    def test_key_has_pending_deletion_window(self):
        """Validates: Requirement 1.4 — 30-day pending deletion window."""
        template = _synth_template()
        template.has_resource_properties("AWS::KMS::Key", {
            "PendingWindowInDays": 30,
        })

    def test_key_has_retain_deletion_policy(self):
        """Validates: Requirement 1.5 — RETAIN removal policy."""
        template = _synth_template()
        template.has_resource("AWS::KMS::Key", {
            "DeletionPolicy": "Retain",
            "UpdateReplacePolicy": "Retain",
        })

    def test_key_has_description(self):
        """Validates: Requirement 1.3 — key has identifying description."""
        template = _synth_template()
        template.has_resource_properties("AWS::KMS::Key", {
            "Description": assertions.Match.string_like_regexp(
                "cedar-deputy-guard"
            ),
        })


class TestKmsAlias:
    """Validates: Requirement 1.3"""

    def test_alias_exists_with_correct_name(self):
        """Validates: Requirement 1.3 — alias identifies cedar-deputy-guard."""
        template = _synth_template()
        template.has_resource_properties("AWS::KMS::Alias", {
            "AliasName": "alias/cedar-deputy-guard",
        })


class TestKmsKeyPolicy:
    """Validates: Requirements 2.5, 2.6, 2.7"""

    def test_key_policy_grants_cloudwatch_logs(self):
        """Validates: Requirement 2.5 — CloudWatch Logs service principal."""
        template = _synth_template()
        template.has_resource_properties("AWS::KMS::Key", {
            "KeyPolicy": assertions.Match.object_like({
                "Statement": assertions.Match.array_with([
                    assertions.Match.object_like({
                        "Sid": "AllowCloudWatchLogs",
                        "Effect": "Allow",
                        "Principal": assertions.Match.object_like({
                            "Service": "logs.us-east-1.amazonaws.com",
                        }),
                        "Action": assertions.Match.array_with([
                            "kms:Encrypt*",
                            "kms:Decrypt*",
                            "kms:ReEncrypt*",
                            "kms:GenerateDataKey*",
                            "kms:Describe*",
                        ]),
                    }),
                ]),
            }),
        })

    def test_key_policy_grants_sns(self):
        """Validates: Requirement 2.6 — SNS service principal."""
        template = _synth_template()
        template.has_resource_properties("AWS::KMS::Key", {
            "KeyPolicy": assertions.Match.object_like({
                "Statement": assertions.Match.array_with([
                    assertions.Match.object_like({
                        "Sid": "AllowSNS",
                        "Effect": "Allow",
                        "Principal": assertions.Match.object_like({
                            "Service": "sns.amazonaws.com",
                        }),
                        "Action": assertions.Match.array_with([
                            "kms:Decrypt",
                            "kms:GenerateDataKey*",
                        ]),
                    }),
                ]),
            }),
        })

    def test_key_policy_grants_sqs(self):
        """Validates: Requirement 2.7 — SQS service principal."""
        template = _synth_template()
        template.has_resource_properties("AWS::KMS::Key", {
            "KeyPolicy": assertions.Match.object_like({
                "Statement": assertions.Match.array_with([
                    assertions.Match.object_like({
                        "Sid": "AllowSQS",
                        "Effect": "Allow",
                        "Principal": assertions.Match.object_like({
                            "Service": "sqs.amazonaws.com",
                        }),
                        "Action": assertions.Match.array_with([
                            "kms:Decrypt",
                            "kms:GenerateDataKey*",
                        ]),
                    }),
                ]),
            }),
        })
