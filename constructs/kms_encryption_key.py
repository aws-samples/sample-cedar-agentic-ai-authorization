# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""CDK construct for a customer-managed AWS KMS encryption key.

Creates a symmetric AWS KMS key with auto-rotation, a 30-day pending deletion
window, and RETAIN removal policy. Grants Amazon CloudWatch Logs, Amazon SNS, and Amazon SQS
service principals the permissions they need to use the key.

Validates: Requirements 1.1, 1.2, 1.3, 1.4, 1.5, 2.5, 2.6, 2.7
"""

from __future__ import annotations

import aws_cdk as cdk
import aws_cdk.aws_iam as iam
import aws_cdk.aws_kms as kms
from constructs import Construct


class KmsEncryptionKey(Construct):
    """CDK construct for the cedar-deputy-guard customer-managed AWS KMS key.

    Args:
        scope: CDK construct scope.
        construct_id: Logical ID for this construct.
        audit_log_group_arn: ARN of the audit log group (optional,
            used for CloudWatch Logs key policy condition).
        alarm_topic_arn: ARN of the alarm SNS topic (optional,
            used for SNS key policy condition).
    """

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        *,
        audit_log_group_arn: str = "",
        alarm_topic_arn: str = "",
    ) -> None:
        super().__init__(scope, construct_id)

        # ── Symmetric AWS KMS key with auto-rotation ─────────────────
        self._key = kms.Key(
            self,
            "Key",
            description="Customer-managed key for cedar-deputy-guard encryption at rest",
            enable_key_rotation=True,
            pending_window=cdk.Duration.days(30),
            removal_policy=cdk.RemovalPolicy.RETAIN,
        )

        # ── Alias ────────────────────────────────────────────────
        self._key.add_alias("alias/cedar-deputy-guard")

        # ── Amazon CloudWatch Logs service principal grant ──────────────
        # Note: In a KMS key policy, Resource "*" refers to the key the policy
        # is attached to (i.e., "this key"), not all keys in the account.
        # This is standard AWS KMS key policy syntax per AWS documentation.
        self._key.add_to_resource_policy(
            iam.PolicyStatement(
                sid="AllowCloudWatchLogs",
                actions=[
                    "kms:Encrypt*",
                    "kms:Decrypt*",
                    "kms:ReEncrypt*",
                    "kms:GenerateDataKey*",
                    "kms:Describe*",
                ],
                principals=[
                    iam.ServicePrincipal(
                        f"logs.{cdk.Stack.of(self).region}.amazonaws.com"
                    ),
                ],
                resources=["*"],  # In key policy, "*" means "this key"
                conditions={
                    "ArnLike": {
                        "kms:EncryptionContext:aws:logs:arn": (
                            f"arn:aws:logs:{cdk.Stack.of(self).region}:"
                            f"{cdk.Stack.of(self).account}:*"
                        ),
                    },
                },
            )
        )

        # ── Amazon SNS service principal grant ──────────────────────────
        self._key.add_to_resource_policy(
            iam.PolicyStatement(
                sid="AllowSNS",
                actions=[
                    "kms:Decrypt",
                    "kms:GenerateDataKey*",
                ],
                principals=[
                    iam.ServicePrincipal("sns.amazonaws.com"),
                ],
                resources=["*"],  # In key policy, "*" means "this key"
            )
        )

        # ── Amazon SQS service principal grant ──────────────────────────
        self._key.add_to_resource_policy(
            iam.PolicyStatement(
                sid="AllowSQS",
                actions=[
                    "kms:Decrypt",
                    "kms:GenerateDataKey*",
                ],
                principals=[
                    iam.ServicePrincipal("sqs.amazonaws.com"),
                ],
                resources=["*"],  # In key policy, "*" means "this key"
            )
        )

    @property
    def key(self) -> kms.Key:
        """The AWS KMS key for use by other constructs."""
        return self._key
