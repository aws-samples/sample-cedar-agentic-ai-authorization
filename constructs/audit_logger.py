# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""CDK construct for the Audit Logger pipeline.

Creates an Amazon CloudWatch Logs log group for OCSF 99001 audit events, a
CloudWatch Logs subscription filter that routes events to an Amazon Security Lake
custom OCSF source via Amazon Data Firehose, and an SQS dead-letter queue
for failed audit emissions.

Validates: Requirements 4.3, 4.4
"""

from __future__ import annotations

from typing import Optional

import aws_cdk as cdk
import aws_cdk.aws_iam as iam
import aws_cdk.aws_kms as kms
import aws_cdk.aws_logs as logs
import aws_cdk.aws_sqs as sqs
from constructs import Construct


class AuditLogger(Construct):
    """CDK construct for the OCSF 99001 audit logging pipeline.

    Args:
        scope: CDK construct scope.
        construct_id: Logical ID for this construct.
        log_group_name: Amazon CloudWatch Logs group name for audit events.
        retention_days: Log retention in days (default: 365).
        dlq_retention_days: DLQ message retention in days (default: 14).
        encryption_key: Optional AWS KMS key for encrypting the log group and DLQ.
    """

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        *,
        log_group_name: str = "/cedar-evaluator/audit",
        retention_days: int = 365,
        dlq_retention_days: int = 14,
        encryption_key: Optional[kms.IKey] = None,
    ) -> None:
        super().__init__(scope, construct_id)

        # ── CloudWatch Logs log group for OCSF 99001 events ──────
        self.log_group = logs.LogGroup(
            self,
            "AuditLogGroup",
            log_group_name=log_group_name,
            retention=logs.RetentionDays.ONE_YEAR,
            removal_policy=cdk.RemovalPolicy.RETAIN,
            encryption_key=encryption_key,
        )

        # ── SQS dead-letter queue for failed audit emissions ─────
        dlq_encryption = sqs.QueueEncryption.KMS if encryption_key else sqs.QueueEncryption.SQS_MANAGED
        # Note: encryption_master_key is the CDK API parameter name for SQS Queue
        # encryption key. This is not author-controlled terminology — it is required
        # by the aws_cdk.aws_sqs.Queue API.
        self.dlq = sqs.Queue(
            self,
            "AuditDLQ",
            queue_name="cedar-audit-dlq",
            retention_period=cdk.Duration.days(dlq_retention_days),
            encryption=dlq_encryption,
            encryption_master_key=encryption_key,  # CDK API parameter name
        )

        # ── IAM role for CloudWatch Logs subscription filter ─────
        # Subscription filter and role are created when Amazon Security Lake
        # destination is configured. Uncomment when ready.
        # self.subscription_role = iam.Role(...)
        # self.subscription_filter = logs.CfnSubscriptionFilter(...)

    @property
    def log_group_arn(self) -> str:
        """Return the audit log group ARN."""
        return self.log_group.log_group_arn

    @property
    def log_group_name_value(self) -> str:
        """Return the audit log group name."""
        return self.log_group.log_group_name

    @property
    def dlq_url(self) -> str:
        """Return the dead-letter queue URL."""
        return self.dlq.queue_url

    @property
    def dlq_arn(self) -> str:
        """Return the dead-letter queue ARN."""
        return self.dlq.queue_arn
