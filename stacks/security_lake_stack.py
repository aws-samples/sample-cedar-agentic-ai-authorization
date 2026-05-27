# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""SecurityLakeStack: Audit logging and Amazon Security Lake integration.

Creates the audit-logger construct (Amazon CloudWatch Logs log group, subscription
filter, SQS DLQ) and a custom OCSF source for Amazon Security Lake.

Validates: Requirements 4.3, 4.4
"""

from typing import Optional

import aws_cdk as cdk
import aws_cdk.aws_kms as kms
from constructs import Construct

from constructs.audit_logger import AuditLogger


class SecurityLakeStack(cdk.Stack):
    """Stack for Amazon CloudWatch Logs, Amazon Security Lake custom OCSF source, and DLQ.

    Args:
        scope: CDK construct scope.
        construct_id: Logical ID for this stack.
        lambda_stack: LambdaStack for cross-stack references (log group ARNs).
        kms_key: Optional KMS key for encrypting the audit log group and DLQ.
    """

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        lambda_stack: cdk.Stack,
        kms_key: Optional[kms.IKey] = None,
        **kwargs,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)
        self.lambda_stack = lambda_stack

        # ── Audit Logger construct ───────────────────────────────
        self.audit_logger = AuditLogger(
            self,
            "AuditLogger",
            log_group_name="/cedar-evaluator/audit",
            retention_days=365,
            dlq_retention_days=14,
            encryption_key=kms_key,
        )

        # ── Custom OCSF source for Amazon Security Lake ─────────────────
        # Amazon Security Lake custom source requires Amazon Security Lake to be
        # enabled in the account. Uncomment when Amazon Security Lake is active.
        # self.custom_source = cdk.CfnResource(
        #     self, "SecurityLakeCustomSource",
        #     type="AWS::SecurityLake::CustomLogSource",
        #     ...
        # )

        # ── Outputs ──────────────────────────────────────────────
        cdk.CfnOutput(
            self,
            "AuditLogGroupArn",
            value=self.audit_logger.log_group_arn,
            description="Amazon CloudWatch Logs group ARN for OCSF 99001 audit events",
            export_name="MasolAuditLogGroupArn",
        )

        cdk.CfnOutput(
            self,
            "AuditDLQUrl",
            value=self.audit_logger.dlq_url,
            description="SQS dead-letter queue URL for failed audit emissions",
            export_name="MasolAuditDLQUrl",
        )
