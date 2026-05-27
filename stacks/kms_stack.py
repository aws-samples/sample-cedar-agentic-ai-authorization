# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""KmsStack: Customer-managed AWS KMS encryption key.

Deployed as a separate stack to avoid CloudFormation circular dependencies
when the key is used by resources in LambdaStack (Secrets Manager, CloudWatch
Logs) that also participate in API Gateway deployment chains.

Validates: Requirements 1.1, 1.2, 2.5, 2.6, 2.7
"""

from __future__ import annotations

import aws_cdk as cdk
from constructs import Construct

from constructs.kms_encryption_key import KmsEncryptionKey


class KmsStack(cdk.Stack):
    """Stack for the customer-managed AWS KMS encryption key.

    Args:
        scope: CDK construct scope.
        construct_id: Logical ID for this stack.
    """

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        self._kms_encryption = KmsEncryptionKey(
            self,
            "KmsEncryptionKey",
        )

        self.kms_key = self._kms_encryption.key

        # Export key ARN for cross-stack reference
        cdk.CfnOutput(
            self,
            "KmsKeyArn",
            value=self.kms_key.key_arn,
            description="Customer-managed KMS key ARN",
            export_name="MasolKmsKeyArn",
        )
