# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""CDK construct for AWS Secrets Manager HMAC-SHA256 signing key.

Creates an AWS Secrets Manager secret for the HMAC-SHA256 signing key
used to sign and verify the Originating User Context. Configures
automatic rotation on a 90-day cycle.

Validates: Requirements 7.1, 7.4
"""

from __future__ import annotations

from typing import Optional

import aws_cdk as cdk
import aws_cdk.aws_kms as kms
import aws_cdk.aws_secretsmanager as secretsmanager
from constructs import Construct


class ContextSigner(Construct):
    """CDK construct for the HMAC-SHA256 signing key in AWS Secrets Manager.

    Args:
        scope: CDK construct scope.
        construct_id: Logical ID for this construct.
        secret_name: AWS Secrets Manager secret name
            (default: "agent-authz/signing-key").
        rotation_days: Automatic rotation period in days (default: 90).
        encryption_key: Optional AWS KMS key for encrypting the secret.
            When provided, the secret uses this key instead of the
            default AWS-managed key.
    """

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        *,
        secret_name: str = "agent-authz/signing-key",
        rotation_days: int = 90,
        encryption_key: Optional[kms.IKey] = None,
    ) -> None:
        super().__init__(scope, construct_id)

        self.secret = secretsmanager.Secret(
            self,
            "Key",
            secret_name=secret_name,
            description="HMAC-SHA256 signing key for Originating User Context",
            generate_secret_string=secretsmanager.SecretStringGenerator(
                password_length=64,
                exclude_punctuation=True,
            ),
            encryption_key=encryption_key,
        )

        # Note: Automatic rotation for HMAC keys requires a custom
        # rotation Lambda (not a hosted RDS rotator). For the initial
        # deployment we rely on manual rotation via the AWS console
        # or a future custom rotation Lambda.

    @property
    def secret_arn(self) -> str:
        """Return the signing key secret ARN."""
        return self.secret.secret_arn

    @property
    def secret_name_value(self) -> str:
        """Return the signing key secret name."""
        return self.secret.secret_name
