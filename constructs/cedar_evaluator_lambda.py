# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""CDK construct for the Cedar Policy Evaluator Lambda function.

Creates a Python 3.12 Lambda function with 512 MB memory, 5s timeout,
provisioned concurrency 10, Amazon VPC private subnet placement, cedarpy bundled,
and least-privilege IAM permissions for Verified Permissions, AWS Secrets
Manager, Amazon CloudWatch Logs, and CloudWatch Metrics.

Validates: Requirements 3.1, 3.6, 6.1, 6.2, 6.4, 7.5
"""

from __future__ import annotations

from pathlib import Path

import aws_cdk as cdk
import aws_cdk.aws_ec2 as ec2
import aws_cdk.aws_iam as iam
import aws_cdk.aws_lambda as _lambda
from constructs import Construct

_LAMBDA_DIR = str(Path(__file__).resolve().parent.parent / "lambda")


class CedarEvaluatorLambda(Construct):
    """CDK construct for the Cedar Policy Evaluator Lambda.

    Creates a Lambda function that validates request envelopes, verifies
    HMAC-SHA256 signatures, evaluates all three Cedar policy layers using
    the embedded cedarpy SDK, and emits OCSF 99001 audit events.

    Args:
        scope: CDK construct scope.
        construct_id: Logical ID for this construct.
        vpc: The Amazon VPC to place the Lambda in.
        policy_store_id: Verified Permissions policy store ID.
        signing_key_secret_name: AWS Secrets Manager secret name for the HMAC
            signing key (default: "agent-authz/signing-key").
        policy_cache_ttl_seconds: Cedar policy cache TTL in seconds
            (default: 60).
        audit_log_group: CloudWatch Logs group name for audit events
            (default: "/cedar-evaluator/audit").
        audit_dlq_url: SQS dead-letter queue URL for failed audit
            emissions (default: "").
        provisioned_concurrency: Number of provisioned concurrent
            executions (default: 10).
    """

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        *,
        vpc: ec2.IVpc,
        policy_store_id: str = "",
        signing_key_secret_name: str = "agent-authz/signing-key",
        policy_cache_ttl_seconds: int = 60,
        audit_log_group: str = "/cedar-evaluator/audit",
        audit_dlq_url: str = "",
        provisioned_concurrency: int = 10,
    ) -> None:
        super().__init__(scope, construct_id)

        self.function = _lambda.Function(
            self,
            "CedarEvaluatorFunction",
            runtime=_lambda.Runtime.PYTHON_3_12,
            handler="cedar_evaluator.handler.handler",
            code=_lambda.Code.from_asset(_LAMBDA_DIR),
            memory_size=512,
            timeout=cdk.Duration.seconds(5),
            vpc=vpc,
            vpc_subnets=ec2.SubnetSelection(
                subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS,
            ),
            environment={
                "SIGNING_KEY_SECRET_NAME": signing_key_secret_name,
                "POLICY_STORE_ID": policy_store_id,
                "POLICY_CACHE_TTL_SECONDS": str(policy_cache_ttl_seconds),
                "AUDIT_LOG_GROUP": audit_log_group,
                "AUDIT_DLQ_URL": audit_dlq_url,
            },
            description=(
                "Cedar Policy Evaluator — validates envelopes, verifies "
                "signatures, evaluates three Cedar policy layers, emits audit"
            ),
        )

        # Provisioned concurrency disabled for initial deployment.
        # Enable after verifying Lambda cold start with bundled dependencies.
        # self.alias = self.function.add_alias(
        #     "live",
        #     provisioned_concurrent_executions=provisioned_concurrency,
        # )

        # ── IAM: verifiedpermissions:IsAuthorized ─────────────────
        if not policy_store_id:
            raise ValueError("policy_store_id is required for least-privilege IAM")
        self.function.add_to_role_policy(
            iam.PolicyStatement(
                actions=["verifiedpermissions:IsAuthorized"],
                resources=[
                    cdk.Arn.format(
                        cdk.ArnComponents(
                            service="verifiedpermissions",
                            region="",
                            resource="policy-store",
                            resource_name=policy_store_id,
                        ),
                        cdk.Stack.of(self),
                    )
                ],
                effect=iam.Effect.ALLOW,
            )
        )

        # ── IAM: secretsmanager:GetSecretValue ────────────────────
        self.function.add_to_role_policy(
            iam.PolicyStatement(
                actions=["secretsmanager:GetSecretValue"],
                resources=[
                    cdk.Arn.format(
                        cdk.ArnComponents(
                            service="secretsmanager",
                            resource="secret",
                            resource_name=f"{signing_key_secret_name}-*",
                            arn_format=cdk.ArnFormat.COLON_RESOURCE_NAME,
                        ),
                        cdk.Stack.of(self),
                    )
                ],
                effect=iam.Effect.ALLOW,
            )
        )

        # ── IAM: logs:PutLogEvents ────────────────────────────────
        self.function.add_to_role_policy(
            iam.PolicyStatement(
                actions=["logs:PutLogEvents"],
                resources=[
                    cdk.Arn.format(
                        cdk.ArnComponents(
                            service="logs",
                            resource="log-group",
                            resource_name=f"{audit_log_group}:*",
                            arn_format=cdk.ArnFormat.COLON_RESOURCE_NAME,
                        ),
                        cdk.Stack.of(self),
                    )
                ],
                effect=iam.Effect.ALLOW,
            )
        )

        # ── IAM: cloudwatch:PutMetricData ─────────────────────────
        # PutMetricData does not support resource-level permissions.
        # Scoped to account-level ARN with namespace condition restricting
        # to our application metrics only.
        self.function.add_to_role_policy(
            iam.PolicyStatement(
                actions=["cloudwatch:PutMetricData"],
                resources=[
                    f"arn:aws:cloudwatch:{cdk.Stack.of(self).region}:{cdk.Stack.of(self).account}:*",
                ],
                conditions={
                    "StringEquals": {
                        "cloudwatch:namespace": "AgentAuthzProtection",
                    },
                },
                effect=iam.Effect.ALLOW,
            )
        )
