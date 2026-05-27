# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""CDK construct for the MCP Protocol Adapter Lambda function.

Creates a Python 3.12 Lambda function with 256 MB memory, 10s timeout,
Amazon VPC private subnet placement, and least-privilege IAM permissions for
Amazon Bedrock Guardrails, AWS Secrets Manager, and Lambda invocation.

Validates: Requirements 5.1, 5.2, 5.3, 5.4, 7.5
"""

from __future__ import annotations

from pathlib import Path

import aws_cdk as cdk
import aws_cdk.aws_ec2 as ec2
import aws_cdk.aws_iam as iam
import aws_cdk.aws_lambda as _lambda
from constructs import Construct

_LAMBDA_DIR = str(Path(__file__).resolve().parent.parent / "lambda")


class McpAdapterLambda(Construct):
    """CDK construct for the MCP Protocol Adapter Lambda.

    Creates a Lambda function that parses MCP JSON-RPC messages, applies
    Amazon Bedrock Guardrails content filtering, builds a signed Request Envelope,
    and invokes the Cedar Evaluator Lambda synchronously.

    Args:
        scope: CDK construct scope.
        construct_id: Logical ID for this construct.
        vpc: The Amazon VPC to place the Lambda in.
        cedar_evaluator_function: The Cedar Evaluator Lambda function to invoke.
        guardrail_id: Amazon Bedrock Guardrail ID for content filtering.
        guardrail_version: Amazon Bedrock Guardrail version (default: "DRAFT").
        signing_key_secret_name: AWS Secrets Manager secret name for the HMAC
            signing key (default: "agent-authz/signing-key").
    """

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        *,
        vpc: ec2.IVpc,
        cedar_evaluator_function: _lambda.IFunction,
        guardrail_id: str = "",
        guardrail_version: str = "DRAFT",
        signing_key_secret_name: str = "agent-authz/signing-key",
    ) -> None:
        super().__init__(scope, construct_id)

        self.function = _lambda.Function(
            self,
            "McpAdapterFunction",
            runtime=_lambda.Runtime.PYTHON_3_12,
            handler="mcp_adapter.handler.handler",
            code=_lambda.Code.from_asset(_LAMBDA_DIR),
            memory_size=256,
            timeout=cdk.Duration.seconds(10),
            vpc=vpc,
            vpc_subnets=ec2.SubnetSelection(
                subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS,
            ),
            environment={
                "CEDAR_EVALUATOR_FUNCTION_NAME": cedar_evaluator_function.function_name,
                "GUARDRAIL_ID": guardrail_id,
                "GUARDRAIL_VERSION": guardrail_version,
                "SIGNING_KEY_SECRET_NAME": signing_key_secret_name,
            },
            description="MCP Protocol Adapter — parses MCP, applies guardrails, invokes Cedar Evaluator",
        )

        # IAM: bedrock:ApplyGuardrail — scoped to specific guardrail
        if not guardrail_id:
            raise ValueError(
                "guardrail_id is required for least-privilege IAM. "
                "Provide a valid Amazon Bedrock Guardrail ID."
            )
        guardrail_arn = cdk.Arn.format(
            cdk.ArnComponents(
                service="bedrock",
                resource="guardrail",
                resource_name=guardrail_id,
                arn_format=cdk.ArnFormat.SLASH_RESOURCE_NAME,
            ),
            cdk.Stack.of(self),
        )
        self.function.add_to_role_policy(
            iam.PolicyStatement(
                actions=["bedrock:ApplyGuardrail"],
                resources=[guardrail_arn],
                effect=iam.Effect.ALLOW,
            )
        )

        # IAM: secretsmanager:GetSecretValue
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

        # IAM: lambda:InvokeFunction on the Cedar Evaluator
        cedar_evaluator_function.grant_invoke(self.function)
