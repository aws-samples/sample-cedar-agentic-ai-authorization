# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""LambdaStack: MCP Adapter Lambda, Cedar Evaluator Lambda, API Gateway, Amazon VPC.

Creates the Amazon VPC with private subnets, instantiates both Lambda constructs,
creates the API Gateway REST API with IAM authorization and throttling
(1000 req/sec), and wires cross-stack dependencies. Adds AWS KMS encryption,
AWS WAF protection, and Amazon Cognito authentication.

Validates: Requirements 2.1, 3.1, 5.1, 5.2, 5.3, 6.2, 6.3, 6.5, 6.6, 7.2, 7.3, 7.4, 7.5
"""

from __future__ import annotations

from typing import Optional

import aws_cdk as cdk
import aws_cdk.aws_apigateway as apigw
import aws_cdk.aws_cognito as cognito
import aws_cdk.aws_dynamodb as dynamodb
import aws_cdk.aws_ec2 as ec2
import aws_cdk.aws_iam as iam
import aws_cdk.aws_kms as kms
import aws_cdk.aws_logs as logs
import aws_cdk.aws_ssm as ssm
from constructs import Construct

from constructs.cedar_evaluator_lambda import CedarEvaluatorLambda
from constructs.context_signer import ContextSigner
from constructs.mcp_adapter_lambda import McpAdapterLambda
from constructs.waf_web_acl import WafWebAcl


class LambdaStack(cdk.Stack):
    """Stack for Lambda functions, Amazon VPC, API Gateway, and signing key.

    Args:
        scope: CDK construct scope.
        construct_id: Logical ID for this stack.
        verified_permissions_stack: VerifiedPermissionsStack providing
            the policy store ID for cross-stack reference.
        kms_key: Optional KMS key from KmsStack for encryption at rest.
    """

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        *,
        verified_permissions_stack: cdk.Stack,
        kms_key: Optional[kms.IKey] = None,
        **kwargs,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        self.verified_permissions_stack = verified_permissions_stack
        self.kms_key = kms_key

        # Read and validate context values
        signing_key_secret_name = (
            self.node.try_get_context("signing_key_secret_name")
            or "agent-authz/signing-key"
        )

        policy_cache_ttl = int(
            self.node.try_get_context("policy_cache_ttl_seconds") or 60
        )
        if policy_cache_ttl <= 0 or policy_cache_ttl > 3600:
            raise ValueError(
                f"policy_cache_ttl_seconds must be between 1 and 3600, got {policy_cache_ttl}"
            )

        provisioned_concurrency = int(
            self.node.try_get_context("cedar_evaluator_provisioned_concurrency")
            or 10
        )
        if provisioned_concurrency < 0 or provisioned_concurrency > 500:
            raise ValueError(
                f"cedar_evaluator_provisioned_concurrency must be between 0 and 500, got {provisioned_concurrency}"
            )

        throttle_rate = int(
            self.node.try_get_context("api_gateway_throttle_rate") or 1000
        )
        if throttle_rate <= 0 or throttle_rate > 10000:
            raise ValueError(
                f"api_gateway_throttle_rate must be between 1 and 10000, got {throttle_rate}"
            )

        # ── Amazon VPC with private subnets ─────────────────────────────
        self.vpc = ec2.Vpc(
            self,
            "LambdaVpc",
            max_azs=2,
            nat_gateways=1,
            subnet_configuration=[
                ec2.SubnetConfiguration(
                    name="Private",
                    subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS,
                    cidr_mask=24,
                ),
                ec2.SubnetConfiguration(
                    name="Public",
                    subnet_type=ec2.SubnetType.PUBLIC,
                    cidr_mask=24,
                ),
            ],
        )

        # ── AWS Secrets Manager signing key ──────────────────────────
        self.context_signer = ContextSigner(
            self,
            "ContextSigner",
            secret_name=signing_key_secret_name,
            encryption_key=kms_key,
        )

        # ── Cedar Evaluator Lambda ───────────────────────────────
        self.cedar_evaluator = CedarEvaluatorLambda(
            self,
            "CedarEvaluator",
            vpc=self.vpc,
            policy_store_id=verified_permissions_stack.policy_store_id,
            signing_key_secret_name=signing_key_secret_name,
            policy_cache_ttl_seconds=policy_cache_ttl,
            provisioned_concurrency=provisioned_concurrency,
        )

        # ── MCP Adapter Lambda ───────────────────────────────────
        guardrail_id = self.node.try_get_context("guardrail_id") or ""
        self.mcp_adapter = McpAdapterLambda(
            self,
            "McpAdapter",
            vpc=self.vpc,
            cedar_evaluator_function=self.cedar_evaluator.function,
            guardrail_id=guardrail_id,
            signing_key_secret_name=signing_key_secret_name,
        )

        # ── Rate Limit DynamoDB Table ────────────────────────────
        self.rate_limit_table = dynamodb.Table(
            self,
            "RateLimitTable",
            table_name="cedar-authz-rate-limits",
            partition_key=dynamodb.Attribute(
                name="pk", type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(
                name="timestamp", type=dynamodb.AttributeType.NUMBER
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            time_to_live_attribute="ttl",
            encryption=dynamodb.TableEncryption.CUSTOMER_MANAGED,
            encryption_key=kms_key,
            removal_policy=cdk.RemovalPolicy.DESTROY,
        )
        self.rate_limit_table.grant_read_write_data(
            self.cedar_evaluator.function
        )
        self.cedar_evaluator.function.add_environment(
            "RATE_LIMIT_TABLE", self.rate_limit_table.table_name
        )
        self.cedar_evaluator.function.add_environment(
            "RATE_LIMIT_ENABLED", "true"
        )

        # ── Enforcement Mode SSM Parameter ───────────────────────
        self.enforcement_mode_param = ssm.StringParameter(
            self,
            "EnforcementModeParam",
            parameter_name="/cedar-authz/enforcement-mode",
            string_value="ENFORCE",
            description="Cedar policy enforcement mode: ENFORCE, LOG_ONLY, or WARN",
        )
        self.enforcement_mode_param.grant_read(
            self.cedar_evaluator.function
        )
        self.cedar_evaluator.function.add_environment(
            "ENFORCEMENT_MODE_PARAMETER",
            self.enforcement_mode_param.parameter_name,
        )

        # ── KMS decrypt grants for Lambda functions ──────────────
        # Both Lambdas need kms:Decrypt to read the Secrets Manager
        # signing key encrypted with the customer-managed KMS key.
        # Using grant_decrypt from the cross-stack KMS key avoids
        # circular dependencies since the key is in a separate stack.
        if kms_key:
            kms_key.grant_decrypt(self.mcp_adapter.function)
            kms_key.grant_decrypt(self.cedar_evaluator.function)

        # ── API Gateway REST API ─────────────────────────────────
        # Access log group for API Gateway
        api_access_log_group = logs.LogGroup(
            self,
            "ApiAccessLogGroup",
            log_group_name="/cedar-evaluator/api-access",
            retention=logs.RetentionDays.ONE_YEAR,
            removal_policy=cdk.RemovalPolicy.RETAIN,
        )

        self.api = apigw.RestApi(
            self,
            "EvaluateApi",
            rest_api_name="cedar-policy-evaluation",
            description="Cedar policy evaluation API with IAM authorization",
            deploy_options=apigw.StageOptions(
                stage_name="prod",
                throttling_rate_limit=throttle_rate,
                throttling_burst_limit=throttle_rate,
                access_log_destination=apigw.LogGroupLogDestination(api_access_log_group),
                access_log_format=apigw.AccessLogFormat.json_with_standard_fields(
                    caller=True,
                    http_method=True,
                    ip=True,
                    protocol=True,
                    request_time=True,
                    resource_path=True,
                    response_length=True,
                    status=True,
                    user=True,
                ),
            ),
            # Enforce HTTPS-only (TLS 1.2+) via resource policy
            policy=iam.PolicyDocument(
                statements=[
                    iam.PolicyStatement(
                        effect=iam.Effect.DENY,
                        principals=[iam.AnyPrincipal()],
                        actions=["execute-api:Invoke"],
                        resources=["execute-api:/*"],
                        conditions={
                            "Bool": {"aws:SecureTransport": "false"},
                        },
                    ),
                    iam.PolicyStatement(
                        effect=iam.Effect.ALLOW,
                        principals=[iam.AnyPrincipal()],
                        actions=["execute-api:Invoke"],
                        resources=["execute-api:/*"],
                    ),
                ],
            ),
        )

        # POST /evaluate → MCP Adapter Lambda (IAM auth)
        evaluate_resource = self.api.root.add_resource("evaluate")
        lambda_integration = apigw.LambdaIntegration(
            self.mcp_adapter.function,
            proxy=True,
        )
        evaluate_resource.add_method(
            "POST",
            lambda_integration,
            authorization_type=apigw.AuthorizationType.IAM,
        )

        # ── Amazon Cognito User Pool with TOTP MFA ───────────────────
        self._user_pool = cognito.UserPool(
            self,
            "UserPool",
            user_pool_name="cedar-deputy-guard-users",
            self_sign_up_enabled=False,
            sign_in_aliases=cognito.SignInAliases(email=True),
            auto_verify=cognito.AutoVerifiedAttrs(email=True),
            mfa=cognito.Mfa.REQUIRED,
            mfa_second_factor=cognito.MfaSecondFactor(
                otp=True,
                sms=False,
            ),
            password_policy=cognito.PasswordPolicy(
                min_length=12,
                require_uppercase=True,
                require_lowercase=True,
                require_digits=True,
                require_symbols=True,
            ),
        )

        self._user_pool_client = self._user_pool.add_client(
            "AppClient",
            user_pool_client_name="cedar-deputy-guard-app-client",
            generate_secret=False,
            auth_flows=cognito.AuthFlow(
                user_password=True,
                user_srp=True,
            ),
        )

        # Cognito authorizer for the /evaluate/cognito endpoint
        cognito_authorizer = apigw.CognitoUserPoolsAuthorizer(
            self,
            "CognitoAuthorizer",
            authorizer_name="cedar-deputy-guard-cognito-authorizer",
            cognito_user_pools=[self._user_pool],
        )

        # POST /evaluate/cognito → same Lambda, Cognito auth
        cognito_resource = evaluate_resource.add_resource("cognito")
        cognito_resource.add_method(
            "POST",
            lambda_integration,
            authorization_type=apigw.AuthorizationType.COGNITO,
            authorizer=cognito_authorizer,
        )

        # ── AWS WAF WebACL (must be after API deployment) ────────────
        self.waf = WafWebAcl(
            self,
            "WafWebAcl",
            api_gateway_stage_arn=f"arn:aws:apigateway:{cdk.Stack.of(self).region}::/restapis/{self.api.rest_api_id}/stages/prod",
        )
        # Ensure WAF association is created after the API stage
        self.waf.node.add_dependency(self.api.deployment_stage)

        # ── Outputs ──────────────────────────────────────────────
        cdk.CfnOutput(
            self,
            "ApiEndpoint",
            value=self.api.url,
            description="API Gateway endpoint URL",
            export_name="MasolApiEndpoint",
        )

        cdk.CfnOutput(
            self,
            "McpAdapterFunctionArn",
            value=self.mcp_adapter.function.function_arn,
            description="MCP Adapter Lambda function ARN",
            export_name="MasolMcpAdapterFunctionArn",
        )

        cdk.CfnOutput(
            self,
            "CedarEvaluatorFunctionArn",
            value=self.cedar_evaluator.function.function_arn,
            description="Cedar Evaluator Lambda function ARN",
            export_name="MasolCedarEvaluatorFunctionArn",
        )

        cdk.CfnOutput(
            self,
            "VpcId",
            value=self.vpc.vpc_id,
            description="Amazon VPC ID for Lambda functions",
            export_name="MasolVpcId",
        )

        cdk.CfnOutput(
            self,
            "UserPoolId",
            value=self._user_pool.user_pool_id,
            description="Amazon Cognito User Pool ID",
            export_name="MasolUserPoolId",
        )

        cdk.CfnOutput(
            self,
            "AppClientId",
            value=self._user_pool_client.user_pool_client_id,
            description="Amazon Cognito App Client ID",
            export_name="MasolAppClientId",
        )

        cdk.CfnOutput(
            self,
            "WebAclArn",
            value=self.waf.web_acl_arn,
            description="AWS WAF WebACL ARN",
            export_name="MasolWebAclArn",
        )
