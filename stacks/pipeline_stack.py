# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""PipelineStack: CI/CD pipelines for Cedar policy and Lambda deployment.

Contains two CodePipeline constructs:
1. Cedar Policy Pipeline — validates and deploys Cedar policies to
   the VerifiedPermissionsStack when policy files change.
2. Lambda Pipeline — builds, tests, and deploys Lambda functions via
   the LambdaStack, with a post-deployment integration test step.

Validates: Requirements 1.1, 1.2, 1.3, 6.1, 6.2
"""

from __future__ import annotations

import aws_cdk as cdk
import aws_cdk.aws_codebuild as codebuild
import aws_cdk.aws_codecommit as codecommit
import aws_cdk.aws_codepipeline as codepipeline
import aws_cdk.aws_codepipeline_actions as cpactions
import aws_cdk.aws_iam as iam
from constructs import Construct


class PipelineStack(cdk.Stack):
    """Stack containing CI/CD pipelines for Cedar policies and Lambda functions.

    Args:
        scope: CDK construct scope.
        construct_id: Logical ID for this stack.
        repo_name: CodeCommit repository name (default: cedar-deputy-guard).
        branch: Branch to track (default: main).
    """

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        *,
        repo_name: str = "cedar-deputy-guard",
        branch: str = "main",
        **kwargs,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # ── Shared CodeCommit repository ─────────────────────────
        self.repository = codecommit.Repository(
            self,
            "SourceRepo",
            repository_name=repo_name,
            description="AgentAuthz Protection — Cedar policies and Lambda code",
        )

        # ── Cedar Policy Pipeline (Task 9.1) ─────────────────────
        self.cedar_pipeline = self._build_cedar_pipeline(branch)

        # ── Lambda Pipeline (Task 9.2) ────────────────────────────
        self.lambda_pipeline = self._build_lambda_pipeline(branch)

        # ── Outputs ──────────────────────────────────────────────
        cdk.CfnOutput(
            self,
            "CedarPipelineName",
            value=self.cedar_pipeline.pipeline_name,
            description="Cedar policy CI/CD pipeline name",
            export_name="MasolCedarPipelineName",
        )
        cdk.CfnOutput(
            self,
            "LambdaPipelineName",
            value=self.lambda_pipeline.pipeline_name,
            description="Lambda CI/CD pipeline name",
            export_name="MasolLambdaPipelineName",
        )
        cdk.CfnOutput(
            self,
            "RepoCloneUrl",
            value=self.repository.repository_clone_url_http,
            description="CodeCommit repository clone URL",
            export_name="MasolRepoCloneUrl",
        )


    # ------------------------------------------------------------------
    # Cedar Policy Pipeline (Task 9.1)
    # ------------------------------------------------------------------

    def _build_cedar_pipeline(self, branch: str) -> codepipeline.Pipeline:
        """Build the Cedar policy CI/CD pipeline.

        Stages:
        1. Source — CodeCommit trigger on cedar/ path changes.
        2. Validate — CodeBuild project that runs Cedar schema validation
           using ``cedarpy.validate_policies``.
        3. Deploy — CDK deploy of VerifiedPermissionsStack.

        Requirements: 1.1, 1.2, 1.3
        """
        source_output = codepipeline.Artifact("CedarSource")

        source_action = cpactions.CodeCommitSourceAction(
            action_name="CodeCommit",
            repository=self.repository,
            branch=branch,
            output=source_output,
            trigger=cpactions.CodeCommitTrigger.EVENTS,
        )

        # Validation CodeBuild project — runs cedarpy schema validation
        validate_project = codebuild.PipelineProject(
            self,
            "CedarValidate",
            project_name="cedar-policy-validate",
            description="Validate Cedar policies against entity/context schemas",
            environment=codebuild.BuildEnvironment(
                build_image=codebuild.LinuxBuildImage.STANDARD_7_0,
                compute_type=codebuild.ComputeType.SMALL,
            ),
            build_spec=codebuild.BuildSpec.from_object({
                "version": "0.2",
                "phases": {
                    "install": {
                        "runtime-versions": {"python": "3.12"},
                        "commands": [
                            "pip install cedarpy",
                        ],
                    },
                    "build": {
                        "commands": [
                            "python -c \""
                            "import cedarpy, pathlib, sys; "
                            "schema = pathlib.Path('cedar/schema/cedar-entity-schema.json').read_text(); "
                            "errors = []; "
                            "[errors.extend(cedarpy.validate_policies(p.read_text(), schema).errors or []) "
                            " for d in ['layer1-agent-to-tool','layer2-agent-to-agent','layer3-originating-user-auth'] "
                            " for p in pathlib.Path(f'cedar/policies/{d}').glob('*.cedar')]; "
                            "print(f'Validated — {len(errors)} errors'); "
                            "sys.exit(1 if errors else 0)"
                            "\"",
                        ],
                    },
                },
            }),
        )

        validate_action = cpactions.CodeBuildAction(
            action_name="ValidatePolicies",
            project=validate_project,
            input=source_output,
        )

        # Deploy CodeBuild project — runs cdk deploy for VerifiedPermissionsStack
        deploy_project = codebuild.PipelineProject(
            self,
            "CedarDeploy",
            project_name="cedar-policy-deploy",
            description="CDK deploy VerifiedPermissionsStack with updated Cedar policies",
            environment=codebuild.BuildEnvironment(
                build_image=codebuild.LinuxBuildImage.STANDARD_7_0,
                compute_type=codebuild.ComputeType.SMALL,
                privileged=False,
            ),
            build_spec=codebuild.BuildSpec.from_object({
                "version": "0.2",
                "phases": {
                    "install": {
                        "runtime-versions": {"python": "3.12", "nodejs": "20"},
                        "commands": [
                            "npm install -g aws-cdk",
                            "pip install -r requirements.txt",
                        ],
                    },
                    "build": {
                        "commands": [
                            "cdk deploy VerifiedPermissionsStack --require-approval never",
                        ],
                    },
                },
            }),
        )
        deploy_project.add_to_role_policy(
            iam.PolicyStatement(
                actions=[
                    "cloudformation:CreateStack",
                    "cloudformation:UpdateStack",
                    "cloudformation:DeleteStack",
                    "cloudformation:DescribeStacks",
                    "cloudformation:DescribeStackEvents",
                    "cloudformation:GetTemplate",
                    "cloudformation:CreateChangeSet",
                    "cloudformation:ExecuteChangeSet",
                    "cloudformation:DeleteChangeSet",
                    "cloudformation:DescribeChangeSet",
                    "cloudformation:GetTemplateSummary",
                ],
                resources=[
                    f"arn:aws:cloudformation:{cdk.Aws.REGION}:{cdk.Aws.ACCOUNT_ID}:stack/VerifiedPermissionsStack/*",
                    f"arn:aws:cloudformation:{cdk.Aws.REGION}:{cdk.Aws.ACCOUNT_ID}:stack/CDKToolkit/*",
                ],
            )
        )
        deploy_project.add_to_role_policy(
            iam.PolicyStatement(
                actions=[
                    "verifiedpermissions:CreatePolicyStore",
                    "verifiedpermissions:UpdatePolicyStore",
                    "verifiedpermissions:DeletePolicyStore",
                    "verifiedpermissions:CreatePolicy",
                    "verifiedpermissions:UpdatePolicy",
                    "verifiedpermissions:DeletePolicy",
                    "verifiedpermissions:CreatePolicyTemplate",
                    "verifiedpermissions:PutSchema",
                    "verifiedpermissions:GetPolicyStore",
                    "verifiedpermissions:GetPolicy",
                    "verifiedpermissions:ListPolicies",
                    "verifiedpermissions:GetSchema",
                ],
                resources=[
                    f"arn:aws:verifiedpermissions:{cdk.Aws.REGION}:{cdk.Aws.ACCOUNT_ID}:policy-store/*",
                ],
            )
        )
        deploy_project.add_to_role_policy(
            iam.PolicyStatement(
                actions=["sts:AssumeRole"],
                resources=[
                    f"arn:aws:iam::{cdk.Aws.ACCOUNT_ID}:role/cdk-*",
                ],
            )
        )

        deploy_action = cpactions.CodeBuildAction(
            action_name="DeployPolicies",
            project=deploy_project,
            input=source_output,
        )

        return codepipeline.Pipeline(
            self,
            "CedarPolicyPipeline",
            pipeline_name="cedar-policy-pipeline",
            stages=[
                codepipeline.StageProps(
                    stage_name="Source",
                    actions=[source_action],
                ),
                codepipeline.StageProps(
                    stage_name="Validate",
                    actions=[validate_action],
                ),
                codepipeline.StageProps(
                    stage_name="Deploy",
                    actions=[deploy_action],
                ),
            ],
        )

    # ------------------------------------------------------------------
    # Lambda Pipeline (Task 9.2)
    # ------------------------------------------------------------------

    def _build_lambda_pipeline(self, branch: str) -> codepipeline.Pipeline:
        """Build the Lambda function CI/CD pipeline.

        Stages:
        1. Source — CodeCommit trigger on lambda/ path changes.
        2. Build — Python packaging and unit tests (pytest).
        3. Deploy — CDK deploy of LambdaStack.
        4. IntegrationTest — post-deployment integration tests.

        Requirements: 6.1, 6.2
        """
        source_output = codepipeline.Artifact("LambdaSource")

        source_action = cpactions.CodeCommitSourceAction(
            action_name="CodeCommit",
            repository=self.repository,
            branch=branch,
            output=source_output,
            trigger=cpactions.CodeCommitTrigger.EVENTS,
        )

        # Build + unit test CodeBuild project
        build_project = codebuild.PipelineProject(
            self,
            "LambdaBuild",
            project_name="lambda-build-test",
            description="Build Python Lambda packages and run unit tests",
            environment=codebuild.BuildEnvironment(
                build_image=codebuild.LinuxBuildImage.STANDARD_7_0,
                compute_type=codebuild.ComputeType.SMALL,
            ),
            build_spec=codebuild.BuildSpec.from_object({
                "version": "0.2",
                "phases": {
                    "install": {
                        "runtime-versions": {"python": "3.12"},
                        "commands": [
                            "pip install -r requirements.txt",
                            "pip install -r requirements-dev.txt",
                        ],
                    },
                    "build": {
                        "commands": [
                            "python -m pytest tests/unit/ -v --tb=short",
                        ],
                    },
                },
                "reports": {
                    "unit-tests": {
                        "files": ["junit.xml"],
                        "base-directory": ".",
                        "discard-paths": "yes",
                        "file-format": "JUNITXML",
                    },
                },
            }),
        )

        build_action = cpactions.CodeBuildAction(
            action_name="BuildAndTest",
            project=build_project,
            input=source_output,
        )

        # Deploy CodeBuild project — cdk deploy LambdaStack
        deploy_project = codebuild.PipelineProject(
            self,
            "LambdaDeploy",
            project_name="lambda-deploy",
            description="CDK deploy LambdaStack with updated Lambda functions",
            environment=codebuild.BuildEnvironment(
                build_image=codebuild.LinuxBuildImage.STANDARD_7_0,
                compute_type=codebuild.ComputeType.SMALL,
            ),
            build_spec=codebuild.BuildSpec.from_object({
                "version": "0.2",
                "phases": {
                    "install": {
                        "runtime-versions": {"python": "3.12", "nodejs": "20"},
                        "commands": [
                            "npm install -g aws-cdk",
                            "pip install -r requirements.txt",
                        ],
                    },
                    "build": {
                        "commands": [
                            "cdk deploy LambdaStack --require-approval never",
                        ],
                    },
                },
            }),
        )
        deploy_project.add_to_role_policy(
            iam.PolicyStatement(
                actions=[
                    "cloudformation:CreateStack",
                    "cloudformation:UpdateStack",
                    "cloudformation:DeleteStack",
                    "cloudformation:DescribeStacks",
                    "cloudformation:DescribeStackEvents",
                    "cloudformation:GetTemplate",
                    "cloudformation:CreateChangeSet",
                    "cloudformation:ExecuteChangeSet",
                    "cloudformation:DeleteChangeSet",
                    "cloudformation:DescribeChangeSet",
                    "cloudformation:GetTemplateSummary",
                ],
                resources=[
                    f"arn:aws:cloudformation:{cdk.Aws.REGION}:{cdk.Aws.ACCOUNT_ID}:stack/LambdaStack/*",
                    f"arn:aws:cloudformation:{cdk.Aws.REGION}:{cdk.Aws.ACCOUNT_ID}:stack/CDKToolkit/*",
                ],
            )
        )
        deploy_project.add_to_role_policy(
            iam.PolicyStatement(
                actions=[
                    "lambda:CreateFunction",
                    "lambda:UpdateFunctionCode",
                    "lambda:UpdateFunctionConfiguration",
                    "lambda:GetFunction",
                    "lambda:GetFunctionConfiguration",
                    "lambda:DeleteFunction",
                    "lambda:AddPermission",
                    "lambda:RemovePermission",
                    "lambda:PublishVersion",
                    "lambda:CreateAlias",
                    "lambda:UpdateAlias",
                    "lambda:TagResource",
                    "lambda:ListTags",
                    "lambda:PutFunctionConcurrency",
                ],
                resources=[
                    f"arn:aws:lambda:{cdk.Aws.REGION}:{cdk.Aws.ACCOUNT_ID}:function:cedar-*",
                ],
            )
        )
        deploy_project.add_to_role_policy(
            iam.PolicyStatement(
                actions=[
                    "apigateway:POST",
                    "apigateway:PATCH",
                    "apigateway:GET",
                    "apigateway:PUT",
                    "apigateway:DELETE",
                ],
                resources=[
                    f"arn:aws:apigateway:{cdk.Aws.REGION}::/restapis",
                    f"arn:aws:apigateway:{cdk.Aws.REGION}::/restapis/*",
                ],
            )
        )
        # ec2:Describe* actions do not support resource-level permissions per AWS
        # documentation. Using conditions to restrict scope to the deployment VPC.
        # nosec: Resource "*" required — ec2:Describe* does not support resource-level permissions.
        deploy_project.add_to_role_policy(
            iam.PolicyStatement(
                actions=[
                    "ec2:DescribeVpcs",
                    "ec2:DescribeSubnets",
                    "ec2:DescribeSecurityGroups",
                    "ec2:DescribeNetworkInterfaces",
                ],
                resources=["*"],
                conditions={
                    "StringEquals": {
                        "aws:RequestedRegion": cdk.Aws.REGION,
                    },
                },
            )
        )
        deploy_project.add_to_role_policy(
            iam.PolicyStatement(
                actions=[
                    "ec2:CreateNetworkInterface",
                    "ec2:DeleteNetworkInterface",
                ],
                resources=[
                    f"arn:aws:ec2:{cdk.Aws.REGION}:{cdk.Aws.ACCOUNT_ID}:network-interface/*",
                    f"arn:aws:ec2:{cdk.Aws.REGION}:{cdk.Aws.ACCOUNT_ID}:subnet/*",
                    f"arn:aws:ec2:{cdk.Aws.REGION}:{cdk.Aws.ACCOUNT_ID}:security-group/*",
                ],
            )
        )
        deploy_project.add_to_role_policy(
            iam.PolicyStatement(
                actions=[
                    "iam:GetRole",
                    "iam:CreateRole",
                    "iam:DeleteRole",
                    "iam:PutRolePolicy",
                    "iam:DeleteRolePolicy",
                    "iam:AttachRolePolicy",
                    "iam:DetachRolePolicy",
                    "iam:PassRole",
                    "iam:TagRole",
                ],
                resources=[
                    f"arn:aws:iam::{cdk.Aws.ACCOUNT_ID}:role/LambdaStack-*",
                    f"arn:aws:iam::{cdk.Aws.ACCOUNT_ID}:role/cdk-*",
                ],
            )
        )
        deploy_project.add_to_role_policy(
            iam.PolicyStatement(
                actions=[
                    "s3:GetObject",
                    "s3:PutObject",
                    "s3:GetBucketLocation",
                    "s3:ListBucket",
                ],
                resources=[
                    f"arn:aws:s3:::cdk-*",
                    f"arn:aws:s3:::cdk-*/*",
                ],
            )
        )
        deploy_project.add_to_role_policy(
            iam.PolicyStatement(
                actions=[
                    "secretsmanager:CreateSecret",
                    "secretsmanager:UpdateSecret",
                    "secretsmanager:DeleteSecret",
                    "secretsmanager:GetSecretValue",
                    "secretsmanager:DescribeSecret",
                    "secretsmanager:TagResource",
                ],
                resources=[
                    f"arn:aws:secretsmanager:{cdk.Aws.REGION}:{cdk.Aws.ACCOUNT_ID}:secret:agent-authz/*",
                ],
            )
        )
        deploy_project.add_to_role_policy(
            iam.PolicyStatement(
                actions=["sts:AssumeRole"],
                resources=[
                    f"arn:aws:iam::{cdk.Aws.ACCOUNT_ID}:role/cdk-*",
                ],
            )
        )

        deploy_action = cpactions.CodeBuildAction(
            action_name="DeployLambda",
            project=deploy_project,
            input=source_output,
        )

        # Integration test CodeBuild project — post-deployment
        integration_test_project = codebuild.PipelineProject(
            self,
            "LambdaIntegrationTest",
            project_name="lambda-integration-test",
            description="Run integration tests against deployed Lambda functions",
            environment=codebuild.BuildEnvironment(
                build_image=codebuild.LinuxBuildImage.STANDARD_7_0,
                compute_type=codebuild.ComputeType.SMALL,
            ),
            build_spec=codebuild.BuildSpec.from_object({
                "version": "0.2",
                "phases": {
                    "install": {
                        "runtime-versions": {"python": "3.12"},
                        "commands": [
                            "pip install -r requirements.txt",
                            "pip install -r requirements-dev.txt",
                        ],
                    },
                    "build": {
                        "commands": [
                            "python -m pytest tests/integration/ -v --tb=short",
                        ],
                    },
                },
            }),
        )

        integration_test_action = cpactions.CodeBuildAction(
            action_name="IntegrationTests",
            project=integration_test_project,
            input=source_output,
        )

        return codepipeline.Pipeline(
            self,
            "LambdaPipeline",
            pipeline_name="lambda-pipeline",
            stages=[
                codepipeline.StageProps(
                    stage_name="Source",
                    actions=[source_action],
                ),
                codepipeline.StageProps(
                    stage_name="BuildAndTest",
                    actions=[build_action],
                ),
                codepipeline.StageProps(
                    stage_name="Deploy",
                    actions=[deploy_action],
                ),
                codepipeline.StageProps(
                    stage_name="IntegrationTest",
                    actions=[integration_test_action],
                ),
            ],
        )
