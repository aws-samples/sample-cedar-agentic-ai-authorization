# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Unit tests for the CognitoAuth CDK construct.

Verifies that the synthesized CloudFormation template contains the expected
Amazon Cognito User Pool configuration: TOTP MFA enforcement, password policy
(min 12, upper/lower/numbers/symbols), advanced security mode ENFORCED,
app client without a client secret supporting USER_PASSWORD_AUTH and
USER_SRP_AUTH flows, and an Amazon Cognito authorizer on API Gateway.

Validates: Requirements 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 5.1
"""

import aws_cdk as cdk
import aws_cdk.assertions as assertions
import aws_cdk.aws_apigateway as apigw

from constructs.cognito_auth import CognitoAuth


def _synth_template() -> assertions.Template:
    """Create a minimal stack with CognitoAuth and return the template."""
    app = cdk.App()
    stack = cdk.Stack(app, "TestStack", env=cdk.Environment(
        account="123456789012", region="us-east-1",
    ))
    api = apigw.RestApi(stack, "TestApi", rest_api_name="test-api")
    cognito_auth = CognitoAuth(stack, "TestCognitoAuth", api=api)
    # Attach the authorizer to a method so CDK can resolve it during synth
    api.root.add_method(
        "POST",
        authorization_type=apigw.AuthorizationType.COGNITO,
        authorizer=cognito_auth.authorizer,
    )
    return assertions.Template.from_stack(stack)


class TestUserPoolMfa:
    """Validates: Requirements 4.1, 4.2"""

    def test_user_pool_mfa_required(self):
        """Validates: Requirement 4.1 — MFA is required (ON) for all users."""
        template = _synth_template()
        template.has_resource_properties("AWS::Cognito::UserPool", {
            "MfaConfiguration": "ON",
        })

    def test_user_pool_totp_enabled(self):
        """Validates: Requirement 4.1 — TOTP MFA is enabled."""
        template = _synth_template()
        template.has_resource_properties("AWS::Cognito::UserPool", {
            "EnabledMfas": assertions.Match.array_with(["SOFTWARE_TOKEN_MFA"]),
        })

    def test_user_pool_email_verification(self):
        """Validates: Requirement 4.2 — email auto-verification enabled."""
        template = _synth_template()
        template.has_resource_properties("AWS::Cognito::UserPool", {
            "AutoVerifiedAttributes": assertions.Match.array_with(["email"]),
        })


class TestUserPoolPasswordPolicy:
    """Validates: Requirement 4.3"""

    def test_password_min_length_12(self):
        """Validates: Requirement 4.3 — minimum password length of 12."""
        template = _synth_template()
        template.has_resource_properties("AWS::Cognito::UserPool", {
            "Policies": assertions.Match.object_like({
                "PasswordPolicy": assertions.Match.object_like({
                    "MinimumLength": 12,
                }),
            }),
        })

    def test_password_requires_uppercase(self):
        """Validates: Requirement 4.3 — requires uppercase characters."""
        template = _synth_template()
        template.has_resource_properties("AWS::Cognito::UserPool", {
            "Policies": assertions.Match.object_like({
                "PasswordPolicy": assertions.Match.object_like({
                    "RequireUppercase": True,
                }),
            }),
        })

    def test_password_requires_lowercase(self):
        """Validates: Requirement 4.3 — requires lowercase characters."""
        template = _synth_template()
        template.has_resource_properties("AWS::Cognito::UserPool", {
            "Policies": assertions.Match.object_like({
                "PasswordPolicy": assertions.Match.object_like({
                    "RequireLowercase": True,
                }),
            }),
        })

    def test_password_requires_numbers(self):
        """Validates: Requirement 4.3 — requires numeric characters."""
        template = _synth_template()
        template.has_resource_properties("AWS::Cognito::UserPool", {
            "Policies": assertions.Match.object_like({
                "PasswordPolicy": assertions.Match.object_like({
                    "RequireNumbers": True,
                }),
            }),
        })

    def test_password_requires_symbols(self):
        """Validates: Requirement 4.3 — requires symbol characters."""
        template = _synth_template()
        template.has_resource_properties("AWS::Cognito::UserPool", {
            "Policies": assertions.Match.object_like({
                "PasswordPolicy": assertions.Match.object_like({
                    "RequireSymbols": True,
                }),
            }),
        })


class TestUserPoolAdvancedSecurity:
    """Validates: Requirement 4.4"""

    def test_advanced_security_mode_enforced(self):
        """Validates: Requirement 4.4 — advanced security mode is ENFORCED."""
        template = _synth_template()
        template.has_resource_properties("AWS::Cognito::UserPool", {
            "UserPoolAddOns": assertions.Match.object_like({
                "AdvancedSecurityMode": "ENFORCED",
            }),
        })


class TestAppClient:
    """Validates: Requirements 4.5, 4.6"""

    def test_app_client_no_secret(self):
        """Validates: Requirement 4.5 — app client has no client secret."""
        template = _synth_template()
        template.has_resource_properties("AWS::Cognito::UserPoolClient", {
            "GenerateSecret": False,
        })

    def test_app_client_auth_flows(self):
        """Validates: Requirement 4.6 — supports USER_PASSWORD_AUTH and USER_SRP_AUTH."""
        template = _synth_template()
        template.has_resource_properties("AWS::Cognito::UserPoolClient", {
            "ExplicitAuthFlows": assertions.Match.array_with([
                "ALLOW_USER_PASSWORD_AUTH",
                "ALLOW_USER_SRP_AUTH",
            ]),
        })


class TestCognitoAuthorizer:
    """Validates: Requirement 5.1"""

    def test_cognito_authorizer_exists(self):
        """Validates: Requirement 5.1 — Amazon Cognito authorizer on API Gateway."""
        template = _synth_template()
        template.has_resource_properties("AWS::ApiGateway::Authorizer", {
            "Type": "COGNITO_USER_POOLS",
        })
