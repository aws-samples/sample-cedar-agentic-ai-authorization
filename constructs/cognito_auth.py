# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""CDK construct for Amazon Cognito User Pool authentication with API Gateway.

Creates an Amazon Cognito User Pool with TOTP MFA enforcement, email verification,
a strict password policy, and advanced security mode ENFORCED. Adds an
app client without a client secret and a CognitoUserPoolsAuthorizer on
the API Gateway.

Validates: Requirements 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 5.1
"""

from __future__ import annotations

import aws_cdk.aws_apigateway as apigw
import aws_cdk.aws_cognito as cognito
from constructs import Construct


class CognitoAuth(Construct):
    """CDK construct for cedar-deputy-guard Amazon Cognito authentication.

    Args:
        scope: CDK construct scope.
        construct_id: Logical ID for this construct.
        api: The API Gateway REST API to attach the authorizer to.
    """

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        *,
        api: apigw.RestApi,
    ) -> None:
        super().__init__(scope, construct_id)

        # ── Amazon Cognito User Pool ────────────────────────────────────
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
            advanced_security_mode=cognito.AdvancedSecurityMode.ENFORCED,
        )

        # ── App Client ───────────────────────────────────────────
        self._user_pool_client = self._user_pool.add_client(
            "AppClient",
            user_pool_client_name="cedar-deputy-guard-app-client",
            generate_secret=False,
            auth_flows=cognito.AuthFlow(
                user_password=True,
                user_srp=True,
            ),
        )

        # ── Amazon Cognito Authorizer on API Gateway ────────────────────
        self._authorizer = apigw.CognitoUserPoolsAuthorizer(
            self,
            "CognitoAuthorizer",
            authorizer_name="cedar-deputy-guard-cognito-authorizer",
            cognito_user_pools=[self._user_pool],
        )

    @property
    def user_pool(self) -> cognito.UserPool:
        """The Amazon Cognito User Pool."""
        return self._user_pool

    @property
    def user_pool_client(self) -> cognito.UserPoolClient:
        """The Amazon Cognito User Pool app client."""
        return self._user_pool_client

    @property
    def authorizer(self) -> apigw.CognitoUserPoolsAuthorizer:
        """The Amazon Cognito authorizer for API Gateway."""
        return self._authorizer
