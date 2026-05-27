# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

#!/usr/bin/env python3
"""CDK app entry point for Agent Authorization Protection system."""

import aws_cdk as cdk

from stacks.kms_stack import KmsStack
from stacks.verified_permissions_stack import VerifiedPermissionsStack
from stacks.lambda_stack import LambdaStack
from stacks.security_lake_stack import SecurityLakeStack
from stacks.monitoring_stack import MonitoringStack


app = cdk.App()

account_id = app.node.try_get_context("account_id") or "123456789012"
region = app.node.try_get_context("region") or "us-east-1"

env = cdk.Environment(account=account_id, region=region)

kms_stack = KmsStack(
    app,
    "KmsStack",
    env=env,
)

verified_permissions_stack = VerifiedPermissionsStack(
    app,
    "VerifiedPermissionsStack",
    env=env,
)

lambda_stack = LambdaStack(
    app,
    "LambdaStack",
    verified_permissions_stack=verified_permissions_stack,
    kms_key=kms_stack.kms_key,
    env=env,
)
lambda_stack.add_dependency(verified_permissions_stack)
lambda_stack.add_dependency(kms_stack)

security_lake_stack = SecurityLakeStack(
    app,
    "SecurityLakeStack",
    lambda_stack=lambda_stack,
    kms_key=kms_stack.kms_key,
    env=env,
)
security_lake_stack.add_dependency(lambda_stack)

monitoring_stack = MonitoringStack(
    app,
    "MonitoringStack",
    lambda_stack=lambda_stack,
    kms_key=kms_stack.kms_key,
    env=env,
)
monitoring_stack.add_dependency(lambda_stack)

app.synth()
