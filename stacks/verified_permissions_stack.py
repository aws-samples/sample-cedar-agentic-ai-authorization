# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""VerifiedPermissionsStack: Cedar policy store and schema deployment."""

import aws_cdk as cdk
from constructs import Construct

from constructs.cedar_policy_store import CedarPolicyStore


class VerifiedPermissionsStack(cdk.Stack):
    """Stack for Amazon Verified Permissions policy store, schemas, and policies.

    Creates the Cedar policy store with entity/context schemas and deploys
    Layer 2 (agent-to-agent delegation) and Layer 3 (originating user auth)
    policies. Exports the policy store ID for cross-stack reference by LambdaStack.
    """

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        self.cedar_policy_store = CedarPolicyStore(
            self,
            "CedarPolicyStore",
        )

        # Export policy store ID for cross-stack reference
        self.policy_store_id_output = cdk.CfnOutput(
            self,
            "PolicyStoreId",
            value=self.cedar_policy_store.policy_store_id,
            description="Amazon Verified Permissions policy store ID",
            export_name="MasolPolicyStoreId",
        )

    @property
    def policy_store_id(self) -> str:
        """Return the policy store ID for cross-stack references."""
        return self.cedar_policy_store.policy_store_id
