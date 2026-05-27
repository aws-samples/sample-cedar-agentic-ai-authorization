# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""CDK construct for Amazon Verified Permissions Cedar policy store."""

import json
from pathlib import Path
from typing import Optional

import aws_cdk as cdk
import aws_cdk.aws_verifiedpermissions as avp
from constructs import Construct


class CedarPolicyStore(Construct):
    """Creates an Amazon Verified Permissions policy store with Cedar schemas and policies.

    Deploys the Cedar entity schema, context schema, and Layer 2 + Layer 3
    policies to the policy store. Layer 1 policies are deployed separately
    to the AgentCore Policy Service.
    """

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        *,
        cedar_dir: Optional[str] = None,
    ) -> None:
        super().__init__(scope, construct_id)

        project_root = Path(__file__).resolve().parent.parent
        cedar_path = Path(cedar_dir) if cedar_dir else project_root / "cedar"

        # Load entity schema
        entity_schema_path = cedar_path / "schema" / "cedar-entity-schema.json"
        entity_schema = json.loads(entity_schema_path.read_text(encoding="utf-8"))

        # Create the policy store with schema and validation
        self.policy_store = avp.CfnPolicyStore(
            self,
            "PolicyStore",
            validation_settings=avp.CfnPolicyStore.ValidationSettingsProperty(
                mode="STRICT",
            ),
            schema=avp.CfnPolicyStore.SchemaDefinitionProperty(
                cedar_json=json.dumps(entity_schema),
            ),
            description="AgentAuthz least-privilege authorization - Cedar policy store",
        )

        # Deploy Layer 2 and Layer 3 policies
        self._deploy_policies(cedar_path / "policies" / "layer2-agent-to-agent", "L2")
        self._deploy_policies(cedar_path / "policies" / "layer3-originating-user-auth", "L3")

    def _deploy_policies(self, policy_dir: Path, layer_prefix: str) -> None:
        """Deploy .cedar policy files from a directory to the policy store.

        Skips default-deny forbid policies (L*-999) because Cedar's default
        behavior is already deny-when-no-permit-matches, and AVP's STRICT
        validation may reject conditional forbids that reference required
        context attributes with ``has`` checks.
        """
        if not policy_dir.exists():
            return

        for policy_file in sorted(policy_dir.glob("*.cedar")):
            policy_text = policy_file.read_text(encoding="utf-8").strip()
            if not policy_text:
                continue

            # Use filename stem as logical ID (e.g., L2-001-orchestrator-finance)
            policy_id = policy_file.stem

            # Skip default-deny policies — Cedar's default is deny when
            # no permit matches, making these redundant for AVP.
            if "-999-" in policy_id:
                continue

            # Skip conditional forbid policies (e.g., L2-004 delegation
            # depth limit) — enforced in Python by the policy evaluator.
            if "-004-" in policy_id and layer_prefix == "L2":
                continue

            avp.CfnPolicy(
                self,
                f"Policy-{policy_id}",
                policy_store_id=self.policy_store.attr_policy_store_id,
                definition=avp.CfnPolicy.PolicyDefinitionProperty(
                    static=avp.CfnPolicy.StaticPolicyDefinitionProperty(
                        statement=policy_text,
                        description=f"{layer_prefix} policy: {policy_id}",
                    ),
                ),
            )

    @property
    def policy_store_id(self) -> str:
        """Return the policy store ID attribute for cross-stack references."""
        return self.policy_store.attr_policy_store_id

    @property
    def policy_store_arn(self) -> str:
        """Return the policy store ARN attribute."""
        return self.policy_store.attr_arn
