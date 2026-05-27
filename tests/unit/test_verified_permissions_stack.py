# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Unit tests for VerifiedPermissionsStack and CedarPolicyStore construct.

Validates: Requirements 1.1, 1.2, 1.3, 7.3
"""

import json

import aws_cdk as cdk
import aws_cdk.assertions as assertions

from stacks.verified_permissions_stack import VerifiedPermissionsStack


def _synth_stack() -> assertions.Template:
    """Synthesize the VerifiedPermissionsStack and return its template."""
    app = cdk.App()
    stack = VerifiedPermissionsStack(app, "TestVerifiedPermissionsStack")
    return assertions.Template.from_stack(stack)


class TestPolicyStoreCreation:
    """Verify the Verified Permissions policy store is created correctly."""

    def test_policy_store_exists(self):
        template = _synth_stack()
        template.resource_count_is("AWS::VerifiedPermissions::PolicyStore", 1)

    def test_policy_store_has_strict_validation(self):
        template = _synth_stack()
        template.has_resource_properties(
            "AWS::VerifiedPermissions::PolicyStore",
            {"ValidationSettings": {"Mode": "STRICT"}},
        )

    def test_policy_store_has_cedar_schema(self):
        template = _synth_stack()
        template.has_resource_properties(
            "AWS::VerifiedPermissions::PolicyStore",
            {"Schema": assertions.Match.object_like({"CedarJson": assertions.Match.any_value()})},
        )

    def test_schema_contains_masol_namespace(self):
        template = _synth_stack()
        resources = template.find_resources("AWS::VerifiedPermissions::PolicyStore")
        for _logical_id, resource in resources.items():
            cedar_json = resource["Properties"]["Schema"]["CedarJson"]
            schema = json.loads(cedar_json)
            assert "AgentAuthz" in schema
            assert "Agent" in schema["AgentAuthz"]["entityTypes"]
            assert "Tool" in schema["AgentAuthz"]["entityTypes"]
            assert "invoke_tool" in schema["AgentAuthz"]["actions"]
            assert "delegate_task" in schema["AgentAuthz"]["actions"]


class TestPolicyDeployment:
    """Verify Layer 2 and Layer 3 policies are deployed."""

    def test_total_policy_count(self):
        """3 Layer 2 permits + 5 Layer 3 permits = 8 policies total."""
        template = _synth_stack()
        template.resource_count_is("AWS::VerifiedPermissions::Policy", 8)

    def test_policies_reference_policy_store(self):
        """Every policy references the policy store via Fn::GetAtt."""
        template = _synth_stack()
        policies = template.find_resources("AWS::VerifiedPermissions::Policy")
        for _logical_id, resource in policies.items():
            policy_store_id = resource["Properties"]["PolicyStoreId"]
            assert "Fn::GetAtt" in policy_store_id

    def test_policies_have_static_definitions(self):
        """Every policy uses a static policy definition with a statement."""
        template = _synth_stack()
        policies = template.find_resources("AWS::VerifiedPermissions::Policy")
        for _logical_id, resource in policies.items():
            definition = resource["Properties"]["Definition"]
            assert "Static" in definition
            assert "Statement" in definition["Static"]
            assert len(definition["Static"]["Statement"]) > 0


class TestCrossStackExport:
    """Verify the policy store ID is exported for cross-stack reference."""

    def test_policy_store_id_output_exists(self):
        template = _synth_stack()
        template.has_output(
            "PolicyStoreId",
            {
                "Export": {"Name": "MasolPolicyStoreId"},
            },
        )

    def test_stack_exposes_policy_store_id_property(self):
        app = cdk.App()
        stack = VerifiedPermissionsStack(app, "TestStack")
        assert stack.policy_store_id is not None
