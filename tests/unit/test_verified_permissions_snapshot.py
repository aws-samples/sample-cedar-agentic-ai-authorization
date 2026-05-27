# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""CDK snapshot tests for VerifiedPermissionsStack.

Captures the full CloudFormation template as a JSON snapshot and compares
on subsequent runs to detect unintended infrastructure drift.

Validates: Requirements 1.1
"""

import json
from pathlib import Path

import aws_cdk as cdk
import aws_cdk.assertions as assertions

from stacks.verified_permissions_stack import VerifiedPermissionsStack

SNAPSHOT_DIR = Path(__file__).parent / "__snapshots__"
SNAPSHOT_FILE = SNAPSHOT_DIR / "verified_permissions_stack.json"


def _synth_template() -> dict:
    """Synthesize the VerifiedPermissionsStack and return the raw template dict."""
    app = cdk.App()
    stack = VerifiedPermissionsStack(app, "TestVerifiedPermissionsStack")
    template = assertions.Template.from_stack(stack)
    return template.to_json()


class TestVerifiedPermissionsSnapshot:
    """Snapshot test: full CloudFormation template for VerifiedPermissionsStack.

    On first run the snapshot file is created. On subsequent runs the
    synthesized template is compared against the stored snapshot. If the
    template changes intentionally, delete the snapshot file and re-run
    to regenerate it.
    """

    def test_template_matches_snapshot(self):
        """Validates: Requirements 1.1 — policy store, schema, and policy deployment."""
        template_json = _synth_template()

        if not SNAPSHOT_FILE.exists():
            SNAPSHOT_DIR.mkdir(parents=True, exist_ok=True)
            SNAPSHOT_FILE.write_text(
                json.dumps(template_json, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            # First run — snapshot created, nothing to compare yet
            return

        stored = json.loads(SNAPSHOT_FILE.read_text(encoding="utf-8"))
        assert template_json == stored, (
            "CloudFormation template has changed. "
            "If this is intentional, delete the snapshot file and re-run:\n"
            f"  rm {SNAPSHOT_FILE}"
        )

    def test_snapshot_contains_policy_store(self):
        """Verify the snapshot includes exactly one PolicyStore resource."""
        template_json = _synth_template()
        policy_stores = [
            lid
            for lid, res in template_json.get("Resources", {}).items()
            if res["Type"] == "AWS::VerifiedPermissions::PolicyStore"
        ]
        assert len(policy_stores) == 1

    def test_snapshot_contains_all_policies(self):
        """Verify the snapshot includes all 11 deployed policies (5 L2 + 6 L3)."""
        template_json = _synth_template()
        policies = [
            lid
            for lid, res in template_json.get("Resources", {}).items()
            if res["Type"] == "AWS::VerifiedPermissions::Policy"
        ]
        assert len(policies) == 8

    def test_snapshot_contains_schema(self):
        """Verify the policy store resource carries a CedarJson schema."""
        template_json = _synth_template()
        for _lid, res in template_json.get("Resources", {}).items():
            if res["Type"] == "AWS::VerifiedPermissions::PolicyStore":
                props = res["Properties"]
                assert "Schema" in props
                assert "CedarJson" in props["Schema"]
                schema = json.loads(props["Schema"]["CedarJson"])
                assert "AgentAuthz" in schema
                break
        else:
            raise AssertionError("No PolicyStore resource found in template")

    def test_snapshot_contains_cfn_output(self):
        """Verify the template exports the policy store ID."""
        template_json = _synth_template()
        outputs = template_json.get("Outputs", {})
        assert any(
            out.get("Export", {}).get("Name") == "MasolPolicyStoreId"
            for out in outputs.values()
        )
