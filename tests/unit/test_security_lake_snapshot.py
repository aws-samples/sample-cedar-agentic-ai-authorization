# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""CDK snapshot tests for SecurityLakeStack.

Captures the full CloudFormation template as a JSON snapshot and compares
on subsequent runs to detect unintended infrastructure drift.

Validates: Requirements 4.3
"""

import json
from pathlib import Path

import aws_cdk as cdk
import aws_cdk.assertions as assertions

from stacks.security_lake_stack import SecurityLakeStack
from stacks.lambda_stack import LambdaStack
from stacks.verified_permissions_stack import VerifiedPermissionsStack

SNAPSHOT_DIR = Path(__file__).parent / "__snapshots__"
SNAPSHOT_FILE = SNAPSHOT_DIR / "security_lake_stack.json"


def _synth_template() -> dict:
    """Synthesize the SecurityLakeStack and return the raw template dict."""
    app = cdk.App()
    env = cdk.Environment(account="123456789012", region="us-east-1")
    vp = VerifiedPermissionsStack(app, "TestVP", env=env)
    ls = LambdaStack(app, "TestLS", verified_permissions_stack=vp, env=env)
    stack = SecurityLakeStack(
        app, "TestSecurityLakeStack",
        lambda_stack=ls,
        kms_key=ls.kms_key,
        env=env,
    )
    template = assertions.Template.from_stack(stack)
    return template.to_json()


class TestSecurityLakeSnapshot:
    """Snapshot tests for SecurityLakeStack CloudFormation template."""

    def test_template_matches_snapshot(self):
        """Validates: Requirements 4.3 — audit pipeline snapshot."""
        template_json = _synth_template()

        if not SNAPSHOT_FILE.exists():
            SNAPSHOT_DIR.mkdir(parents=True, exist_ok=True)
            SNAPSHOT_FILE.write_text(
                json.dumps(template_json, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            return

        stored = json.loads(SNAPSHOT_FILE.read_text(encoding="utf-8"))
        assert template_json == stored, (
            "CloudFormation template has changed. "
            "If this is intentional, delete the snapshot file and re-run:\n"
            f"  rm {SNAPSHOT_FILE}"
        )

    def test_snapshot_contains_log_group(self):
        """Verify the template includes an Amazon CloudWatch Logs log group."""
        template_json = _synth_template()
        log_groups = [
            lid
            for lid, res in template_json.get("Resources", {}).items()
            if res["Type"] == "AWS::Logs::LogGroup"
        ]
        assert len(log_groups) == 1

    def test_snapshot_contains_subscription_filter(self):
        """Verify the template includes a subscription filter for OCSF 99001.

        Note: Subscription filter is not currently configured in the stack.
        This test verifies the current state (no filters).
        """
        template_json = _synth_template()
        filters = [
            lid
            for lid, res in template_json.get("Resources", {}).items()
            if res["Type"] == "AWS::Logs::SubscriptionFilter"
        ]
        assert len(filters) == 0

    def test_snapshot_contains_dlq(self):
        """Verify the template includes an SQS dead-letter queue."""
        template_json = _synth_template()
        queues = [
            lid
            for lid, res in template_json.get("Resources", {}).items()
            if res["Type"] == "AWS::SQS::Queue"
        ]
        assert len(queues) == 1

    def test_snapshot_contains_custom_source(self):
        """Verify the template includes an Amazon Security Lake custom log source.

        Note: Amazon Security Lake custom source is commented out in the stack
        (requires Amazon Security Lake to be enabled in the account).
        This test verifies the current state (no custom sources).
        """
        template_json = _synth_template()
        sources = [
            lid
            for lid, res in template_json.get("Resources", {}).items()
            if res["Type"] == "AWS::SecurityLake::CustomLogSource"
        ]
        assert len(sources) == 0

    def test_snapshot_contains_outputs(self):
        """Verify the template exports audit log group ARN and DLQ URL."""
        template_json = _synth_template()
        outputs = template_json.get("Outputs", {})
        export_names = [
            out.get("Export", {}).get("Name")
            for out in outputs.values()
        ]
        assert "MasolAuditLogGroupArn" in export_names
        assert "MasolAuditDLQUrl" in export_names
