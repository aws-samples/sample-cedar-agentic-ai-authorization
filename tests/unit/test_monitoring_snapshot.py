# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""CDK snapshot tests for MonitoringStack.

Captures the full CloudFormation template as a JSON snapshot and compares
on subsequent runs to detect unintended infrastructure drift.

Validates: Requirements 9.1
"""

import json
from pathlib import Path

import aws_cdk as cdk
import aws_cdk.assertions as assertions

from stacks.monitoring_stack import MonitoringStack
from stacks.lambda_stack import LambdaStack
from stacks.verified_permissions_stack import VerifiedPermissionsStack

SNAPSHOT_DIR = Path(__file__).parent / "__snapshots__"
SNAPSHOT_FILE = SNAPSHOT_DIR / "monitoring_stack.json"


def _synth_template() -> dict:
    """Synthesize the MonitoringStack and return the raw template dict."""
    app = cdk.App()
    env = cdk.Environment(account="123456789012", region="us-east-1")
    vp = VerifiedPermissionsStack(app, "TestVP", env=env)
    ls = LambdaStack(app, "TestLS", verified_permissions_stack=vp, env=env)
    stack = MonitoringStack(app, "TestMonitoringStack", lambda_stack=ls, env=env)
    template = assertions.Template.from_stack(stack)
    return template.to_json()


class TestMonitoringSnapshot:
    """Snapshot tests for MonitoringStack CloudFormation template."""

    def test_template_matches_snapshot(self):
        """Validates: Requirements 9.1 — dashboard, alarms, SNS snapshot."""
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

    def test_snapshot_contains_dashboard(self):
        """Verify the template includes an Amazon CloudWatch dashboard."""
        template_json = _synth_template()
        dashboards = [
            lid
            for lid, res in template_json.get("Resources", {}).items()
            if res["Type"] == "AWS::CloudWatch::Dashboard"
        ]
        assert len(dashboards) == 1

    def test_snapshot_contains_sns_topic(self):
        """Verify the template includes an SNS topic for alarm notifications."""
        template_json = _synth_template()
        topics = [
            lid
            for lid, res in template_json.get("Resources", {}).items()
            if res["Type"] == "AWS::SNS::Topic"
        ]
        assert len(topics) == 1

    def test_snapshot_contains_denial_rate_alarms(self):
        """Verify the template includes 3 denial rate alarms (L1, L2, L3)."""
        template_json = _synth_template()
        alarms = [
            lid
            for lid, res in template_json.get("Resources", {}).items()
            if res["Type"] == "AWS::CloudWatch::Alarm"
            and "DenialRate" in res.get("Properties", {}).get("AlarmName", "")
        ]
        assert len(alarms) == 3

    def test_snapshot_contains_sig_failure_alarm(self):
        """Verify the template includes a signature verification failure alarm."""
        template_json = _synth_template()
        alarms = [
            lid
            for lid, res in template_json.get("Resources", {}).items()
            if res["Type"] == "AWS::CloudWatch::Alarm"
            and "SignatureVerification" in res.get("Properties", {}).get("AlarmName", "")
        ]
        assert len(alarms) == 1

    def test_snapshot_contains_latency_alarm(self):
        """Verify the template includes a latency degradation alarm."""
        template_json = _synth_template()
        alarms = [
            lid
            for lid, res in template_json.get("Resources", {}).items()
            if res["Type"] == "AWS::CloudWatch::Alarm"
            and "Latency" in res.get("Properties", {}).get("AlarmName", "")
        ]
        assert len(alarms) == 1

    def test_snapshot_total_alarm_count(self):
        """Verify the template has exactly 5 alarms (3 denial + 1 sig + 1 latency)."""
        template_json = _synth_template()
        alarms = [
            lid
            for lid, res in template_json.get("Resources", {}).items()
            if res["Type"] == "AWS::CloudWatch::Alarm"
        ]
        assert len(alarms) == 5

    def test_snapshot_contains_outputs(self):
        """Verify the template exports alarm topic ARN and dashboard name."""
        template_json = _synth_template()
        outputs = template_json.get("Outputs", {})
        export_names = [
            out.get("Export", {}).get("Name")
            for out in outputs.values()
        ]
        assert "MasolAlarmTopicArn" in export_names
        assert "MasolDashboardName" in export_names
