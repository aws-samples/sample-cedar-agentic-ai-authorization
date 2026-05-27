# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""MonitoringStack: Amazon CloudWatch dashboard, alarms, and SNS notifications.

Creates an Amazon CloudWatch dashboard with policy evaluation metrics, Amazon CloudWatch
alarms for denial rate spikes / latency degradation / signature verification
failures, and an SNS topic for alarm notifications.

Validates: Requirements 4.6, 9.1, 9.2
"""

from typing import Optional

import aws_cdk as cdk
import aws_cdk.aws_cloudwatch as cw
import aws_cdk.aws_cloudwatch_actions as cw_actions
import aws_cdk.aws_kms as kms
import aws_cdk.aws_sns as sns
from constructs import Construct

# Metric namespace used by the Cedar Evaluator Lambda
_METRIC_NAMESPACE = "AgentAuthzProtection"


class MonitoringStack(cdk.Stack):
    """Stack for Amazon CloudWatch dashboard, alarms, and SNS topic.

    Args:
        scope: CDK construct scope.
        construct_id: Logical ID for this stack.
        lambda_stack: LambdaStack for cross-stack references.
        denial_rate_threshold: Alarm threshold for denial rate (default 0.1).
        alarm_evaluation_periods: Number of 5-min periods for alarm eval (default 5).
    """

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        lambda_stack: cdk.Stack,
        kms_key: Optional[kms.IKey] = None,
        **kwargs,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)
        self.lambda_stack = lambda_stack

        denial_rate_threshold = self.node.try_get_context(
            "denial_rate_alarm_threshold",
        ) or 0.1
        alarm_evaluation_periods = self.node.try_get_context(
            "alarm_evaluation_periods",
        ) or 5

        # ── SNS topic for alarm notifications ────────────────────
        # Note: master_key is the CDK API parameter name for SNS Topic
        # encryption. This is not author-controlled terminology — it is required
        # by the aws_cdk.aws_sns.Topic API.
        self.alarm_topic = sns.Topic(
            self,
            "AlarmTopic",
            topic_name="cedar-policy-alarms",
            display_name="Cedar Policy Evaluation Alarms",
            master_key=kms_key,  # CDK API parameter name
        )

        # ── Metrics ──────────────────────────────────────────────
        latency_metric = cw.Metric(
            namespace=_METRIC_NAMESPACE,
            metric_name="PolicyEvaluationLatency",
            statistic="Average",
            period=cdk.Duration.minutes(5),
        )

        evaluation_count_metric = cw.Metric(
            namespace=_METRIC_NAMESPACE,
            metric_name="PolicyEvaluationCount",
            statistic="Sum",
            period=cdk.Duration.minutes(5),
        )

        sig_failure_metric = cw.Metric(
            namespace=_METRIC_NAMESPACE,
            metric_name="SignatureVerificationFailure",
            statistic="Sum",
            period=cdk.Duration.minutes(5),
        )

        depth_exceeded_metric = cw.Metric(
            namespace=_METRIC_NAMESPACE,
            metric_name="DelegationDepthExceeded",
            statistic="Sum",
            period=cdk.Duration.minutes(5),
        )

        # ── Dashboard ────────────────────────────────────────────
        self.dashboard = cw.Dashboard(
            self,
            "PolicyEvaluationDashboard",
            dashboard_name="CedarPolicyEvaluation",
        )

        # Row 1: Latency percentiles (p50, p95, p99)
        self.dashboard.add_widgets(
            cw.GraphWidget(
                title="PolicyEvaluationLatency (p50/p95/p99)",
                left=[
                    cw.Metric(
                        namespace=_METRIC_NAMESPACE,
                        metric_name="PolicyEvaluationLatency",
                        statistic="p50",
                        period=cdk.Duration.minutes(5),
                        label="p50",
                    ),
                    cw.Metric(
                        namespace=_METRIC_NAMESPACE,
                        metric_name="PolicyEvaluationLatency",
                        statistic="p95",
                        period=cdk.Duration.minutes(5),
                        label="p95",
                    ),
                    cw.Metric(
                        namespace=_METRIC_NAMESPACE,
                        metric_name="PolicyEvaluationLatency",
                        statistic="p99",
                        period=cdk.Duration.minutes(5),
                        label="p99",
                    ),
                ],
                width=12,
            ),
        )

        # Row 2: Evaluation count by layer and decision
        self.dashboard.add_widgets(
            cw.GraphWidget(
                title="PolicyEvaluationCount by Layer & Decision",
                left=[
                    cw.Metric(
                        namespace=_METRIC_NAMESPACE,
                        metric_name="PolicyEvaluationCount",
                        dimensions_map={"Layer": "L1", "Decision": "PERMIT"},
                        statistic="Sum",
                        period=cdk.Duration.minutes(5),
                        label="L1 PERMIT",
                    ),
                    cw.Metric(
                        namespace=_METRIC_NAMESPACE,
                        metric_name="PolicyEvaluationCount",
                        dimensions_map={"Layer": "L1", "Decision": "DENY"},
                        statistic="Sum",
                        period=cdk.Duration.minutes(5),
                        label="L1 DENY",
                    ),
                    cw.Metric(
                        namespace=_METRIC_NAMESPACE,
                        metric_name="PolicyEvaluationCount",
                        dimensions_map={"Layer": "L2", "Decision": "PERMIT"},
                        statistic="Sum",
                        period=cdk.Duration.minutes(5),
                        label="L2 PERMIT",
                    ),
                    cw.Metric(
                        namespace=_METRIC_NAMESPACE,
                        metric_name="PolicyEvaluationCount",
                        dimensions_map={"Layer": "L2", "Decision": "DENY"},
                        statistic="Sum",
                        period=cdk.Duration.minutes(5),
                        label="L2 DENY",
                    ),
                    cw.Metric(
                        namespace=_METRIC_NAMESPACE,
                        metric_name="PolicyEvaluationCount",
                        dimensions_map={"Layer": "L3", "Decision": "PERMIT"},
                        statistic="Sum",
                        period=cdk.Duration.minutes(5),
                        label="L3 PERMIT",
                    ),
                    cw.Metric(
                        namespace=_METRIC_NAMESPACE,
                        metric_name="PolicyEvaluationCount",
                        dimensions_map={"Layer": "L3", "Decision": "DENY"},
                        statistic="Sum",
                        period=cdk.Duration.minutes(5),
                        label="L3 DENY",
                    ),
                ],
                width=12,
            ),
        )

        # Row 3: DenialRate per layer
        self.dashboard.add_widgets(
            cw.GraphWidget(
                title="DenialRate per Layer",
                left=[
                    cw.Metric(
                        namespace=_METRIC_NAMESPACE,
                        metric_name="DenialRate",
                        dimensions_map={"Layer": layer},
                        statistic="Average",
                        period=cdk.Duration.minutes(5),
                        label=f"{layer} DenialRate",
                    )
                    for layer in ("L1", "L2", "L3")
                ],
                width=12,
            ),
        )

        # Row 4: SignatureVerificationFailure and DelegationDepthExceeded
        self.dashboard.add_widgets(
            cw.GraphWidget(
                title="SignatureVerificationFailure",
                left=[sig_failure_metric],
                width=6,
            ),
            cw.GraphWidget(
                title="DelegationDepthExceeded",
                left=[depth_exceeded_metric],
                width=6,
            ),
        )

        # ── Alarms ───────────────────────────────────────────────

        # Denial rate alarm per layer (threshold 0.1 over 5-min window)
        self.denial_rate_alarms: list[cw.Alarm] = []
        for layer in ("L1", "L2", "L3"):
            alarm = cw.Alarm(
                self,
                f"DenialRateAlarm{layer}",
                alarm_name=f"CedarDenialRate-{layer}",
                alarm_description=(
                    f"Denial rate for {layer} exceeds "
                    f"{denial_rate_threshold} over 5-minute window"
                ),
                metric=cw.Metric(
                    namespace=_METRIC_NAMESPACE,
                    metric_name="DenialRate",
                    dimensions_map={"Layer": layer},
                    statistic="Average",
                    period=cdk.Duration.minutes(5),
                ),
                threshold=float(denial_rate_threshold),
                evaluation_periods=int(alarm_evaluation_periods),
                comparison_operator=cw.ComparisonOperator.GREATER_THAN_THRESHOLD,
                treat_missing_data=cw.TreatMissingData.NOT_BREACHING,
            )
            alarm.add_alarm_action(cw_actions.SnsAction(self.alarm_topic))
            self.denial_rate_alarms.append(alarm)

        # Signature verification failure spike alarm
        self.sig_failure_alarm = cw.Alarm(
            self,
            "SignatureVerificationFailureAlarm",
            alarm_name="CedarSignatureVerificationFailure",
            alarm_description="Signature verification failures detected",
            metric=sig_failure_metric,
            threshold=1,
            evaluation_periods=1,
            comparison_operator=cw.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
            treat_missing_data=cw.TreatMissingData.NOT_BREACHING,
        )
        self.sig_failure_alarm.add_alarm_action(
            cw_actions.SnsAction(self.alarm_topic),
        )

        # Latency degradation alarm (p99 > 5ms)
        self.latency_alarm = cw.Alarm(
            self,
            "LatencyDegradationAlarm",
            alarm_name="CedarLatencyDegradation",
            alarm_description="Policy evaluation p99 latency exceeds 5ms",
            metric=cw.Metric(
                namespace=_METRIC_NAMESPACE,
                metric_name="PolicyEvaluationLatency",
                statistic="p99",
                period=cdk.Duration.minutes(5),
            ),
            threshold=5,
            evaluation_periods=int(alarm_evaluation_periods),
            comparison_operator=cw.ComparisonOperator.GREATER_THAN_THRESHOLD,
            treat_missing_data=cw.TreatMissingData.NOT_BREACHING,
        )
        self.latency_alarm.add_alarm_action(
            cw_actions.SnsAction(self.alarm_topic),
        )

        # ── Outputs ──────────────────────────────────────────────
        cdk.CfnOutput(
            self,
            "AlarmTopicArn",
            value=self.alarm_topic.topic_arn,
            description="SNS topic ARN for Cedar policy evaluation alarms",
            export_name="MasolAlarmTopicArn",
        )

        cdk.CfnOutput(
            self,
            "DashboardName",
            value=self.dashboard.dashboard_name,
            description="Amazon CloudWatch dashboard name",
            export_name="MasolDashboardName",
        )
