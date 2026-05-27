# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""CDK construct for an AWS WAF v2 WebACL protecting API Gateway.

Creates a regional AWS WAF WebACL with four rules: AWS CommonRuleSet,
AWS SQLiRuleSet, IP rate limiting (100 req/5min), and request body
size constraint (8192 bytes). Associates the WebACL with the
API Gateway stage.

Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7
"""

from __future__ import annotations

import aws_cdk.aws_wafv2 as wafv2
from constructs import Construct


class WafWebAcl(Construct):
    """CDK construct for the cedar-deputy-guard AWS WAF WebACL.

    Args:
        scope: CDK construct scope.
        construct_id: Logical ID for this construct.
        api_gateway_stage_arn: ARN of the API Gateway stage to protect.
    """

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        *,
        api_gateway_stage_arn: str,
    ) -> None:
        super().__init__(scope, construct_id)

        self._web_acl = wafv2.CfnWebACL(
            self,
            "WebACL",
            scope="REGIONAL",
            default_action=wafv2.CfnWebACL.DefaultActionProperty(allow={}),
            visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
                cloud_watch_metrics_enabled=True,
                metric_name="cedar-deputy-guard-waf",
                sampled_requests_enabled=True,
            ),
            name="cedar-deputy-guard-waf",
            description="AWS WAF WebACL for cedar-deputy-guard API Gateway",
            rules=[
                # ── Rule 1: AWS Managed Common Rule Set ──────────
                wafv2.CfnWebACL.RuleProperty(
                    name="AWSManagedRulesCommonRuleSet",
                    priority=1,
                    override_action=wafv2.CfnWebACL.OverrideActionProperty(
                        none={},
                    ),
                    statement=wafv2.CfnWebACL.StatementProperty(
                        managed_rule_group_statement=wafv2.CfnWebACL.ManagedRuleGroupStatementProperty(
                            vendor_name="AWS",
                            name="AWSManagedRulesCommonRuleSet",
                        ),
                    ),
                    visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
                        cloud_watch_metrics_enabled=True,
                        metric_name="cedar-deputy-guard-common-rules",
                        sampled_requests_enabled=True,
                    ),
                ),
                # ── Rule 2: AWS Managed SQLi Rule Set ────────────
                wafv2.CfnWebACL.RuleProperty(
                    name="AWSManagedRulesSQLiRuleSet",
                    priority=2,
                    override_action=wafv2.CfnWebACL.OverrideActionProperty(
                        none={},
                    ),
                    statement=wafv2.CfnWebACL.StatementProperty(
                        managed_rule_group_statement=wafv2.CfnWebACL.ManagedRuleGroupStatementProperty(
                            vendor_name="AWS",
                            name="AWSManagedRulesSQLiRuleSet",
                        ),
                    ),
                    visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
                        cloud_watch_metrics_enabled=True,
                        metric_name="cedar-deputy-guard-sqli-rules",
                        sampled_requests_enabled=True,
                    ),
                ),
                # ── Rule 3: Rate-based rule (100 req/5min per IP) ─
                wafv2.CfnWebACL.RuleProperty(
                    name="RateLimitPerIP",
                    priority=3,
                    action=wafv2.CfnWebACL.RuleActionProperty(
                        block={},
                    ),
                    statement=wafv2.CfnWebACL.StatementProperty(
                        rate_based_statement=wafv2.CfnWebACL.RateBasedStatementProperty(
                            limit=100,
                            aggregate_key_type="IP",
                        ),
                    ),
                    visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
                        cloud_watch_metrics_enabled=True,
                        metric_name="cedar-deputy-guard-rate-limit",
                        sampled_requests_enabled=True,
                    ),
                ),
                # ── Rule 4: Body size constraint (8192 bytes) ────
                wafv2.CfnWebACL.RuleProperty(
                    name="BodySizeConstraint",
                    priority=4,
                    action=wafv2.CfnWebACL.RuleActionProperty(
                        block={},
                    ),
                    statement=wafv2.CfnWebACL.StatementProperty(
                        size_constraint_statement=wafv2.CfnWebACL.SizeConstraintStatementProperty(
                            field_to_match=wafv2.CfnWebACL.FieldToMatchProperty(
                                body={},
                            ),
                            comparison_operator="GT",
                            size=8192,
                            text_transformations=[
                                wafv2.CfnWebACL.TextTransformationProperty(
                                    priority=0,
                                    type="NONE",
                                ),
                            ],
                        ),
                    ),
                    visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
                        cloud_watch_metrics_enabled=True,
                        metric_name="cedar-deputy-guard-body-size",
                        sampled_requests_enabled=True,
                    ),
                ),
            ],
        )

        # ── Associate WebACL with API Gateway stage ──────────────
        wafv2.CfnWebACLAssociation(
            self,
            "WebACLAssociation",
            web_acl_arn=self._web_acl.attr_arn,
            resource_arn=api_gateway_stage_arn,
        )

    @property
    def web_acl_arn(self) -> str:
        """The WebACL ARN for CloudFormation output."""
        return self._web_acl.attr_arn
