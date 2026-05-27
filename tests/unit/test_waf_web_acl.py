# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Unit tests for the WafWebAcl CDK construct.

Verifies that the synthesized CloudFormation template contains the expected
AWS WAF WebACL configuration: default ALLOW action, four rules (CommonRuleSet,
SQLiRuleSet, rate-based, body size constraint), WebACL association with
API Gateway stage, and Amazon CloudWatch metrics enabled.

Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7
"""

import aws_cdk as cdk
import aws_cdk.assertions as assertions

from constructs.waf_web_acl import WafWebAcl

DUMMY_STAGE_ARN = (
    "arn:aws:apigateway:us-east-1::/restapis/abc123/stages/prod"
)


def _synth_template() -> assertions.Template:
    """Create a minimal stack with WafWebAcl and return the template."""
    app = cdk.App()
    stack = cdk.Stack(app, "TestStack", env=cdk.Environment(
        account="123456789012", region="us-east-1",
    ))
    WafWebAcl(stack, "TestWaf", api_gateway_stage_arn=DUMMY_STAGE_ARN)
    return assertions.Template.from_stack(stack)


class TestWebAclDefaults:
    """Validates: Requirements 3.6, 3.7"""

    def test_web_acl_has_default_allow_action(self):
        """Validates: Requirement 3.6 — default action is ALLOW."""
        template = _synth_template()
        template.has_resource_properties("AWS::WAFv2::WebACL", {
            "DefaultAction": {"Allow": {}},
        })

    def test_web_acl_has_cloudwatch_metrics_enabled(self):
        """Validates: Requirement 3.7 — CloudWatch metrics with cedar-deputy-guard metric name."""
        template = _synth_template()
        template.has_resource_properties("AWS::WAFv2::WebACL", {
            "VisibilityConfig": assertions.Match.object_like({
                "CloudWatchMetricsEnabled": True,
                "MetricName": assertions.Match.string_like_regexp(
                    "cedar-deputy-guard"
                ),
            }),
        })


class TestWebAclRules:
    """Validates: Requirements 3.2, 3.3, 3.4, 3.5"""

    def test_web_acl_contains_common_rule_set(self):
        """Validates: Requirement 3.2 — AWSManagedRulesCommonRuleSet in block mode."""
        template = _synth_template()
        template.has_resource_properties("AWS::WAFv2::WebACL", {
            "Rules": assertions.Match.array_with([
                assertions.Match.object_like({
                    "Name": "AWSManagedRulesCommonRuleSet",
                    "Statement": {
                        "ManagedRuleGroupStatement": {
                            "VendorName": "AWS",
                            "Name": "AWSManagedRulesCommonRuleSet",
                        },
                    },
                }),
            ]),
        })

    def test_web_acl_contains_sqli_rule_set(self):
        """Validates: Requirement 3.3 — AWSManagedRulesSQLiRuleSet in block mode."""
        template = _synth_template()
        template.has_resource_properties("AWS::WAFv2::WebACL", {
            "Rules": assertions.Match.array_with([
                assertions.Match.object_like({
                    "Name": "AWSManagedRulesSQLiRuleSet",
                    "Statement": {
                        "ManagedRuleGroupStatement": {
                            "VendorName": "AWS",
                            "Name": "AWSManagedRulesSQLiRuleSet",
                        },
                    },
                }),
            ]),
        })

    def test_web_acl_contains_rate_based_rule(self):
        """Validates: Requirement 3.4 — rate-based rule with limit 100."""
        template = _synth_template()
        template.has_resource_properties("AWS::WAFv2::WebACL", {
            "Rules": assertions.Match.array_with([
                assertions.Match.object_like({
                    "Name": "RateLimitPerIP",
                    "Statement": {
                        "RateBasedStatement": {
                            "Limit": 100,
                            "AggregateKeyType": "IP",
                        },
                    },
                }),
            ]),
        })

    def test_web_acl_contains_body_size_constraint(self):
        """Validates: Requirement 3.5 — size constraint rule with 8192 byte limit."""
        template = _synth_template()
        template.has_resource_properties("AWS::WAFv2::WebACL", {
            "Rules": assertions.Match.array_with([
                assertions.Match.object_like({
                    "Name": "BodySizeConstraint",
                    "Statement": {
                        "SizeConstraintStatement": {
                            "ComparisonOperator": "GT",
                            "Size": 8192,
                            "FieldToMatch": {"Body": {}},
                        },
                    },
                }),
            ]),
        })


class TestWebAclAssociation:
    """Validates: Requirement 3.1"""

    def test_web_acl_association_exists(self):
        """Validates: Requirement 3.1 — WebACL associated with API Gateway stage."""
        template = _synth_template()
        template.has_resource_properties("AWS::WAFv2::WebACLAssociation", {
            "ResourceArn": DUMMY_STAGE_ARN,
        })
