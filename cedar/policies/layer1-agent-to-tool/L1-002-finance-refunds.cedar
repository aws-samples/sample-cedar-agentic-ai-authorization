// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

// L1-002: Finance agent can invoke refund tools
permit(
  principal == AgentAuthz::Agent::"finance-agent",
  action == AgentAuthz::Action::"invoke_tool",
  resource == AgentAuthz::Tool::"process_refund"
) when {
  principal.trust_level >= 3 &&
  principal.namespace == "payments" &&
  principal.lifecycle_stage == "production"
};
