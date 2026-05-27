// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

// L3-003: Refund processing requires finance roles + MFA
permit(
  principal == AgentAuthz::Agent::"finance-agent",
  action == AgentAuthz::Action::"invoke_tool",
  resource == AgentAuthz::Tool::"process_refund"
) when {
  (context.originating_user.role == "admin" || context.originating_user.role == "finance_manager" || context.originating_user.role == "support_lead") &&
  context.originating_user.mfa_verified == true &&
  context.delegation_depth <= 3
};
