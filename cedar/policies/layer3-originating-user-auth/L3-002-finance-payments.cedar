// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

// L3-002: Payment processing requires finance_manager or admin + MFA
permit(
  principal == AgentAuthz::Agent::"finance-agent",
  action == AgentAuthz::Action::"invoke_tool",
  resource == AgentAuthz::Tool::"process_payment"
) when {
  (context.originating_user.role == "admin" || context.originating_user.role == "finance_manager") &&
  context.originating_user.mfa_verified == true &&
  context.delegation_depth <= 3
};
