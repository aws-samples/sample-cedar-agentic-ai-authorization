// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

// L3-001: High-risk tool (delete_records) requires admin + MFA
permit(
  principal == AgentAuthz::Agent::"data-bot",
  action == AgentAuthz::Action::"invoke_tool",
  resource == AgentAuthz::Tool::"delete_records"
) when {
  context.originating_user.role == "admin" &&
  context.originating_user.mfa_verified == true &&
  context.delegation_depth <= 2
};
