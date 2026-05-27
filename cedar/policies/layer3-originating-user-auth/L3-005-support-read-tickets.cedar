// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

// L3-005: Read tickets — relaxed for support roles
permit(
  principal == AgentAuthz::Agent::"support-agent",
  action == AgentAuthz::Action::"invoke_tool",
  resource == AgentAuthz::Tool::"read_tickets"
) when {
  (context.originating_user.role == "admin" || context.originating_user.role == "support" || context.originating_user.role == "support_lead") &&
  context.delegation_depth <= 2
};
