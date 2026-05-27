// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

// L3-004: Read records requires at least analyst role
permit(
  principal == AgentAuthz::Agent::"data-bot",
  action == AgentAuthz::Action::"invoke_tool",
  resource == AgentAuthz::Tool::"read_records"
) when {
  (context.originating_user.role == "admin" || context.originating_user.role == "analyst" || context.originating_user.role == "data_engineer") &&
  context.delegation_depth <= 3
};
