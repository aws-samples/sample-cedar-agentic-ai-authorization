// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

// L2-003: Orchestrator can delegate to support agent
permit(
  principal == AgentAuthz::Agent::"orchestrator",
  action == AgentAuthz::Action::"delegate_task",
  resource == AgentAuthz::Agent::"support-agent"
) when {
  context.delegation_depth <= 2 &&
  context.target_capabilities.containsAll(context.requested_capabilities)
};
