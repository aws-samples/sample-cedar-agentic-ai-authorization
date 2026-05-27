// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

// L1-005: Support agent can read tickets
permit(
  principal == AgentAuthz::Agent::"support-agent",
  action == AgentAuthz::Action::"invoke_tool",
  resource == AgentAuthz::Tool::"read_tickets"
) when {
  principal.trust_level >= 1 &&
  principal.namespace == "support"
};
