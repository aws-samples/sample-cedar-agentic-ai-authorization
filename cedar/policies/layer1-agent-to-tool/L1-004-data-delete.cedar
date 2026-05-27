// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

// L1-004: Data agent can delete records (high-risk)
permit(
  principal == AgentAuthz::Agent::"data-bot",
  action == AgentAuthz::Action::"invoke_tool",
  resource == AgentAuthz::Tool::"delete_records"
) when {
  principal.trust_level >= 4 &&
  principal.namespace == "data" &&
  principal.lifecycle_stage == "production"
};
