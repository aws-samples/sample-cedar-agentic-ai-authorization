// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

// L2-004: Hard limit on delegation depth
forbid(
  principal,
  action == AgentAuthz::Action::"delegate_task",
  resource
) when {
  context.delegation_depth > 5
};
