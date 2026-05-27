// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

// L3-999: Default deny when no originating user context
forbid(
  principal,
  action == AgentAuthz::Action::"invoke_tool",
  resource
) when {
  !(context has originating_user)
};
