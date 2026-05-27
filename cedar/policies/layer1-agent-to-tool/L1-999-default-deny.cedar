// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

// L1-999: Default deny
forbid(
  principal,
  action == AgentAuthz::Action::"invoke_tool",
  resource
);
