// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

// L2-999: Default deny delegation
forbid(
  principal,
  action == AgentAuthz::Action::"delegate_task",
  resource
);
