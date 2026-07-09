// Copyright © 2023 Cisco Systems, Inc. and its affiliates.
// All rights reserved.
//
// Licensed under the Mozilla Public License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://mozilla.org/MPL/2.0/
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: MPL-2.0

package helpers

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// ComputedWhen returns a String plan modifier backing the definition flag
// `computed_when: <sibling>=<bool>`. When the sibling Bool equals expected and the
// attribute is unset in config, it keeps the prior state value instead of planning a
// change to null (a conditional UseStateForUnknown for server-owned-on-condition fields).
func ComputedWhen(siblingAttr string, expected bool) planmodifier.String {
	return computedWhen{siblingAttr: siblingAttr, expected: expected}
}

type computedWhen struct {
	siblingAttr string
	expected    bool
}

func (m computedWhen) Description(_ context.Context) string {
	return fmt.Sprintf("Keeps the prior state value when the sibling attribute '%s' is %t "+
		"and this attribute is not set in the configuration.", m.siblingAttr, m.expected)
}

func (m computedWhen) MarkdownDescription(ctx context.Context) string {
	return m.Description(ctx)
}

func (m computedWhen) PlanModifyString(ctx context.Context, req planmodifier.StringRequest, resp *planmodifier.StringResponse) {
	// An explicit config value (including explicit null) is always honored.
	if !req.ConfigValue.IsNull() {
		return
	}
	// On create there is no prior state to adopt.
	if req.StateValue.IsNull() {
		return
	}
	// Keep state only on the server-owned branch (sibling == expected).
	var sibling types.Bool
	diags := req.Plan.GetAttribute(ctx, path.Root(m.siblingAttr), &sibling)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	if sibling.IsUnknown() || sibling.IsNull() || sibling.ValueBool() != m.expected {
		return
	}
	resp.PlanValue = req.StateValue
}
