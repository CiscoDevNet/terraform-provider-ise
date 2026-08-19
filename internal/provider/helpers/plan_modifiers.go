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

// PreserveStateIfUnconfigured returns a List plan modifier for nested list attributes
// marked Computed: true that are managed outside the join_point resource (e.g. groups
// managed by ise_active_directory_add_groups). When the attribute is not set in config
// (null), it preserves the prior state value so that groups already stored in Terraform
// state do not appear as a diff. On first create (no prior state) it returns null rather
// than unknown, preventing the type-conversion error that listplanmodifier.UseStateForUnknown()
// would cause when the model struct uses []T.
func PreserveStateIfUnconfigured() planmodifier.List {
	return preserveStateIfUnconfigured{}
}

type preserveStateIfUnconfigured struct{}

func (m preserveStateIfUnconfigured) Description(_ context.Context) string {
	return "Preserves the prior state value when the attribute is not set in config, " +
		"preventing spurious diffs for server-managed list attributes."
}

func (m preserveStateIfUnconfigured) MarkdownDescription(ctx context.Context) string {
	return m.Description(ctx)
}

func (m preserveStateIfUnconfigured) PlanModifyList(ctx context.Context, req planmodifier.ListRequest, resp *planmodifier.ListResponse) {
	if !req.ConfigValue.IsNull() {
		return
	}
	if !req.StateValue.IsNull() && !req.StateValue.IsUnknown() {
		resp.PlanValue = req.StateValue
		return
	}
	resp.PlanValue = types.ListNull(req.PlanValue.ElementType(ctx))
}

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
	// On the server-owned branch (sibling == expected) the value is assigned by ISE.
	var sibling types.Bool
	diags := req.Plan.GetAttribute(ctx, path.Root(m.siblingAttr), &sibling)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	if sibling.IsUnknown() || sibling.IsNull() || sibling.ValueBool() != m.expected {
		return
	}
	// On create there is no prior state, so let the value stay unknown.
	if req.State.Raw.IsNull() {
		return
	}
	// If the prior state has no value (import/refresh of a dynamic endpoint that ISE
	// left unset), keep it null so a fresh import shows no diff.
	if req.StateValue.IsNull() {
		resp.PlanValue = types.StringNull()
		return
	}
	// State holds an ISE-assigned value. ISE may reassign it on any update, so reuse it
	// only on a no-op; if anything else in the resource is changing, plan it unknown and
	// let the read-back fill in ISE's real value.
	if !req.Plan.Raw.Equal(req.State.Raw) {
		resp.PlanValue = types.StringUnknown()
		return
	}
	resp.PlanValue = req.StateValue
}
