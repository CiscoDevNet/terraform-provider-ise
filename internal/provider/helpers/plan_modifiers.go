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

// AdoptStateWhenSiblingBoolEquals returns a String plan modifier for an attribute
// whose ownership flips based on a sibling Bool attribute. It backs the definition
// flag `computed_when: <sibling>=<bool>`.
//
//   - sibling != expected → the attribute is operator-owned; the modifier does nothing
//     and the normal config-vs-state diff applies.
//   - sibling == expected → the attribute is server-owned (ISE computes it). When the
//     operator leaves the attribute unset (config null), the modifier keeps the prior
//     state value instead of planning a change to null. This is what prevents the
//     perpetual "UUID -> null" ghost diff on ise_endpoint.profile_id for dynamically
//     profiled endpoints (static_profile_assignment=false) after a brownfield import.
//
// Unlike UseStateForUnknown, this only suppresses the diff on the server-owned branch,
// so genuine operator changes on the operator-owned branch still plan normally, and
// the attribute is not blanket-frozen.
func AdoptStateWhenSiblingBoolEquals(siblingAttr string, expected bool) planmodifier.String {
	return adoptStateWhenSiblingBoolEquals{siblingAttr: siblingAttr, expected: expected}
}

type adoptStateWhenSiblingBoolEquals struct {
	siblingAttr string
	expected    bool
}

func (m adoptStateWhenSiblingBoolEquals) Description(_ context.Context) string {
	return fmt.Sprintf("Keeps the prior state value when the sibling attribute '%s' is %t "+
		"and this attribute is not set in the configuration.", m.siblingAttr, m.expected)
}

func (m adoptStateWhenSiblingBoolEquals) MarkdownDescription(ctx context.Context) string {
	return m.Description(ctx)
}

func (m adoptStateWhenSiblingBoolEquals) PlanModifyString(ctx context.Context, req planmodifier.StringRequest, resp *planmodifier.StringResponse) {
	// Only act when the operator did not set this attribute in the configuration.
	// An explicit config value (including an explicit null) is always honored.
	if !req.ConfigValue.IsNull() {
		return
	}

	// On create there is no prior state to adopt; leave the planned value as-is.
	if req.StateValue.IsNull() {
		return
	}

	// Read the sibling Bool from the plan. If it is unknown or does not match the
	// expected value, do nothing (operator-owned branch).
	var sibling types.Bool
	diags := req.Plan.GetAttribute(ctx, path.Root(m.siblingAttr), &sibling)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	if sibling.IsUnknown() || sibling.IsNull() || sibling.ValueBool() != m.expected {
		return
	}

	// Server-owned branch (sibling == expected) with no operator config: keep state.
	resp.PlanValue = req.StateValue
}
