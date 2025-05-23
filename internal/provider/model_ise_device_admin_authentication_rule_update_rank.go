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

// Code generated by "gen/generator.go"; DO NOT EDIT.

package provider

//template:begin imports
import (
	"context"
	"fmt"
	"net/url"

	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

//template:end imports

//template:begin types
type DeviceAdminAuthenticationRuleUpdateRank struct {
	Id          types.String `tfsdk:"id"`
	RuleId      types.String `tfsdk:"rule_id"`
	PolicySetId types.String `tfsdk:"policy_set_id"`
	Rank        types.Int64  `tfsdk:"rank"`
}

//template:end types

//template:begin getPath
func (data DeviceAdminAuthenticationRuleUpdateRank) getPath() string {
	return fmt.Sprintf("/api/v1/policy/device-admin/policy-set/%v/authentication", url.QueryEscape(data.PolicySetId.ValueString()))
}

//template:end getPath

//template:begin getPathDelete

//template:end getPathDelete

//template:begin toBody
func (data DeviceAdminAuthenticationRuleUpdateRank) toBody(ctx context.Context, state DeviceAdminAuthenticationRuleUpdateRank) string {
	body := ""
	if !data.RuleId.IsNull() {
		body, _ = sjson.Set(body, "", data.RuleId.ValueString())
	}
	if !data.Rank.IsNull() {
		body, _ = sjson.Set(body, "rule.rank", data.Rank.ValueInt64())
	}
	return body
}

//template:end toBody

//template:begin fromBody
func (data *DeviceAdminAuthenticationRuleUpdateRank) fromBody(ctx context.Context, res gjson.Result) {
	if value := res.Get("response.rule.rank"); value.Exists() && value.Type != gjson.Null {
		data.Rank = types.Int64Value(value.Int())
	} else {
		data.Rank = types.Int64Null()
	}
}

//template:end fromBody

//template:begin updateFromBody
func (data *DeviceAdminAuthenticationRuleUpdateRank) updateFromBody(ctx context.Context, res gjson.Result) {
	if value := res.Get("response.rule.rank"); value.Exists() && !data.Rank.IsNull() {
		data.Rank = types.Int64Value(value.Int())
	} else {
		data.Rank = types.Int64Null()
	}
}

//template:end updateFromBody

//template:begin isNull
func (data *DeviceAdminAuthenticationRuleUpdateRank) isNull(ctx context.Context, res gjson.Result) bool {
	if !data.RuleId.IsNull() {
		return false
	}
	if !data.Rank.IsNull() {
		return false
	}
	return true
}

//template:end isNull
