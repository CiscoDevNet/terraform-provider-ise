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
	"strconv"

	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

//template:end imports

//template:begin types
type DeviceAdminAuthenticationRuleUpdateRanks struct {
	Id          types.String                                    `tfsdk:"id"`
	PolicySetId types.String                                    `tfsdk:"policy_set_id"`
	Rules       []DeviceAdminAuthenticationRuleUpdateRanksRules `tfsdk:"rules"`
}

type DeviceAdminAuthenticationRuleUpdateRanksRules struct {
	Id   types.String `tfsdk:"id"`
	Rank types.Int64  `tfsdk:"rank"`
}

//template:end types

//template:begin getPath
func (data DeviceAdminAuthenticationRuleUpdateRanks) getPath() string {
	return fmt.Sprintf("/api/v1/policy/device-admin/policy-set/%v/authentication", url.QueryEscape(data.PolicySetId.ValueString()))
}

//template:end getPath

//template:begin getPathDelete

//template:end getPathDelete

//template:begin toBody
func (data DeviceAdminAuthenticationRuleUpdateRanks) toBody(ctx context.Context, state DeviceAdminAuthenticationRuleUpdateRanks) string {
	body := ""
	if len(data.Rules) > 0 {
		body, _ = sjson.Set(body, "rules", []interface{}{})
		for _, item := range data.Rules {
			itemBody := ""
			if !item.Id.IsNull() {
				itemBody, _ = sjson.Set(itemBody, "rule.id", item.Id.ValueString())
			}
			if !item.Rank.IsNull() {
				itemBody, _ = sjson.Set(itemBody, "rule.rank", item.Rank.ValueInt64())
			}
			body, _ = sjson.SetRaw(body, "rules.-1", itemBody)
		}
	}
	return body
}

//template:end toBody

//template:begin fromBody
func (data *DeviceAdminAuthenticationRuleUpdateRanks) fromBody(ctx context.Context, res gjson.Result) {
	if value := res.Get("response.rules"); value.Exists() {
		data.Rules = make([]DeviceAdminAuthenticationRuleUpdateRanksRules, 0)
		value.ForEach(func(k, v gjson.Result) bool {
			item := DeviceAdminAuthenticationRuleUpdateRanksRules{}
			if cValue := v.Get("rule.id"); cValue.Exists() && cValue.Type != gjson.Null {
				item.Id = types.StringValue(cValue.String())
			} else {
				item.Id = types.StringNull()
			}
			if cValue := v.Get("rule.rank"); cValue.Exists() && cValue.Type != gjson.Null {
				item.Rank = types.Int64Value(cValue.Int())
			} else {
				item.Rank = types.Int64Null()
			}
			data.Rules = append(data.Rules, item)
			return true
		})
	}
}

//template:end fromBody

//template:begin updateFromBody
func (data *DeviceAdminAuthenticationRuleUpdateRanks) updateFromBody(ctx context.Context, res gjson.Result) {
	for i := range data.Rules {
		keys := [...]string{"rule.id", "rule.rank"}
		keyValues := [...]string{data.Rules[i].Id.ValueString(), strconv.FormatInt(data.Rules[i].Rank.ValueInt64(), 10)}

		var r gjson.Result
		res.Get("response").ForEach(
			func(_, v gjson.Result) bool {
				found := false
				for ik := range keys {
					if v.Get(keys[ik]).String() == keyValues[ik] {
						found = true
						continue
					}
					found = false
					break
				}
				if found {
					r = v
					return false
				}
				return true
			},
		)
		if value := r.Get("rule.id"); value.Exists() && !data.Rules[i].Id.IsNull() {
			data.Rules[i].Id = types.StringValue(value.String())
		} else {
			data.Rules[i].Id = types.StringNull()
		}
		if value := r.Get("rule.rank"); value.Exists() && !data.Rules[i].Rank.IsNull() {
			data.Rules[i].Rank = types.Int64Value(value.Int())
		} else {
			data.Rules[i].Rank = types.Int64Null()
		}
	}
}

//template:end updateFromBody

//template:begin isNull
func (data *DeviceAdminAuthenticationRuleUpdateRanks) isNull(ctx context.Context, res gjson.Result) bool {
	if len(data.Rules) > 0 {
		return false
	}
	return true
}

//template:end isNull
