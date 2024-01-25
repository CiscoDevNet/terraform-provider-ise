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

	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

//template:end imports

//template:begin types
type TACACSProfile struct {
	Id                types.String                     `tfsdk:"id"`
	Name              types.String                     `tfsdk:"name"`
	Description       types.String                     `tfsdk:"description"`
	SessionAttributes []TACACSProfileSessionAttributes `tfsdk:"session_attributes"`
}

type TACACSProfileSessionAttributes struct {
	Type  types.String `tfsdk:"type"`
	Name  types.String `tfsdk:"name"`
	Value types.String `tfsdk:"value"`
}

//template:end types

//template:begin getPath
func (data TACACSProfile) getPath() string {
	return "/ers/config/tacacsprofile"
}

//template:end getPath

//template:begin getPathPut

//template:end getPathPut

//template:begin toBody
func (data TACACSProfile) toBody(ctx context.Context, state TACACSProfile) string {
	body := ""
	if !data.Name.IsNull() {
		body, _ = sjson.Set(body, "TacacsProfile.name", data.Name.ValueString())
	}
	if !data.Description.IsNull() {
		body, _ = sjson.Set(body, "TacacsProfile.description", data.Description.ValueString())
	}
	if len(data.SessionAttributes) > 0 {
		body, _ = sjson.Set(body, "TacacsProfile.sessionAttributes.sessionAttributeList", []interface{}{})
		for _, item := range data.SessionAttributes {
			itemBody := ""
			if !item.Type.IsNull() {
				itemBody, _ = sjson.Set(itemBody, "type", item.Type.ValueString())
			}
			if !item.Name.IsNull() {
				itemBody, _ = sjson.Set(itemBody, "name", item.Name.ValueString())
			}
			if !item.Value.IsNull() {
				itemBody, _ = sjson.Set(itemBody, "value", item.Value.ValueString())
			}
			body, _ = sjson.SetRaw(body, "TacacsProfile.sessionAttributes.sessionAttributeList.-1", itemBody)
		}
	}
	return body
}

//template:end toBody

//template:begin fromBody
func (data *TACACSProfile) fromBody(ctx context.Context, res gjson.Result) {
	if value := res.Get("TacacsProfile.name"); value.Exists() {
		data.Name = types.StringValue(value.String())
	} else {
		data.Name = types.StringNull()
	}
	if value := res.Get("TacacsProfile.description"); value.Exists() {
		data.Description = types.StringValue(value.String())
	} else {
		data.Description = types.StringNull()
	}
	if value := res.Get("TacacsProfile.sessionAttributes.sessionAttributeList"); value.Exists() {
		data.SessionAttributes = make([]TACACSProfileSessionAttributes, 0)
		value.ForEach(func(k, v gjson.Result) bool {
			item := TACACSProfileSessionAttributes{}
			if cValue := v.Get("type"); cValue.Exists() {
				item.Type = types.StringValue(cValue.String())
			} else {
				item.Type = types.StringNull()
			}
			if cValue := v.Get("name"); cValue.Exists() {
				item.Name = types.StringValue(cValue.String())
			} else {
				item.Name = types.StringNull()
			}
			if cValue := v.Get("value"); cValue.Exists() {
				item.Value = types.StringValue(cValue.String())
			} else {
				item.Value = types.StringNull()
			}
			data.SessionAttributes = append(data.SessionAttributes, item)
			return true
		})
	}
}

//template:end fromBody

//template:begin updateFromBody
func (data *TACACSProfile) updateFromBody(ctx context.Context, res gjson.Result) {
	if value := res.Get("TacacsProfile.name"); value.Exists() && !data.Name.IsNull() {
		data.Name = types.StringValue(value.String())
	} else {
		data.Name = types.StringNull()
	}
	if value := res.Get("TacacsProfile.description"); value.Exists() && !data.Description.IsNull() {
		data.Description = types.StringValue(value.String())
	} else {
		data.Description = types.StringNull()
	}
	for i := range data.SessionAttributes {
		keys := [...]string{"type", "name", "value"}
		keyValues := [...]string{data.SessionAttributes[i].Type.ValueString(), data.SessionAttributes[i].Name.ValueString(), data.SessionAttributes[i].Value.ValueString()}

		var r gjson.Result
		res.Get("TacacsProfile.sessionAttributes.sessionAttributeList").ForEach(
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
		if value := r.Get("type"); value.Exists() && !data.SessionAttributes[i].Type.IsNull() {
			data.SessionAttributes[i].Type = types.StringValue(value.String())
		} else {
			data.SessionAttributes[i].Type = types.StringNull()
		}
		if value := r.Get("name"); value.Exists() && !data.SessionAttributes[i].Name.IsNull() {
			data.SessionAttributes[i].Name = types.StringValue(value.String())
		} else {
			data.SessionAttributes[i].Name = types.StringNull()
		}
		if value := r.Get("value"); value.Exists() && !data.SessionAttributes[i].Value.IsNull() {
			data.SessionAttributes[i].Value = types.StringValue(value.String())
		} else {
			data.SessionAttributes[i].Value = types.StringNull()
		}
	}
}

//template:end updateFromBody

//template:begin isNull
func (data *TACACSProfile) isNull(ctx context.Context, res gjson.Result) bool {
	if !data.Name.IsNull() {
		return false
	}
	if !data.Description.IsNull() {
		return false
	}
	if len(data.SessionAttributes) > 0 {
		return false
	}
	return true
}

//template:end isNull
