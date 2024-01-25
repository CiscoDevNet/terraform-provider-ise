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
type TACACSCommandSet struct {
	Id              types.String               `tfsdk:"id"`
	Name            types.String               `tfsdk:"name"`
	Description     types.String               `tfsdk:"description"`
	PermitUnmatched types.Bool                 `tfsdk:"permit_unmatched"`
	Commands        []TACACSCommandSetCommands `tfsdk:"commands"`
}

type TACACSCommandSetCommands struct {
	Grant     types.String `tfsdk:"grant"`
	Command   types.String `tfsdk:"command"`
	Arguments types.String `tfsdk:"arguments"`
}

//template:end types

//template:begin getPath
func (data TACACSCommandSet) getPath() string {
	return "/ers/config/tacacscommandsets"
}

//template:end getPath

//template:begin toBody
func (data TACACSCommandSet) toBody(ctx context.Context, state TACACSCommandSet) string {
	body := ""
	if !data.Name.IsNull() {
		body, _ = sjson.Set(body, "TacacsCommandSets.name", data.Name.ValueString())
	}
	if !data.Description.IsNull() {
		body, _ = sjson.Set(body, "TacacsCommandSets.description", data.Description.ValueString())
	}
	if !data.PermitUnmatched.IsNull() {
		body, _ = sjson.Set(body, "TacacsCommandSets.permitUnmatched", data.PermitUnmatched.ValueBool())
	}
	if len(data.Commands) > 0 {
		body, _ = sjson.Set(body, "TacacsCommandSets.commands.commandList", []interface{}{})
		for _, item := range data.Commands {
			itemBody := ""
			if !item.Grant.IsNull() {
				itemBody, _ = sjson.Set(itemBody, "grant", item.Grant.ValueString())
			}
			if !item.Command.IsNull() {
				itemBody, _ = sjson.Set(itemBody, "command", item.Command.ValueString())
			}
			if !item.Arguments.IsNull() {
				itemBody, _ = sjson.Set(itemBody, "arguments", item.Arguments.ValueString())
			}
			body, _ = sjson.SetRaw(body, "TacacsCommandSets.commands.commandList.-1", itemBody)
		}
	}
	return body
}

//template:end toBody

//template:begin fromBody
func (data *TACACSCommandSet) fromBody(ctx context.Context, res gjson.Result) {
	if value := res.Get("TacacsCommandSets.name"); value.Exists() {
		data.Name = types.StringValue(value.String())
	} else {
		data.Name = types.StringNull()
	}
	if value := res.Get("TacacsCommandSets.description"); value.Exists() {
		data.Description = types.StringValue(value.String())
	} else {
		data.Description = types.StringNull()
	}
	if value := res.Get("TacacsCommandSets.permitUnmatched"); value.Exists() {
		data.PermitUnmatched = types.BoolValue(value.Bool())
	} else {
		data.PermitUnmatched = types.BoolValue(false)
	}
	if value := res.Get("TacacsCommandSets.commands.commandList"); value.Exists() {
		data.Commands = make([]TACACSCommandSetCommands, 0)
		value.ForEach(func(k, v gjson.Result) bool {
			item := TACACSCommandSetCommands{}
			if cValue := v.Get("grant"); cValue.Exists() {
				item.Grant = types.StringValue(cValue.String())
			} else {
				item.Grant = types.StringNull()
			}
			if cValue := v.Get("command"); cValue.Exists() {
				item.Command = types.StringValue(cValue.String())
			} else {
				item.Command = types.StringNull()
			}
			if cValue := v.Get("arguments"); cValue.Exists() {
				item.Arguments = types.StringValue(cValue.String())
			} else {
				item.Arguments = types.StringNull()
			}
			data.Commands = append(data.Commands, item)
			return true
		})
	}
}

//template:end fromBody

//template:begin updateFromBody
func (data *TACACSCommandSet) updateFromBody(ctx context.Context, res gjson.Result) {
	if value := res.Get("TacacsCommandSets.name"); value.Exists() && !data.Name.IsNull() {
		data.Name = types.StringValue(value.String())
	} else {
		data.Name = types.StringNull()
	}
	if value := res.Get("TacacsCommandSets.description"); value.Exists() && !data.Description.IsNull() {
		data.Description = types.StringValue(value.String())
	} else {
		data.Description = types.StringNull()
	}
	if value := res.Get("TacacsCommandSets.permitUnmatched"); value.Exists() && !data.PermitUnmatched.IsNull() {
		data.PermitUnmatched = types.BoolValue(value.Bool())
	} else if data.PermitUnmatched.ValueBool() != false {
		data.PermitUnmatched = types.BoolNull()
	}
	for i := range data.Commands {
		keys := [...]string{"grant", "command", "arguments"}
		keyValues := [...]string{data.Commands[i].Grant.ValueString(), data.Commands[i].Command.ValueString(), data.Commands[i].Arguments.ValueString()}

		var r gjson.Result
		res.Get("TacacsCommandSets.commands.commandList").ForEach(
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
		if value := r.Get("grant"); value.Exists() && !data.Commands[i].Grant.IsNull() {
			data.Commands[i].Grant = types.StringValue(value.String())
		} else {
			data.Commands[i].Grant = types.StringNull()
		}
		if value := r.Get("command"); value.Exists() && !data.Commands[i].Command.IsNull() {
			data.Commands[i].Command = types.StringValue(value.String())
		} else {
			data.Commands[i].Command = types.StringNull()
		}
		if value := r.Get("arguments"); value.Exists() && !data.Commands[i].Arguments.IsNull() {
			data.Commands[i].Arguments = types.StringValue(value.String())
		} else {
			data.Commands[i].Arguments = types.StringNull()
		}
	}
}

//template:end updateFromBody

//template:begin isNull
func (data *TACACSCommandSet) isNull(ctx context.Context, res gjson.Result) bool {
	if !data.Name.IsNull() {
		return false
	}
	if !data.Description.IsNull() {
		return false
	}
	if !data.PermitUnmatched.IsNull() {
		return false
	}
	if len(data.Commands) > 0 {
		return false
	}
	return true
}

//template:end isNull
