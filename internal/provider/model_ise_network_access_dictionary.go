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
type NetworkAccessDictionary struct {
	Id                 types.String `tfsdk:"id"`
	Name               types.String `tfsdk:"name"`
	Description        types.String `tfsdk:"description"`
	Version            types.String `tfsdk:"version"`
	DictionaryAttrType types.String `tfsdk:"dictionary_attr_type"`
}

//template:end types

//template:begin getPath
func (data NetworkAccessDictionary) getPath() string {
	return "/api/v1/policy/network-access/dictionaries"
}

//template:end getPath

//template:begin getPathDelete

//template:end getPathDelete

//template:begin toBody
func (data NetworkAccessDictionary) toBody(ctx context.Context, state NetworkAccessDictionary) string {
	body := ""
	if !data.Name.IsNull() {
		body, _ = sjson.Set(body, "name", data.Name.ValueString())
	}
	if !data.Description.IsNull() {
		body, _ = sjson.Set(body, "description", data.Description.ValueString())
	}
	if !data.Version.IsNull() {
		body, _ = sjson.Set(body, "version", data.Version.ValueString())
	}
	if !data.DictionaryAttrType.IsNull() {
		body, _ = sjson.Set(body, "dictionaryAttrType", data.DictionaryAttrType.ValueString())
	}
	return body
}

//template:end toBody

//template:begin fromBody
func (data *NetworkAccessDictionary) fromBody(ctx context.Context, res gjson.Result) {
	if value := res.Get("response.name"); value.Exists() && value.Type != gjson.Null {
		data.Name = types.StringValue(value.String())
	} else {
		data.Name = types.StringNull()
	}
	if value := res.Get("response.description"); value.Exists() && value.Type != gjson.Null {
		data.Description = types.StringValue(value.String())
	} else {
		data.Description = types.StringNull()
	}
	if value := res.Get("response.version"); value.Exists() && value.Type != gjson.Null {
		data.Version = types.StringValue(value.String())
	} else {
		data.Version = types.StringNull()
	}
	if value := res.Get("response.dictionaryAttrType"); value.Exists() && value.Type != gjson.Null {
		data.DictionaryAttrType = types.StringValue(value.String())
	} else {
		data.DictionaryAttrType = types.StringNull()
	}
}

//template:end fromBody

//template:begin updateFromBody
func (data *NetworkAccessDictionary) updateFromBody(ctx context.Context, res gjson.Result) {
	if value := res.Get("response.name"); value.Exists() && !data.Name.IsNull() {
		data.Name = types.StringValue(value.String())
	} else {
		data.Name = types.StringNull()
	}
	if value := res.Get("response.description"); value.Exists() && !data.Description.IsNull() {
		data.Description = types.StringValue(value.String())
	} else {
		data.Description = types.StringNull()
	}
	if value := res.Get("response.version"); value.Exists() && !data.Version.IsNull() {
		data.Version = types.StringValue(value.String())
	} else {
		data.Version = types.StringNull()
	}
	if value := res.Get("response.dictionaryAttrType"); value.Exists() && !data.DictionaryAttrType.IsNull() {
		data.DictionaryAttrType = types.StringValue(value.String())
	} else {
		data.DictionaryAttrType = types.StringNull()
	}
}

//template:end updateFromBody

//template:begin isNull
func (data *NetworkAccessDictionary) isNull(ctx context.Context, res gjson.Result) bool {
	if !data.Name.IsNull() {
		return false
	}
	if !data.Description.IsNull() {
		return false
	}
	if !data.Version.IsNull() {
		return false
	}
	if !data.DictionaryAttrType.IsNull() {
		return false
	}
	return true
}

//template:end isNull
