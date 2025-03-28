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
type DownloadableACL struct {
	Id          types.String `tfsdk:"id"`
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
	Dacl        types.String `tfsdk:"dacl"`
	DaclType    types.String `tfsdk:"dacl_type"`
}

//template:end types

//template:begin getPath
func (data DownloadableACL) getPath() string {
	return "/ers/config/downloadableacl"
}

//template:end getPath

//template:begin getPathDelete

//template:end getPathDelete

//template:begin toBody
func (data DownloadableACL) toBody(ctx context.Context, state DownloadableACL) string {
	body := ""
	if !data.Name.IsNull() {
		body, _ = sjson.Set(body, "DownloadableAcl.name", data.Name.ValueString())
	}
	if !data.Description.IsNull() {
		body, _ = sjson.Set(body, "DownloadableAcl.description", data.Description.ValueString())
	}
	if !data.Dacl.IsNull() {
		body, _ = sjson.Set(body, "DownloadableAcl.dacl", data.Dacl.ValueString())
	}
	if !data.DaclType.IsNull() {
		body, _ = sjson.Set(body, "DownloadableAcl.daclType", data.DaclType.ValueString())
	}
	return body
}

//template:end toBody

//template:begin fromBody
func (data *DownloadableACL) fromBody(ctx context.Context, res gjson.Result) {
	if value := res.Get("DownloadableAcl.name"); value.Exists() && value.Type != gjson.Null {
		data.Name = types.StringValue(value.String())
	} else {
		data.Name = types.StringNull()
	}
	if value := res.Get("DownloadableAcl.description"); value.Exists() && value.Type != gjson.Null {
		data.Description = types.StringValue(value.String())
	} else {
		data.Description = types.StringNull()
	}
	if value := res.Get("DownloadableAcl.dacl"); value.Exists() && value.Type != gjson.Null {
		data.Dacl = types.StringValue(value.String())
	} else {
		data.Dacl = types.StringNull()
	}
	if value := res.Get("DownloadableAcl.daclType"); value.Exists() && value.Type != gjson.Null {
		data.DaclType = types.StringValue(value.String())
	} else {
		data.DaclType = types.StringValue("IPV4")
	}
}

//template:end fromBody

//template:begin updateFromBody
func (data *DownloadableACL) updateFromBody(ctx context.Context, res gjson.Result) {
	if value := res.Get("DownloadableAcl.name"); value.Exists() && !data.Name.IsNull() {
		data.Name = types.StringValue(value.String())
	} else {
		data.Name = types.StringNull()
	}
	if value := res.Get("DownloadableAcl.description"); value.Exists() && !data.Description.IsNull() {
		data.Description = types.StringValue(value.String())
	} else {
		data.Description = types.StringNull()
	}
	if value := res.Get("DownloadableAcl.dacl"); value.Exists() && !data.Dacl.IsNull() {
		data.Dacl = types.StringValue(value.String())
	} else {
		data.Dacl = types.StringNull()
	}
	if value := res.Get("DownloadableAcl.daclType"); value.Exists() && !data.DaclType.IsNull() {
		data.DaclType = types.StringValue(value.String())
	} else if data.DaclType.ValueString() != "IPV4" {
		data.DaclType = types.StringNull()
	}
}

//template:end updateFromBody

//template:begin isNull
func (data *DownloadableACL) isNull(ctx context.Context, res gjson.Result) bool {
	if !data.Name.IsNull() {
		return false
	}
	if !data.Description.IsNull() {
		return false
	}
	if !data.Dacl.IsNull() {
		return false
	}
	if !data.DaclType.IsNull() {
		return false
	}
	return true
}

//template:end isNull
