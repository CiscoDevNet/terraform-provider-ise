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
type AllowedProtocolsTACACS struct {
	Id            types.String `tfsdk:"id"`
	Name          types.String `tfsdk:"name"`
	Description   types.String `tfsdk:"description"`
	AllowPapAscii types.Bool   `tfsdk:"allow_pap_ascii"`
	AllowChap     types.Bool   `tfsdk:"allow_chap"`
	AllowMsChapV1 types.Bool   `tfsdk:"allow_ms_chap_v1"`
}

//template:end types

//template:begin getPath
func (data AllowedProtocolsTACACS) getPath() string {
	return "/ers/config/allowedprotocols"
}

//template:end getPath

//template:begin toBody
func (data AllowedProtocolsTACACS) toBody(ctx context.Context, state AllowedProtocolsTACACS) string {
	body := ""
	if !data.Name.IsNull() {
		body, _ = sjson.Set(body, "AllowedProtocols.name", data.Name.ValueString())
	}
	if !data.Description.IsNull() {
		body, _ = sjson.Set(body, "AllowedProtocols.description", data.Description.ValueString())
	}
	body, _ = sjson.Set(body, "AllowedProtocols.processHostLookup", false)
	if !data.AllowPapAscii.IsNull() {
		body, _ = sjson.Set(body, "AllowedProtocols.allowPapAscii", data.AllowPapAscii.ValueBool())
	}
	if !data.AllowChap.IsNull() {
		body, _ = sjson.Set(body, "AllowedProtocols.allowChap", data.AllowChap.ValueBool())
	}
	if !data.AllowMsChapV1.IsNull() {
		body, _ = sjson.Set(body, "AllowedProtocols.allowMsChapV1", data.AllowMsChapV1.ValueBool())
	}
	body, _ = sjson.Set(body, "AllowedProtocols.allowMsChapV2", false)
	body, _ = sjson.Set(body, "AllowedProtocols.allowEapMd5", false)
	body, _ = sjson.Set(body, "AllowedProtocols.allowLeap", false)
	body, _ = sjson.Set(body, "AllowedProtocols.allowEapTls", false)
	body, _ = sjson.Set(body, "AllowedProtocols.allowEapTtls", false)
	body, _ = sjson.Set(body, "AllowedProtocols.allowEapFast", false)
	body, _ = sjson.Set(body, "AllowedProtocols.allowPeap", false)
	body, _ = sjson.Set(body, "AllowedProtocols.allowTeap", false)
	body, _ = sjson.Set(body, "AllowedProtocols.allowPreferredEapProtocol", false)
	body, _ = sjson.Set(body, "AllowedProtocols.eapTlsLBit", false)
	body, _ = sjson.Set(body, "AllowedProtocols.allowWeakCiphersForEap", false)
	body, _ = sjson.Set(body, "AllowedProtocols.requireMessageAuth", false)
	body, _ = sjson.Set(body, "AllowedProtocols.fiveG", false)
	return body
}

//template:end toBody

//template:begin fromBody
func (data *AllowedProtocolsTACACS) fromBody(ctx context.Context, res gjson.Result) {
	if value := res.Get("AllowedProtocols.name"); value.Exists() {
		data.Name = types.StringValue(value.String())
	} else {
		data.Name = types.StringNull()
	}
	if value := res.Get("AllowedProtocols.description"); value.Exists() {
		data.Description = types.StringValue(value.String())
	} else {
		data.Description = types.StringNull()
	}
	if value := res.Get("AllowedProtocols.allowPapAscii"); value.Exists() {
		data.AllowPapAscii = types.BoolValue(value.Bool())
	} else {
		data.AllowPapAscii = types.BoolNull()
	}
	if value := res.Get("AllowedProtocols.allowChap"); value.Exists() {
		data.AllowChap = types.BoolValue(value.Bool())
	} else {
		data.AllowChap = types.BoolNull()
	}
	if value := res.Get("AllowedProtocols.allowMsChapV1"); value.Exists() {
		data.AllowMsChapV1 = types.BoolValue(value.Bool())
	} else {
		data.AllowMsChapV1 = types.BoolNull()
	}
}

//template:end fromBody

//template:begin updateFromBody
func (data *AllowedProtocolsTACACS) updateFromBody(ctx context.Context, res gjson.Result) {
	if value := res.Get("AllowedProtocols.name"); value.Exists() && !data.Name.IsNull() {
		data.Name = types.StringValue(value.String())
	} else {
		data.Name = types.StringNull()
	}
	if value := res.Get("AllowedProtocols.description"); value.Exists() && !data.Description.IsNull() {
		data.Description = types.StringValue(value.String())
	} else {
		data.Description = types.StringNull()
	}
	if value := res.Get("AllowedProtocols.allowPapAscii"); value.Exists() && !data.AllowPapAscii.IsNull() {
		data.AllowPapAscii = types.BoolValue(value.Bool())
	} else {
		data.AllowPapAscii = types.BoolNull()
	}
	if value := res.Get("AllowedProtocols.allowChap"); value.Exists() && !data.AllowChap.IsNull() {
		data.AllowChap = types.BoolValue(value.Bool())
	} else {
		data.AllowChap = types.BoolNull()
	}
	if value := res.Get("AllowedProtocols.allowMsChapV1"); value.Exists() && !data.AllowMsChapV1.IsNull() {
		data.AllowMsChapV1 = types.BoolValue(value.Bool())
	} else {
		data.AllowMsChapV1 = types.BoolNull()
	}
}

//template:end updateFromBody

//template:begin isNull
func (data *AllowedProtocolsTACACS) isNull(ctx context.Context, res gjson.Result) bool {
	if !data.Name.IsNull() {
		return false
	}
	if !data.Description.IsNull() {
		return false
	}
	if !data.AllowPapAscii.IsNull() {
		return false
	}
	if !data.AllowChap.IsNull() {
		return false
	}
	if !data.AllowMsChapV1.IsNull() {
		return false
	}
	return true
}

//template:end isNull
