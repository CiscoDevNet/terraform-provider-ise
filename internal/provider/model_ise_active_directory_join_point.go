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
type ActiveDirectoryJoinPoint struct {
	Id                            types.String                           `tfsdk:"id"`
	Name                          types.String                           `tfsdk:"name"`
	Description                   types.String                           `tfsdk:"description"`
	Domain                        types.String                           `tfsdk:"domain"`
	AdScopesNames                 types.String                           `tfsdk:"ad_scopes_names"`
	EnableDomainAllowedList       types.Bool                             `tfsdk:"enable_domain_allowed_list"`
	Groups                        []ActiveDirectoryJoinPointGroups       `tfsdk:"groups"`
	Attributes                    []ActiveDirectoryJoinPointAttributes   `tfsdk:"attributes"`
	RewriteRules                  []ActiveDirectoryJoinPointRewriteRules `tfsdk:"rewrite_rules"`
	EnableRewrites                types.Bool                             `tfsdk:"enable_rewrites"`
	EnablePassChange              types.Bool                             `tfsdk:"enable_pass_change"`
	EnableMachineAuth             types.Bool                             `tfsdk:"enable_machine_auth"`
	EnableMachineAccess           types.Bool                             `tfsdk:"enable_machine_access"`
	EnableDialinPermissionCheck   types.Bool                             `tfsdk:"enable_dialin_permission_check"`
	PlaintextAuth                 types.Bool                             `tfsdk:"plaintext_auth"`
	AgingTime                     types.Int64                            `tfsdk:"aging_time"`
	EnableCallbackForDialinClient types.Bool                             `tfsdk:"enable_callback_for_dialin_client"`
	IdentityNotInAdBehaviour      types.String                           `tfsdk:"identity_not_in_ad_behaviour"`
	UnreachableDomainsBehaviour   types.String                           `tfsdk:"unreachable_domains_behaviour"`
	Schema                        types.String                           `tfsdk:"schema"`
	FirstName                     types.String                           `tfsdk:"first_name"`
	Department                    types.String                           `tfsdk:"department"`
	LastName                      types.String                           `tfsdk:"last_name"`
	OrganizationalUnit            types.String                           `tfsdk:"organizational_unit"`
	JobTitle                      types.String                           `tfsdk:"job_title"`
	Locality                      types.String                           `tfsdk:"locality"`
	Email                         types.String                           `tfsdk:"email"`
	StateOrProvince               types.String                           `tfsdk:"state_or_province"`
	Telephone                     types.String                           `tfsdk:"telephone"`
	Country                       types.String                           `tfsdk:"country"`
	StreetAddress                 types.String                           `tfsdk:"street_address"`
	EnableFailedAuthProtection    types.Bool                             `tfsdk:"enable_failed_auth_protection"`
	FailedAuthThreshold           types.Int64                            `tfsdk:"failed_auth_threshold"`
	AuthProtectionType            types.String                           `tfsdk:"auth_protection_type"`
}

type ActiveDirectoryJoinPointGroups struct {
	Name types.String `tfsdk:"name"`
	Sid  types.String `tfsdk:"sid"`
	Type types.String `tfsdk:"type"`
}

type ActiveDirectoryJoinPointAttributes struct {
	Name         types.String `tfsdk:"name"`
	Type         types.String `tfsdk:"type"`
	InternalName types.String `tfsdk:"internal_name"`
	DefaultValue types.String `tfsdk:"default_value"`
}

type ActiveDirectoryJoinPointRewriteRules struct {
	RowId         types.String `tfsdk:"row_id"`
	RewriteMatch  types.String `tfsdk:"rewrite_match"`
	RewriteResult types.String `tfsdk:"rewrite_result"`
}

//template:end types

//template:begin getPath
func (data ActiveDirectoryJoinPoint) getPath() string {
	return "/ers/config/activedirectory"
}

//template:end getPath

//template:begin getPathDelete

//template:end getPathDelete

//template:begin toBody
func (data ActiveDirectoryJoinPoint) toBody(ctx context.Context, state ActiveDirectoryJoinPoint) string {
	body := ""
	if !data.Name.IsNull() {
		body, _ = sjson.Set(body, "ERSActiveDirectory.name", data.Name.ValueString())
	}
	if !data.Description.IsNull() {
		body, _ = sjson.Set(body, "ERSActiveDirectory.description", data.Description.ValueString())
	}
	if !data.Domain.IsNull() {
		body, _ = sjson.Set(body, "ERSActiveDirectory.domain", data.Domain.ValueString())
	}
	if !data.AdScopesNames.IsNull() {
		body, _ = sjson.Set(body, "ERSActiveDirectory.adScopesNames", data.AdScopesNames.ValueString())
	}
	if !data.EnableDomainAllowedList.IsNull() {
		body, _ = sjson.Set(body, "ERSActiveDirectory.enableDomainAllowedList", data.EnableDomainAllowedList.ValueBool())
	}
	if len(data.Groups) > 0 {
		body, _ = sjson.Set(body, "ERSActiveDirectory.adgroups.groups", []interface{}{})
		for _, item := range data.Groups {
			itemBody := ""
			if !item.Name.IsNull() {
				itemBody, _ = sjson.Set(itemBody, "name", item.Name.ValueString())
			}
			if !item.Sid.IsNull() {
				itemBody, _ = sjson.Set(itemBody, "sid", item.Sid.ValueString())
			}
			if !item.Type.IsNull() {
				itemBody, _ = sjson.Set(itemBody, "type", item.Type.ValueString())
			}
			body, _ = sjson.SetRaw(body, "ERSActiveDirectory.adgroups.groups.-1", itemBody)
		}
	}
	if len(data.Attributes) > 0 {
		body, _ = sjson.Set(body, "ERSActiveDirectory.adAttributes.attributes", []interface{}{})
		for _, item := range data.Attributes {
			itemBody := ""
			if !item.Name.IsNull() {
				itemBody, _ = sjson.Set(itemBody, "name", item.Name.ValueString())
			}
			if !item.Type.IsNull() {
				itemBody, _ = sjson.Set(itemBody, "type", item.Type.ValueString())
			}
			if !item.InternalName.IsNull() {
				itemBody, _ = sjson.Set(itemBody, "internalName", item.InternalName.ValueString())
			}
			if !item.DefaultValue.IsNull() {
				itemBody, _ = sjson.Set(itemBody, "defaultValue", item.DefaultValue.ValueString())
			}
			body, _ = sjson.SetRaw(body, "ERSActiveDirectory.adAttributes.attributes.-1", itemBody)
		}
	}
	if len(data.RewriteRules) > 0 {
		body, _ = sjson.Set(body, "ERSActiveDirectory.advancedSettings.rewriteRules", []interface{}{})
		for _, item := range data.RewriteRules {
			itemBody := ""
			if !item.RowId.IsNull() {
				itemBody, _ = sjson.Set(itemBody, "rowId", item.RowId.ValueString())
			}
			if !item.RewriteMatch.IsNull() {
				itemBody, _ = sjson.Set(itemBody, "rewriteMatch", item.RewriteMatch.ValueString())
			}
			if !item.RewriteResult.IsNull() {
				itemBody, _ = sjson.Set(itemBody, "rewriteResult", item.RewriteResult.ValueString())
			}
			body, _ = sjson.SetRaw(body, "ERSActiveDirectory.advancedSettings.rewriteRules.-1", itemBody)
		}
	}
	if !data.EnableRewrites.IsNull() {
		body, _ = sjson.Set(body, "ERSActiveDirectory.advancedSettings.enableRewrites", data.EnableRewrites.ValueBool())
	}
	if !data.EnablePassChange.IsNull() {
		body, _ = sjson.Set(body, "ERSActiveDirectory.advancedSettings.enablePassChange", data.EnablePassChange.ValueBool())
	}
	if !data.EnableMachineAuth.IsNull() {
		body, _ = sjson.Set(body, "ERSActiveDirectory.advancedSettings.enableMachineAuth", data.EnableMachineAuth.ValueBool())
	}
	if !data.EnableMachineAccess.IsNull() {
		body, _ = sjson.Set(body, "ERSActiveDirectory.advancedSettings.enableMachineAccess", data.EnableMachineAccess.ValueBool())
	}
	if !data.EnableDialinPermissionCheck.IsNull() {
		body, _ = sjson.Set(body, "ERSActiveDirectory.advancedSettings.enableDialinPermissionCheck", data.EnableDialinPermissionCheck.ValueBool())
	}
	if !data.PlaintextAuth.IsNull() {
		body, _ = sjson.Set(body, "ERSActiveDirectory.advancedSettings.plaintextAuth", data.PlaintextAuth.ValueBool())
	}
	if !data.AgingTime.IsNull() {
		body, _ = sjson.Set(body, "ERSActiveDirectory.advancedSettings.agingTime", data.AgingTime.ValueInt64())
	}
	if !data.EnableCallbackForDialinClient.IsNull() {
		body, _ = sjson.Set(body, "ERSActiveDirectory.advancedSettings.enableCallbackForDialinClient", data.EnableCallbackForDialinClient.ValueBool())
	}
	if !data.IdentityNotInAdBehaviour.IsNull() {
		body, _ = sjson.Set(body, "ERSActiveDirectory.advancedSettings.identityNotInAdBehaviour", data.IdentityNotInAdBehaviour.ValueString())
	}
	if !data.UnreachableDomainsBehaviour.IsNull() {
		body, _ = sjson.Set(body, "ERSActiveDirectory.advancedSettings.unreachableDomainsBehaviour", data.UnreachableDomainsBehaviour.ValueString())
	}
	if !data.Schema.IsNull() {
		body, _ = sjson.Set(body, "ERSActiveDirectory.advancedSettings.schema", data.Schema.ValueString())
	}
	if !data.FirstName.IsNull() {
		body, _ = sjson.Set(body, "ERSActiveDirectory.advancedSettings.firstName", data.FirstName.ValueString())
	}
	if !data.Department.IsNull() {
		body, _ = sjson.Set(body, "ERSActiveDirectory.advancedSettings.department", data.Department.ValueString())
	}
	if !data.LastName.IsNull() {
		body, _ = sjson.Set(body, "ERSActiveDirectory.advancedSettings.lastName", data.LastName.ValueString())
	}
	if !data.OrganizationalUnit.IsNull() {
		body, _ = sjson.Set(body, "ERSActiveDirectory.advancedSettings.organizationalUnit", data.OrganizationalUnit.ValueString())
	}
	if !data.JobTitle.IsNull() {
		body, _ = sjson.Set(body, "ERSActiveDirectory.advancedSettings.jobTitle", data.JobTitle.ValueString())
	}
	if !data.Locality.IsNull() {
		body, _ = sjson.Set(body, "ERSActiveDirectory.advancedSettings.locality", data.Locality.ValueString())
	}
	if !data.Email.IsNull() {
		body, _ = sjson.Set(body, "ERSActiveDirectory.advancedSettings.email", data.Email.ValueString())
	}
	if !data.StateOrProvince.IsNull() {
		body, _ = sjson.Set(body, "ERSActiveDirectory.advancedSettings.stateOrProvince", data.StateOrProvince.ValueString())
	}
	if !data.Telephone.IsNull() {
		body, _ = sjson.Set(body, "ERSActiveDirectory.advancedSettings.telephone", data.Telephone.ValueString())
	}
	if !data.Country.IsNull() {
		body, _ = sjson.Set(body, "ERSActiveDirectory.advancedSettings.country", data.Country.ValueString())
	}
	if !data.StreetAddress.IsNull() {
		body, _ = sjson.Set(body, "ERSActiveDirectory.advancedSettings.streetAddress", data.StreetAddress.ValueString())
	}
	if !data.EnableFailedAuthProtection.IsNull() {
		body, _ = sjson.Set(body, "ERSActiveDirectory.advancedSettings.enableFailedAuthProtection", data.EnableFailedAuthProtection.ValueBool())
	}
	if !data.FailedAuthThreshold.IsNull() {
		body, _ = sjson.Set(body, "ERSActiveDirectory.advancedSettings.failedAuthThreshold", data.FailedAuthThreshold.ValueInt64())
	}
	if !data.AuthProtectionType.IsNull() {
		body, _ = sjson.Set(body, "ERSActiveDirectory.advancedSettings.authProtectionType", data.AuthProtectionType.ValueString())
	}
	return body
}

//template:end toBody

//template:begin fromBody
func (data *ActiveDirectoryJoinPoint) fromBody(ctx context.Context, res gjson.Result) {
	if value := res.Get("ERSActiveDirectory.name"); value.Exists() && value.Type != gjson.Null {
		data.Name = types.StringValue(value.String())
	} else {
		data.Name = types.StringNull()
	}
	if value := res.Get("ERSActiveDirectory.description"); value.Exists() && value.Type != gjson.Null {
		data.Description = types.StringValue(value.String())
	} else {
		data.Description = types.StringNull()
	}
	if value := res.Get("ERSActiveDirectory.domain"); value.Exists() && value.Type != gjson.Null {
		data.Domain = types.StringValue(value.String())
	} else {
		data.Domain = types.StringNull()
	}
	if value := res.Get("ERSActiveDirectory.adScopesNames"); value.Exists() && value.Type != gjson.Null {
		data.AdScopesNames = types.StringValue(value.String())
	} else {
		data.AdScopesNames = types.StringValue("Default_Scope")
	}
	if value := res.Get("ERSActiveDirectory.enableDomainAllowedList"); value.Exists() && value.Type != gjson.Null {
		data.EnableDomainAllowedList = types.BoolValue(value.Bool())
	} else {
		data.EnableDomainAllowedList = types.BoolValue(true)
	}
	if value := res.Get("ERSActiveDirectory.adgroups.groups"); value.Exists() {
		data.Groups = make([]ActiveDirectoryJoinPointGroups, 0)
		value.ForEach(func(k, v gjson.Result) bool {
			item := ActiveDirectoryJoinPointGroups{}
			if cValue := v.Get("name"); cValue.Exists() && cValue.Type != gjson.Null {
				item.Name = types.StringValue(cValue.String())
			} else {
				item.Name = types.StringNull()
			}
			if cValue := v.Get("sid"); cValue.Exists() && cValue.Type != gjson.Null {
				item.Sid = types.StringValue(cValue.String())
			} else {
				item.Sid = types.StringNull()
			}
			data.Groups = append(data.Groups, item)
			return true
		})
	}
	if value := res.Get("ERSActiveDirectory.adAttributes.attributes"); value.Exists() {
		data.Attributes = make([]ActiveDirectoryJoinPointAttributes, 0)
		value.ForEach(func(k, v gjson.Result) bool {
			item := ActiveDirectoryJoinPointAttributes{}
			if cValue := v.Get("name"); cValue.Exists() && cValue.Type != gjson.Null {
				item.Name = types.StringValue(cValue.String())
			} else {
				item.Name = types.StringNull()
			}
			if cValue := v.Get("type"); cValue.Exists() && cValue.Type != gjson.Null {
				item.Type = types.StringValue(cValue.String())
			} else {
				item.Type = types.StringNull()
			}
			if cValue := v.Get("internalName"); cValue.Exists() && cValue.Type != gjson.Null {
				item.InternalName = types.StringValue(cValue.String())
			} else {
				item.InternalName = types.StringNull()
			}
			if cValue := v.Get("defaultValue"); cValue.Exists() && cValue.Type != gjson.Null {
				item.DefaultValue = types.StringValue(cValue.String())
			} else {
				item.DefaultValue = types.StringNull()
			}
			data.Attributes = append(data.Attributes, item)
			return true
		})
	}
	if value := res.Get("ERSActiveDirectory.advancedSettings.rewriteRules"); value.Exists() {
		data.RewriteRules = make([]ActiveDirectoryJoinPointRewriteRules, 0)
		value.ForEach(func(k, v gjson.Result) bool {
			item := ActiveDirectoryJoinPointRewriteRules{}
			if cValue := v.Get("rowId"); cValue.Exists() && cValue.Type != gjson.Null {
				item.RowId = types.StringValue(cValue.String())
			} else {
				item.RowId = types.StringNull()
			}
			if cValue := v.Get("rewriteMatch"); cValue.Exists() && cValue.Type != gjson.Null {
				item.RewriteMatch = types.StringValue(cValue.String())
			} else {
				item.RewriteMatch = types.StringNull()
			}
			if cValue := v.Get("rewriteResult"); cValue.Exists() && cValue.Type != gjson.Null {
				item.RewriteResult = types.StringValue(cValue.String())
			} else {
				item.RewriteResult = types.StringNull()
			}
			data.RewriteRules = append(data.RewriteRules, item)
			return true
		})
	}
	if value := res.Get("ERSActiveDirectory.advancedSettings.enableRewrites"); value.Exists() && value.Type != gjson.Null {
		data.EnableRewrites = types.BoolValue(value.Bool())
	} else {
		data.EnableRewrites = types.BoolValue(false)
	}
	if value := res.Get("ERSActiveDirectory.advancedSettings.enablePassChange"); value.Exists() && value.Type != gjson.Null {
		data.EnablePassChange = types.BoolValue(value.Bool())
	} else {
		data.EnablePassChange = types.BoolValue(true)
	}
	if value := res.Get("ERSActiveDirectory.advancedSettings.enableMachineAuth"); value.Exists() && value.Type != gjson.Null {
		data.EnableMachineAuth = types.BoolValue(value.Bool())
	} else {
		data.EnableMachineAuth = types.BoolValue(true)
	}
	if value := res.Get("ERSActiveDirectory.advancedSettings.enableMachineAccess"); value.Exists() && value.Type != gjson.Null {
		data.EnableMachineAccess = types.BoolValue(value.Bool())
	} else {
		data.EnableMachineAccess = types.BoolValue(true)
	}
	if value := res.Get("ERSActiveDirectory.advancedSettings.enableDialinPermissionCheck"); value.Exists() && value.Type != gjson.Null {
		data.EnableDialinPermissionCheck = types.BoolValue(value.Bool())
	} else {
		data.EnableDialinPermissionCheck = types.BoolValue(false)
	}
	if value := res.Get("ERSActiveDirectory.advancedSettings.plaintextAuth"); value.Exists() && value.Type != gjson.Null {
		data.PlaintextAuth = types.BoolValue(value.Bool())
	} else {
		data.PlaintextAuth = types.BoolValue(false)
	}
	if value := res.Get("ERSActiveDirectory.advancedSettings.agingTime"); value.Exists() && value.Type != gjson.Null {
		data.AgingTime = types.Int64Value(value.Int())
	} else {
		data.AgingTime = types.Int64Value(5)
	}
	if value := res.Get("ERSActiveDirectory.advancedSettings.enableCallbackForDialinClient"); value.Exists() && value.Type != gjson.Null {
		data.EnableCallbackForDialinClient = types.BoolValue(value.Bool())
	} else {
		data.EnableCallbackForDialinClient = types.BoolValue(false)
	}
	if value := res.Get("ERSActiveDirectory.advancedSettings.identityNotInAdBehaviour"); value.Exists() && value.Type != gjson.Null {
		data.IdentityNotInAdBehaviour = types.StringValue(value.String())
	} else {
		data.IdentityNotInAdBehaviour = types.StringNull()
	}
	if value := res.Get("ERSActiveDirectory.advancedSettings.unreachableDomainsBehaviour"); value.Exists() && value.Type != gjson.Null {
		data.UnreachableDomainsBehaviour = types.StringValue(value.String())
	} else {
		data.UnreachableDomainsBehaviour = types.StringNull()
	}
	if value := res.Get("ERSActiveDirectory.advancedSettings.schema"); value.Exists() && value.Type != gjson.Null {
		data.Schema = types.StringValue(value.String())
	} else {
		data.Schema = types.StringNull()
	}
	if value := res.Get("ERSActiveDirectory.advancedSettings.firstName"); value.Exists() && value.Type != gjson.Null {
		data.FirstName = types.StringValue(value.String())
	} else {
		data.FirstName = types.StringNull()
	}
	if value := res.Get("ERSActiveDirectory.advancedSettings.department"); value.Exists() && value.Type != gjson.Null {
		data.Department = types.StringValue(value.String())
	} else {
		data.Department = types.StringNull()
	}
	if value := res.Get("ERSActiveDirectory.advancedSettings.lastName"); value.Exists() && value.Type != gjson.Null {
		data.LastName = types.StringValue(value.String())
	} else {
		data.LastName = types.StringNull()
	}
	if value := res.Get("ERSActiveDirectory.advancedSettings.organizationalUnit"); value.Exists() && value.Type != gjson.Null {
		data.OrganizationalUnit = types.StringValue(value.String())
	} else {
		data.OrganizationalUnit = types.StringNull()
	}
	if value := res.Get("ERSActiveDirectory.advancedSettings.jobTitle"); value.Exists() && value.Type != gjson.Null {
		data.JobTitle = types.StringValue(value.String())
	} else {
		data.JobTitle = types.StringNull()
	}
	if value := res.Get("ERSActiveDirectory.advancedSettings.locality"); value.Exists() && value.Type != gjson.Null {
		data.Locality = types.StringValue(value.String())
	} else {
		data.Locality = types.StringNull()
	}
	if value := res.Get("ERSActiveDirectory.advancedSettings.email"); value.Exists() && value.Type != gjson.Null {
		data.Email = types.StringValue(value.String())
	} else {
		data.Email = types.StringNull()
	}
	if value := res.Get("ERSActiveDirectory.advancedSettings.stateOrProvince"); value.Exists() && value.Type != gjson.Null {
		data.StateOrProvince = types.StringValue(value.String())
	} else {
		data.StateOrProvince = types.StringNull()
	}
	if value := res.Get("ERSActiveDirectory.advancedSettings.telephone"); value.Exists() && value.Type != gjson.Null {
		data.Telephone = types.StringValue(value.String())
	} else {
		data.Telephone = types.StringNull()
	}
	if value := res.Get("ERSActiveDirectory.advancedSettings.country"); value.Exists() && value.Type != gjson.Null {
		data.Country = types.StringValue(value.String())
	} else {
		data.Country = types.StringNull()
	}
	if value := res.Get("ERSActiveDirectory.advancedSettings.streetAddress"); value.Exists() && value.Type != gjson.Null {
		data.StreetAddress = types.StringValue(value.String())
	} else {
		data.StreetAddress = types.StringNull()
	}
	if value := res.Get("ERSActiveDirectory.advancedSettings.enableFailedAuthProtection"); value.Exists() && value.Type != gjson.Null {
		data.EnableFailedAuthProtection = types.BoolValue(value.Bool())
	} else {
		data.EnableFailedAuthProtection = types.BoolValue(false)
	}
	if value := res.Get("ERSActiveDirectory.advancedSettings.failedAuthThreshold"); value.Exists() && value.Type != gjson.Null {
		data.FailedAuthThreshold = types.Int64Value(value.Int())
	} else {
		data.FailedAuthThreshold = types.Int64Value(5)
	}
	if value := res.Get("ERSActiveDirectory.advancedSettings.authProtectionType"); value.Exists() && value.Type != gjson.Null {
		data.AuthProtectionType = types.StringValue(value.String())
	} else {
		data.AuthProtectionType = types.StringNull()
	}
}

//template:end fromBody

//template:begin updateFromBody
func (data *ActiveDirectoryJoinPoint) updateFromBody(ctx context.Context, res gjson.Result) {
	if value := res.Get("ERSActiveDirectory.name"); value.Exists() && !data.Name.IsNull() {
		data.Name = types.StringValue(value.String())
	} else {
		data.Name = types.StringNull()
	}
	if value := res.Get("ERSActiveDirectory.description"); value.Exists() && !data.Description.IsNull() {
		data.Description = types.StringValue(value.String())
	} else {
		data.Description = types.StringNull()
	}
	if value := res.Get("ERSActiveDirectory.domain"); value.Exists() && !data.Domain.IsNull() {
		data.Domain = types.StringValue(value.String())
	} else {
		data.Domain = types.StringNull()
	}
	if value := res.Get("ERSActiveDirectory.adScopesNames"); value.Exists() && !data.AdScopesNames.IsNull() {
		data.AdScopesNames = types.StringValue(value.String())
	} else if data.AdScopesNames.ValueString() != "Default_Scope" {
		data.AdScopesNames = types.StringNull()
	}
	if value := res.Get("ERSActiveDirectory.enableDomainAllowedList"); value.Exists() && !data.EnableDomainAllowedList.IsNull() {
		data.EnableDomainAllowedList = types.BoolValue(value.Bool())
	} else if data.EnableDomainAllowedList.ValueBool() != true {
		data.EnableDomainAllowedList = types.BoolNull()
	}
	for i := range data.Groups {
		keys := [...]string{"sid"}
		keyValues := [...]string{data.Groups[i].Sid.ValueString()}

		var r gjson.Result
		res.Get("ERSActiveDirectory.adgroups.groups").ForEach(
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
		if value := r.Get("name"); value.Exists() && !data.Groups[i].Name.IsNull() {
			data.Groups[i].Name = types.StringValue(value.String())
		} else {
			data.Groups[i].Name = types.StringNull()
		}
		if value := r.Get("sid"); value.Exists() && !data.Groups[i].Sid.IsNull() {
			data.Groups[i].Sid = types.StringValue(value.String())
		} else {
			data.Groups[i].Sid = types.StringNull()
		}
	}
	for i := range data.Attributes {
		keys := [...]string{"name", "type", "internalName", "defaultValue"}
		keyValues := [...]string{data.Attributes[i].Name.ValueString(), data.Attributes[i].Type.ValueString(), data.Attributes[i].InternalName.ValueString(), data.Attributes[i].DefaultValue.ValueString()}

		var r gjson.Result
		res.Get("ERSActiveDirectory.adAttributes.attributes").ForEach(
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
		if value := r.Get("name"); value.Exists() && !data.Attributes[i].Name.IsNull() {
			data.Attributes[i].Name = types.StringValue(value.String())
		} else {
			data.Attributes[i].Name = types.StringNull()
		}
		if value := r.Get("type"); value.Exists() && !data.Attributes[i].Type.IsNull() {
			data.Attributes[i].Type = types.StringValue(value.String())
		} else {
			data.Attributes[i].Type = types.StringNull()
		}
		if value := r.Get("internalName"); value.Exists() && !data.Attributes[i].InternalName.IsNull() {
			data.Attributes[i].InternalName = types.StringValue(value.String())
		} else {
			data.Attributes[i].InternalName = types.StringNull()
		}
		if value := r.Get("defaultValue"); value.Exists() && !data.Attributes[i].DefaultValue.IsNull() {
			data.Attributes[i].DefaultValue = types.StringValue(value.String())
		} else {
			data.Attributes[i].DefaultValue = types.StringNull()
		}
	}
	for i := range data.RewriteRules {
		keys := [...]string{"rowId", "rewriteMatch", "rewriteResult"}
		keyValues := [...]string{data.RewriteRules[i].RowId.ValueString(), data.RewriteRules[i].RewriteMatch.ValueString(), data.RewriteRules[i].RewriteResult.ValueString()}

		var r gjson.Result
		res.Get("ERSActiveDirectory.advancedSettings.rewriteRules").ForEach(
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
		if value := r.Get("rowId"); value.Exists() && !data.RewriteRules[i].RowId.IsNull() {
			data.RewriteRules[i].RowId = types.StringValue(value.String())
		} else {
			data.RewriteRules[i].RowId = types.StringNull()
		}
		if value := r.Get("rewriteMatch"); value.Exists() && !data.RewriteRules[i].RewriteMatch.IsNull() {
			data.RewriteRules[i].RewriteMatch = types.StringValue(value.String())
		} else {
			data.RewriteRules[i].RewriteMatch = types.StringNull()
		}
		if value := r.Get("rewriteResult"); value.Exists() && !data.RewriteRules[i].RewriteResult.IsNull() {
			data.RewriteRules[i].RewriteResult = types.StringValue(value.String())
		} else {
			data.RewriteRules[i].RewriteResult = types.StringNull()
		}
	}
	if value := res.Get("ERSActiveDirectory.advancedSettings.enableRewrites"); value.Exists() && !data.EnableRewrites.IsNull() {
		data.EnableRewrites = types.BoolValue(value.Bool())
	} else if data.EnableRewrites.ValueBool() != false {
		data.EnableRewrites = types.BoolNull()
	}
	if value := res.Get("ERSActiveDirectory.advancedSettings.enablePassChange"); value.Exists() && !data.EnablePassChange.IsNull() {
		data.EnablePassChange = types.BoolValue(value.Bool())
	} else if data.EnablePassChange.ValueBool() != true {
		data.EnablePassChange = types.BoolNull()
	}
	if value := res.Get("ERSActiveDirectory.advancedSettings.enableMachineAuth"); value.Exists() && !data.EnableMachineAuth.IsNull() {
		data.EnableMachineAuth = types.BoolValue(value.Bool())
	} else if data.EnableMachineAuth.ValueBool() != true {
		data.EnableMachineAuth = types.BoolNull()
	}
	if value := res.Get("ERSActiveDirectory.advancedSettings.enableMachineAccess"); value.Exists() && !data.EnableMachineAccess.IsNull() {
		data.EnableMachineAccess = types.BoolValue(value.Bool())
	} else if data.EnableMachineAccess.ValueBool() != true {
		data.EnableMachineAccess = types.BoolNull()
	}
	if value := res.Get("ERSActiveDirectory.advancedSettings.enableDialinPermissionCheck"); value.Exists() && !data.EnableDialinPermissionCheck.IsNull() {
		data.EnableDialinPermissionCheck = types.BoolValue(value.Bool())
	} else if data.EnableDialinPermissionCheck.ValueBool() != false {
		data.EnableDialinPermissionCheck = types.BoolNull()
	}
	if value := res.Get("ERSActiveDirectory.advancedSettings.plaintextAuth"); value.Exists() && !data.PlaintextAuth.IsNull() {
		data.PlaintextAuth = types.BoolValue(value.Bool())
	} else if data.PlaintextAuth.ValueBool() != false {
		data.PlaintextAuth = types.BoolNull()
	}
	if value := res.Get("ERSActiveDirectory.advancedSettings.agingTime"); value.Exists() && !data.AgingTime.IsNull() {
		data.AgingTime = types.Int64Value(value.Int())
	} else if data.AgingTime.ValueInt64() != 5 {
		data.AgingTime = types.Int64Null()
	}
	if value := res.Get("ERSActiveDirectory.advancedSettings.enableCallbackForDialinClient"); value.Exists() && !data.EnableCallbackForDialinClient.IsNull() {
		data.EnableCallbackForDialinClient = types.BoolValue(value.Bool())
	} else if data.EnableCallbackForDialinClient.ValueBool() != false {
		data.EnableCallbackForDialinClient = types.BoolNull()
	}
	if value := res.Get("ERSActiveDirectory.advancedSettings.identityNotInAdBehaviour"); value.Exists() && !data.IdentityNotInAdBehaviour.IsNull() {
		data.IdentityNotInAdBehaviour = types.StringValue(value.String())
	} else {
		data.IdentityNotInAdBehaviour = types.StringNull()
	}
	if value := res.Get("ERSActiveDirectory.advancedSettings.unreachableDomainsBehaviour"); value.Exists() && !data.UnreachableDomainsBehaviour.IsNull() {
		data.UnreachableDomainsBehaviour = types.StringValue(value.String())
	} else {
		data.UnreachableDomainsBehaviour = types.StringNull()
	}
	if value := res.Get("ERSActiveDirectory.advancedSettings.schema"); value.Exists() && !data.Schema.IsNull() {
		data.Schema = types.StringValue(value.String())
	} else {
		data.Schema = types.StringNull()
	}
	if value := res.Get("ERSActiveDirectory.advancedSettings.firstName"); value.Exists() && !data.FirstName.IsNull() {
		data.FirstName = types.StringValue(value.String())
	} else {
		data.FirstName = types.StringNull()
	}
	if value := res.Get("ERSActiveDirectory.advancedSettings.department"); value.Exists() && !data.Department.IsNull() {
		data.Department = types.StringValue(value.String())
	} else {
		data.Department = types.StringNull()
	}
	if value := res.Get("ERSActiveDirectory.advancedSettings.lastName"); value.Exists() && !data.LastName.IsNull() {
		data.LastName = types.StringValue(value.String())
	} else {
		data.LastName = types.StringNull()
	}
	if value := res.Get("ERSActiveDirectory.advancedSettings.organizationalUnit"); value.Exists() && !data.OrganizationalUnit.IsNull() {
		data.OrganizationalUnit = types.StringValue(value.String())
	} else {
		data.OrganizationalUnit = types.StringNull()
	}
	if value := res.Get("ERSActiveDirectory.advancedSettings.jobTitle"); value.Exists() && !data.JobTitle.IsNull() {
		data.JobTitle = types.StringValue(value.String())
	} else {
		data.JobTitle = types.StringNull()
	}
	if value := res.Get("ERSActiveDirectory.advancedSettings.locality"); value.Exists() && !data.Locality.IsNull() {
		data.Locality = types.StringValue(value.String())
	} else {
		data.Locality = types.StringNull()
	}
	if value := res.Get("ERSActiveDirectory.advancedSettings.email"); value.Exists() && !data.Email.IsNull() {
		data.Email = types.StringValue(value.String())
	} else {
		data.Email = types.StringNull()
	}
	if value := res.Get("ERSActiveDirectory.advancedSettings.stateOrProvince"); value.Exists() && !data.StateOrProvince.IsNull() {
		data.StateOrProvince = types.StringValue(value.String())
	} else {
		data.StateOrProvince = types.StringNull()
	}
	if value := res.Get("ERSActiveDirectory.advancedSettings.telephone"); value.Exists() && !data.Telephone.IsNull() {
		data.Telephone = types.StringValue(value.String())
	} else {
		data.Telephone = types.StringNull()
	}
	if value := res.Get("ERSActiveDirectory.advancedSettings.country"); value.Exists() && !data.Country.IsNull() {
		data.Country = types.StringValue(value.String())
	} else {
		data.Country = types.StringNull()
	}
	if value := res.Get("ERSActiveDirectory.advancedSettings.streetAddress"); value.Exists() && !data.StreetAddress.IsNull() {
		data.StreetAddress = types.StringValue(value.String())
	} else {
		data.StreetAddress = types.StringNull()
	}
	if value := res.Get("ERSActiveDirectory.advancedSettings.enableFailedAuthProtection"); value.Exists() && !data.EnableFailedAuthProtection.IsNull() {
		data.EnableFailedAuthProtection = types.BoolValue(value.Bool())
	} else if data.EnableFailedAuthProtection.ValueBool() != false {
		data.EnableFailedAuthProtection = types.BoolNull()
	}
	if value := res.Get("ERSActiveDirectory.advancedSettings.failedAuthThreshold"); value.Exists() && !data.FailedAuthThreshold.IsNull() {
		data.FailedAuthThreshold = types.Int64Value(value.Int())
	} else if data.FailedAuthThreshold.ValueInt64() != 5 {
		data.FailedAuthThreshold = types.Int64Null()
	}
	if value := res.Get("ERSActiveDirectory.advancedSettings.authProtectionType"); value.Exists() && !data.AuthProtectionType.IsNull() {
		data.AuthProtectionType = types.StringValue(value.String())
	} else {
		data.AuthProtectionType = types.StringNull()
	}
}

//template:end updateFromBody

//template:begin isNull
func (data *ActiveDirectoryJoinPoint) isNull(ctx context.Context, res gjson.Result) bool {
	if !data.Name.IsNull() {
		return false
	}
	if !data.Description.IsNull() {
		return false
	}
	if !data.Domain.IsNull() {
		return false
	}
	if !data.AdScopesNames.IsNull() {
		return false
	}
	if !data.EnableDomainAllowedList.IsNull() {
		return false
	}
	if len(data.Groups) > 0 {
		return false
	}
	if len(data.Attributes) > 0 {
		return false
	}
	if len(data.RewriteRules) > 0 {
		return false
	}
	if !data.EnableRewrites.IsNull() {
		return false
	}
	if !data.EnablePassChange.IsNull() {
		return false
	}
	if !data.EnableMachineAuth.IsNull() {
		return false
	}
	if !data.EnableMachineAccess.IsNull() {
		return false
	}
	if !data.EnableDialinPermissionCheck.IsNull() {
		return false
	}
	if !data.PlaintextAuth.IsNull() {
		return false
	}
	if !data.AgingTime.IsNull() {
		return false
	}
	if !data.EnableCallbackForDialinClient.IsNull() {
		return false
	}
	if !data.IdentityNotInAdBehaviour.IsNull() {
		return false
	}
	if !data.UnreachableDomainsBehaviour.IsNull() {
		return false
	}
	if !data.Schema.IsNull() {
		return false
	}
	if !data.FirstName.IsNull() {
		return false
	}
	if !data.Department.IsNull() {
		return false
	}
	if !data.LastName.IsNull() {
		return false
	}
	if !data.OrganizationalUnit.IsNull() {
		return false
	}
	if !data.JobTitle.IsNull() {
		return false
	}
	if !data.Locality.IsNull() {
		return false
	}
	if !data.Email.IsNull() {
		return false
	}
	if !data.StateOrProvince.IsNull() {
		return false
	}
	if !data.Telephone.IsNull() {
		return false
	}
	if !data.Country.IsNull() {
		return false
	}
	if !data.StreetAddress.IsNull() {
		return false
	}
	if !data.EnableFailedAuthProtection.IsNull() {
		return false
	}
	if !data.FailedAuthThreshold.IsNull() {
		return false
	}
	if !data.AuthProtectionType.IsNull() {
		return false
	}
	return true
}

//template:end isNull
