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
type AuthorizationProfile struct {
	Id                                               types.String                             `tfsdk:"id"`
	Name                                             types.String                             `tfsdk:"name"`
	Description                                      types.String                             `tfsdk:"description"`
	VlanNameId                                       types.String                             `tfsdk:"vlan_name_id"`
	VlanTagId                                        types.Int64                              `tfsdk:"vlan_tag_id"`
	WebRedirectionType                               types.String                             `tfsdk:"web_redirection_type"`
	WebRedirectionAcl                                types.String                             `tfsdk:"web_redirection_acl"`
	WebRedirectionPortalName                         types.String                             `tfsdk:"web_redirection_portal_name"`
	WebRedirectionStaticIpHostNameFqdn               types.String                             `tfsdk:"web_redirection_static_ip_host_name_fqdn"`
	WebRedirectionDisplayCertificatesRenewalMessages types.Bool                               `tfsdk:"web_redirection_display_certificates_renewal_messages"`
	AgentlessPosture                                 types.Bool                               `tfsdk:"agentless_posture"`
	AccessType                                       types.String                             `tfsdk:"access_type"`
	ProfileName                                      types.String                             `tfsdk:"profile_name"`
	AirespaceAcl                                     types.String                             `tfsdk:"airespace_acl"`
	Acl                                              types.String                             `tfsdk:"acl"`
	DaclName                                         types.String                             `tfsdk:"dacl_name"`
	AutoSmartPort                                    types.String                             `tfsdk:"auto_smart_port"`
	InterfaceTemplate                                types.String                             `tfsdk:"interface_template"`
	Ipv6AclFilter                                    types.String                             `tfsdk:"ipv6_acl_filter"`
	AvcProfile                                       types.String                             `tfsdk:"avc_profile"`
	AsaVpn                                           types.String                             `tfsdk:"asa_vpn"`
	UniqueIdentifier                                 types.String                             `tfsdk:"unique_identifier"`
	TrackMovement                                    types.Bool                               `tfsdk:"track_movement"`
	ServiceTemplate                                  types.Bool                               `tfsdk:"service_template"`
	EasywiredSessionCandidate                        types.Bool                               `tfsdk:"easywired_session_candidate"`
	VoiceDomainPermission                            types.Bool                               `tfsdk:"voice_domain_permission"`
	Neat                                             types.Bool                               `tfsdk:"neat"`
	WebAuth                                          types.Bool                               `tfsdk:"web_auth"`
	MacSecPolicy                                     types.String                             `tfsdk:"mac_sec_policy"`
	ReauthenticationConnectivity                     types.String                             `tfsdk:"reauthentication_connectivity"`
	ReauthenticationTimer                            types.Int64                              `tfsdk:"reauthentication_timer"`
	AdvancedAttributes                               []AuthorizationProfileAdvancedAttributes `tfsdk:"advanced_attributes"`
	Ipv6DaclName                                     types.String                             `tfsdk:"ipv6_dacl_name"`
	AirespaceIpv6Acl                                 types.String                             `tfsdk:"airespace_ipv6_acl"`
}

type AuthorizationProfileAdvancedAttributes struct {
	AttributeLeftDictionaryName  types.String `tfsdk:"attribute_left_dictionary_name"`
	AttributeLeftName            types.String `tfsdk:"attribute_left_name"`
	AttributeRightValueType      types.String `tfsdk:"attribute_right_value_type"`
	AttributeRightValue          types.String `tfsdk:"attribute_right_value"`
	AttributeRightDictionaryName types.String `tfsdk:"attribute_right_dictionary_name"`
	AttributeRightName           types.String `tfsdk:"attribute_right_name"`
}

//template:end types

//template:begin getPath
func (data AuthorizationProfile) getPath() string {
	return "/ers/config/authorizationprofile"
}

//template:end getPath

//template:begin getPathDelete

//template:end getPathDelete

//template:begin toBody
func (data AuthorizationProfile) toBody(ctx context.Context, state AuthorizationProfile) string {
	body := ""
	if !data.Name.IsNull() {
		body, _ = sjson.Set(body, "AuthorizationProfile.name", data.Name.ValueString())
	}
	if !data.Description.IsNull() {
		body, _ = sjson.Set(body, "AuthorizationProfile.description", data.Description.ValueString())
	}
	if !data.VlanNameId.IsNull() {
		body, _ = sjson.Set(body, "AuthorizationProfile.vlan.nameID", data.VlanNameId.ValueString())
	}
	if !data.VlanTagId.IsNull() {
		body, _ = sjson.Set(body, "AuthorizationProfile.vlan.tagID", data.VlanTagId.ValueInt64())
	}
	if !data.WebRedirectionType.IsNull() {
		body, _ = sjson.Set(body, "AuthorizationProfile.webRedirection.WebRedirectionType", data.WebRedirectionType.ValueString())
	}
	if !data.WebRedirectionAcl.IsNull() {
		body, _ = sjson.Set(body, "AuthorizationProfile.webRedirection.acl", data.WebRedirectionAcl.ValueString())
	}
	if !data.WebRedirectionPortalName.IsNull() {
		body, _ = sjson.Set(body, "AuthorizationProfile.webRedirection.portalName", data.WebRedirectionPortalName.ValueString())
	}
	if !data.WebRedirectionStaticIpHostNameFqdn.IsNull() {
		body, _ = sjson.Set(body, "AuthorizationProfile.webRedirection.staticIPHostNameFQDN", data.WebRedirectionStaticIpHostNameFqdn.ValueString())
	}
	if !data.WebRedirectionDisplayCertificatesRenewalMessages.IsNull() {
		body, _ = sjson.Set(body, "AuthorizationProfile.webRedirection.displayCertificatesRenewalMessages", data.WebRedirectionDisplayCertificatesRenewalMessages.ValueBool())
	}
	if !data.AgentlessPosture.IsNull() {
		body, _ = sjson.Set(body, "AuthorizationProfile.agentlessPosture", data.AgentlessPosture.ValueBool())
	}
	if !data.AccessType.IsNull() {
		body, _ = sjson.Set(body, "AuthorizationProfile.accessType", data.AccessType.ValueString())
	}
	body, _ = sjson.Set(body, "AuthorizationProfile.authzProfileType", "SWITCH")
	if !data.ProfileName.IsNull() {
		body, _ = sjson.Set(body, "AuthorizationProfile.profileName", data.ProfileName.ValueString())
	}
	if !data.AirespaceAcl.IsNull() {
		body, _ = sjson.Set(body, "AuthorizationProfile.airespaceACL", data.AirespaceAcl.ValueString())
	}
	if !data.Acl.IsNull() {
		body, _ = sjson.Set(body, "AuthorizationProfile.acl", data.Acl.ValueString())
	}
	if !data.DaclName.IsNull() {
		body, _ = sjson.Set(body, "AuthorizationProfile.daclName", data.DaclName.ValueString())
	}
	if !data.AutoSmartPort.IsNull() {
		body, _ = sjson.Set(body, "AuthorizationProfile.autoSmartPort", data.AutoSmartPort.ValueString())
	}
	if !data.InterfaceTemplate.IsNull() {
		body, _ = sjson.Set(body, "AuthorizationProfile.interfaceTemplate", data.InterfaceTemplate.ValueString())
	}
	if !data.Ipv6AclFilter.IsNull() {
		body, _ = sjson.Set(body, "AuthorizationProfile.ipv6ACLFilter", data.Ipv6AclFilter.ValueString())
	}
	if !data.AvcProfile.IsNull() {
		body, _ = sjson.Set(body, "AuthorizationProfile.avcProfile", data.AvcProfile.ValueString())
	}
	if !data.AsaVpn.IsNull() {
		body, _ = sjson.Set(body, "AuthorizationProfile.asaVpn", data.AsaVpn.ValueString())
	}
	if !data.UniqueIdentifier.IsNull() {
		body, _ = sjson.Set(body, "AuthorizationProfile.uniqueIdentifier", data.UniqueIdentifier.ValueString())
	}
	if !data.TrackMovement.IsNull() {
		body, _ = sjson.Set(body, "AuthorizationProfile.trackMovement", data.TrackMovement.ValueBool())
	}
	if !data.ServiceTemplate.IsNull() {
		body, _ = sjson.Set(body, "AuthorizationProfile.serviceTemplate", data.ServiceTemplate.ValueBool())
	}
	if !data.EasywiredSessionCandidate.IsNull() {
		body, _ = sjson.Set(body, "AuthorizationProfile.easywiredSessionCandidate", data.EasywiredSessionCandidate.ValueBool())
	}
	if !data.VoiceDomainPermission.IsNull() {
		body, _ = sjson.Set(body, "AuthorizationProfile.voiceDomainPermission", data.VoiceDomainPermission.ValueBool())
	}
	if !data.Neat.IsNull() {
		body, _ = sjson.Set(body, "AuthorizationProfile.neat", data.Neat.ValueBool())
	}
	if !data.WebAuth.IsNull() {
		body, _ = sjson.Set(body, "AuthorizationProfile.webAuth", data.WebAuth.ValueBool())
	}
	if !data.MacSecPolicy.IsNull() {
		body, _ = sjson.Set(body, "AuthorizationProfile.macSecPolicy", data.MacSecPolicy.ValueString())
	}
	if !data.ReauthenticationConnectivity.IsNull() {
		body, _ = sjson.Set(body, "AuthorizationProfile.reauth.connectivity", data.ReauthenticationConnectivity.ValueString())
	}
	if !data.ReauthenticationTimer.IsNull() {
		body, _ = sjson.Set(body, "AuthorizationProfile.reauth.timer", data.ReauthenticationTimer.ValueInt64())
	}
	if len(data.AdvancedAttributes) > 0 {
		body, _ = sjson.Set(body, "AuthorizationProfile.advancedAttributes", []interface{}{})
		for _, item := range data.AdvancedAttributes {
			itemBody := ""
			itemBody, _ = sjson.Set(itemBody, "leftHandSideDictionaryAttribue.AdvancedAttributeValueType", "AdvancedDictionaryAttribute")
			if !item.AttributeLeftDictionaryName.IsNull() {
				itemBody, _ = sjson.Set(itemBody, "leftHandSideDictionaryAttribue.dictionaryName", item.AttributeLeftDictionaryName.ValueString())
			}
			if !item.AttributeLeftName.IsNull() {
				itemBody, _ = sjson.Set(itemBody, "leftHandSideDictionaryAttribue.attributeName", item.AttributeLeftName.ValueString())
			}
			if !item.AttributeRightValueType.IsNull() {
				itemBody, _ = sjson.Set(itemBody, "rightHandSideAttribueValue.AdvancedAttributeValueType", item.AttributeRightValueType.ValueString())
			}
			if !item.AttributeRightValue.IsNull() {
				itemBody, _ = sjson.Set(itemBody, "rightHandSideAttribueValue.value", item.AttributeRightValue.ValueString())
			}
			if !item.AttributeRightDictionaryName.IsNull() {
				itemBody, _ = sjson.Set(itemBody, "rightHandSideAttribueValue.dictionaryName", item.AttributeRightDictionaryName.ValueString())
			}
			if !item.AttributeRightName.IsNull() {
				itemBody, _ = sjson.Set(itemBody, "rightHandSideAttribueValue.attributeName", item.AttributeRightName.ValueString())
			}
			body, _ = sjson.SetRaw(body, "AuthorizationProfile.advancedAttributes.-1", itemBody)
		}
	}
	if !data.Ipv6DaclName.IsNull() {
		body, _ = sjson.Set(body, "AuthorizationProfile.ipv6DaclName", data.Ipv6DaclName.ValueString())
	}
	if !data.AirespaceIpv6Acl.IsNull() {
		body, _ = sjson.Set(body, "AuthorizationProfile.airespaceIPv6ACL", data.AirespaceIpv6Acl.ValueString())
	}
	return body
}

//template:end toBody

//template:begin fromBody
func (data *AuthorizationProfile) fromBody(ctx context.Context, res gjson.Result) {
	if value := res.Get("AuthorizationProfile.name"); value.Exists() && value.Type != gjson.Null {
		data.Name = types.StringValue(value.String())
	} else {
		data.Name = types.StringNull()
	}
	if value := res.Get("AuthorizationProfile.description"); value.Exists() && value.Type != gjson.Null {
		data.Description = types.StringValue(value.String())
	} else {
		data.Description = types.StringNull()
	}
	if value := res.Get("AuthorizationProfile.vlan.nameID"); value.Exists() && value.Type != gjson.Null {
		data.VlanNameId = types.StringValue(value.String())
	} else {
		data.VlanNameId = types.StringNull()
	}
	if value := res.Get("AuthorizationProfile.vlan.tagID"); value.Exists() && value.Type != gjson.Null {
		data.VlanTagId = types.Int64Value(value.Int())
	} else {
		data.VlanTagId = types.Int64Null()
	}
	if value := res.Get("AuthorizationProfile.webRedirection.WebRedirectionType"); value.Exists() && value.Type != gjson.Null {
		data.WebRedirectionType = types.StringValue(value.String())
	} else {
		data.WebRedirectionType = types.StringNull()
	}
	if value := res.Get("AuthorizationProfile.webRedirection.acl"); value.Exists() && value.Type != gjson.Null {
		data.WebRedirectionAcl = types.StringValue(value.String())
	} else {
		data.WebRedirectionAcl = types.StringNull()
	}
	if value := res.Get("AuthorizationProfile.webRedirection.portalName"); value.Exists() && value.Type != gjson.Null {
		data.WebRedirectionPortalName = types.StringValue(value.String())
	} else {
		data.WebRedirectionPortalName = types.StringNull()
	}
	if value := res.Get("AuthorizationProfile.webRedirection.staticIPHostNameFQDN"); value.Exists() && value.Type != gjson.Null {
		data.WebRedirectionStaticIpHostNameFqdn = types.StringValue(value.String())
	} else {
		data.WebRedirectionStaticIpHostNameFqdn = types.StringNull()
	}
	if value := res.Get("AuthorizationProfile.webRedirection.displayCertificatesRenewalMessages"); value.Exists() && value.Type != gjson.Null {
		data.WebRedirectionDisplayCertificatesRenewalMessages = types.BoolValue(value.Bool())
	} else {
		data.WebRedirectionDisplayCertificatesRenewalMessages = types.BoolNull()
	}
	if value := res.Get("AuthorizationProfile.agentlessPosture"); value.Exists() && value.Type != gjson.Null {
		data.AgentlessPosture = types.BoolValue(value.Bool())
	} else {
		data.AgentlessPosture = types.BoolNull()
	}
	if value := res.Get("AuthorizationProfile.accessType"); value.Exists() && value.Type != gjson.Null {
		data.AccessType = types.StringValue(value.String())
	} else {
		data.AccessType = types.StringValue("ACCESS_ACCEPT")
	}
	if value := res.Get("AuthorizationProfile.profileName"); value.Exists() && value.Type != gjson.Null {
		data.ProfileName = types.StringValue(value.String())
	} else {
		data.ProfileName = types.StringValue("Cisco")
	}
	if value := res.Get("AuthorizationProfile.airespaceACL"); value.Exists() && value.Type != gjson.Null {
		data.AirespaceAcl = types.StringValue(value.String())
	} else {
		data.AirespaceAcl = types.StringNull()
	}
	if value := res.Get("AuthorizationProfile.acl"); value.Exists() && value.Type != gjson.Null {
		data.Acl = types.StringValue(value.String())
	} else {
		data.Acl = types.StringNull()
	}
	if value := res.Get("AuthorizationProfile.daclName"); value.Exists() && value.Type != gjson.Null {
		data.DaclName = types.StringValue(value.String())
	} else {
		data.DaclName = types.StringNull()
	}
	if value := res.Get("AuthorizationProfile.autoSmartPort"); value.Exists() && value.Type != gjson.Null {
		data.AutoSmartPort = types.StringValue(value.String())
	} else {
		data.AutoSmartPort = types.StringNull()
	}
	if value := res.Get("AuthorizationProfile.interfaceTemplate"); value.Exists() && value.Type != gjson.Null {
		data.InterfaceTemplate = types.StringValue(value.String())
	} else {
		data.InterfaceTemplate = types.StringNull()
	}
	if value := res.Get("AuthorizationProfile.ipv6ACLFilter"); value.Exists() && value.Type != gjson.Null {
		data.Ipv6AclFilter = types.StringValue(value.String())
	} else {
		data.Ipv6AclFilter = types.StringNull()
	}
	if value := res.Get("AuthorizationProfile.avcProfile"); value.Exists() && value.Type != gjson.Null {
		data.AvcProfile = types.StringValue(value.String())
	} else {
		data.AvcProfile = types.StringNull()
	}
	if value := res.Get("AuthorizationProfile.asaVpn"); value.Exists() && value.Type != gjson.Null {
		data.AsaVpn = types.StringValue(value.String())
	} else {
		data.AsaVpn = types.StringNull()
	}
	if value := res.Get("AuthorizationProfile.uniqueIdentifier"); value.Exists() && value.Type != gjson.Null {
		data.UniqueIdentifier = types.StringValue(value.String())
	} else {
		data.UniqueIdentifier = types.StringNull()
	}
	if value := res.Get("AuthorizationProfile.trackMovement"); value.Exists() && value.Type != gjson.Null {
		data.TrackMovement = types.BoolValue(value.Bool())
	} else {
		data.TrackMovement = types.BoolValue(false)
	}
	if value := res.Get("AuthorizationProfile.serviceTemplate"); value.Exists() && value.Type != gjson.Null {
		data.ServiceTemplate = types.BoolValue(value.Bool())
	} else {
		data.ServiceTemplate = types.BoolValue(false)
	}
	if value := res.Get("AuthorizationProfile.easywiredSessionCandidate"); value.Exists() && value.Type != gjson.Null {
		data.EasywiredSessionCandidate = types.BoolValue(value.Bool())
	} else {
		data.EasywiredSessionCandidate = types.BoolValue(false)
	}
	if value := res.Get("AuthorizationProfile.voiceDomainPermission"); value.Exists() && value.Type != gjson.Null {
		data.VoiceDomainPermission = types.BoolValue(value.Bool())
	} else {
		data.VoiceDomainPermission = types.BoolValue(false)
	}
	if value := res.Get("AuthorizationProfile.neat"); value.Exists() && value.Type != gjson.Null {
		data.Neat = types.BoolValue(value.Bool())
	} else {
		data.Neat = types.BoolValue(false)
	}
	if value := res.Get("AuthorizationProfile.webAuth"); value.Exists() && value.Type != gjson.Null {
		data.WebAuth = types.BoolValue(value.Bool())
	} else {
		data.WebAuth = types.BoolValue(false)
	}
	if value := res.Get("AuthorizationProfile.macSecPolicy"); value.Exists() && value.Type != gjson.Null {
		data.MacSecPolicy = types.StringValue(value.String())
	} else {
		data.MacSecPolicy = types.StringNull()
	}
	if value := res.Get("AuthorizationProfile.reauth.connectivity"); value.Exists() && value.Type != gjson.Null {
		data.ReauthenticationConnectivity = types.StringValue(value.String())
	} else {
		data.ReauthenticationConnectivity = types.StringNull()
	}
	if value := res.Get("AuthorizationProfile.reauth.timer"); value.Exists() && value.Type != gjson.Null {
		data.ReauthenticationTimer = types.Int64Value(value.Int())
	} else {
		data.ReauthenticationTimer = types.Int64Null()
	}
	if value := res.Get("AuthorizationProfile.advancedAttributes"); value.Exists() {
		data.AdvancedAttributes = make([]AuthorizationProfileAdvancedAttributes, 0)
		value.ForEach(func(k, v gjson.Result) bool {
			item := AuthorizationProfileAdvancedAttributes{}
			if cValue := v.Get("leftHandSideDictionaryAttribue.dictionaryName"); cValue.Exists() && cValue.Type != gjson.Null {
				item.AttributeLeftDictionaryName = types.StringValue(cValue.String())
			} else {
				item.AttributeLeftDictionaryName = types.StringNull()
			}
			if cValue := v.Get("leftHandSideDictionaryAttribue.attributeName"); cValue.Exists() && cValue.Type != gjson.Null {
				item.AttributeLeftName = types.StringValue(cValue.String())
			} else {
				item.AttributeLeftName = types.StringNull()
			}
			if cValue := v.Get("rightHandSideAttribueValue.AdvancedAttributeValueType"); cValue.Exists() && cValue.Type != gjson.Null {
				item.AttributeRightValueType = types.StringValue(cValue.String())
			} else {
				item.AttributeRightValueType = types.StringNull()
			}
			if cValue := v.Get("rightHandSideAttribueValue.value"); cValue.Exists() && cValue.Type != gjson.Null {
				item.AttributeRightValue = types.StringValue(cValue.String())
			} else {
				item.AttributeRightValue = types.StringNull()
			}
			if cValue := v.Get("rightHandSideAttribueValue.dictionaryName"); cValue.Exists() && cValue.Type != gjson.Null {
				item.AttributeRightDictionaryName = types.StringValue(cValue.String())
			} else {
				item.AttributeRightDictionaryName = types.StringNull()
			}
			if cValue := v.Get("rightHandSideAttribueValue.attributeName"); cValue.Exists() && cValue.Type != gjson.Null {
				item.AttributeRightName = types.StringValue(cValue.String())
			} else {
				item.AttributeRightName = types.StringNull()
			}
			data.AdvancedAttributes = append(data.AdvancedAttributes, item)
			return true
		})
	}
	if value := res.Get("AuthorizationProfile.ipv6DaclName"); value.Exists() && value.Type != gjson.Null {
		data.Ipv6DaclName = types.StringValue(value.String())
	} else {
		data.Ipv6DaclName = types.StringNull()
	}
	if value := res.Get("AuthorizationProfile.airespaceIPv6ACL"); value.Exists() && value.Type != gjson.Null {
		data.AirespaceIpv6Acl = types.StringValue(value.String())
	} else {
		data.AirespaceIpv6Acl = types.StringNull()
	}
}

//template:end fromBody

//template:begin updateFromBody
func (data *AuthorizationProfile) updateFromBody(ctx context.Context, res gjson.Result) {
	if value := res.Get("AuthorizationProfile.name"); value.Exists() && !data.Name.IsNull() {
		data.Name = types.StringValue(value.String())
	} else {
		data.Name = types.StringNull()
	}
	if value := res.Get("AuthorizationProfile.description"); value.Exists() && !data.Description.IsNull() {
		data.Description = types.StringValue(value.String())
	} else {
		data.Description = types.StringNull()
	}
	if value := res.Get("AuthorizationProfile.vlan.nameID"); value.Exists() && !data.VlanNameId.IsNull() {
		data.VlanNameId = types.StringValue(value.String())
	} else {
		data.VlanNameId = types.StringNull()
	}
	if value := res.Get("AuthorizationProfile.vlan.tagID"); value.Exists() && !data.VlanTagId.IsNull() {
		data.VlanTagId = types.Int64Value(value.Int())
	} else {
		data.VlanTagId = types.Int64Null()
	}
	if value := res.Get("AuthorizationProfile.webRedirection.WebRedirectionType"); value.Exists() && !data.WebRedirectionType.IsNull() {
		data.WebRedirectionType = types.StringValue(value.String())
	} else {
		data.WebRedirectionType = types.StringNull()
	}
	if value := res.Get("AuthorizationProfile.webRedirection.acl"); value.Exists() && !data.WebRedirectionAcl.IsNull() {
		data.WebRedirectionAcl = types.StringValue(value.String())
	} else {
		data.WebRedirectionAcl = types.StringNull()
	}
	if value := res.Get("AuthorizationProfile.webRedirection.portalName"); value.Exists() && !data.WebRedirectionPortalName.IsNull() {
		data.WebRedirectionPortalName = types.StringValue(value.String())
	} else {
		data.WebRedirectionPortalName = types.StringNull()
	}
	if value := res.Get("AuthorizationProfile.webRedirection.staticIPHostNameFQDN"); value.Exists() && !data.WebRedirectionStaticIpHostNameFqdn.IsNull() {
		data.WebRedirectionStaticIpHostNameFqdn = types.StringValue(value.String())
	} else {
		data.WebRedirectionStaticIpHostNameFqdn = types.StringNull()
	}
	if value := res.Get("AuthorizationProfile.webRedirection.displayCertificatesRenewalMessages"); value.Exists() && !data.WebRedirectionDisplayCertificatesRenewalMessages.IsNull() {
		data.WebRedirectionDisplayCertificatesRenewalMessages = types.BoolValue(value.Bool())
	} else {
		data.WebRedirectionDisplayCertificatesRenewalMessages = types.BoolNull()
	}
	if value := res.Get("AuthorizationProfile.agentlessPosture"); value.Exists() && !data.AgentlessPosture.IsNull() {
		data.AgentlessPosture = types.BoolValue(value.Bool())
	} else {
		data.AgentlessPosture = types.BoolNull()
	}
	if value := res.Get("AuthorizationProfile.accessType"); value.Exists() && !data.AccessType.IsNull() {
		data.AccessType = types.StringValue(value.String())
	} else if data.AccessType.ValueString() != "ACCESS_ACCEPT" {
		data.AccessType = types.StringNull()
	}
	if value := res.Get("AuthorizationProfile.profileName"); value.Exists() && !data.ProfileName.IsNull() {
		data.ProfileName = types.StringValue(value.String())
	} else if data.ProfileName.ValueString() != "Cisco" {
		data.ProfileName = types.StringNull()
	}
	if value := res.Get("AuthorizationProfile.airespaceACL"); value.Exists() && !data.AirespaceAcl.IsNull() {
		data.AirespaceAcl = types.StringValue(value.String())
	} else {
		data.AirespaceAcl = types.StringNull()
	}
	if value := res.Get("AuthorizationProfile.acl"); value.Exists() && !data.Acl.IsNull() {
		data.Acl = types.StringValue(value.String())
	} else {
		data.Acl = types.StringNull()
	}
	if value := res.Get("AuthorizationProfile.daclName"); value.Exists() && !data.DaclName.IsNull() {
		data.DaclName = types.StringValue(value.String())
	} else {
		data.DaclName = types.StringNull()
	}
	if value := res.Get("AuthorizationProfile.autoSmartPort"); value.Exists() && !data.AutoSmartPort.IsNull() {
		data.AutoSmartPort = types.StringValue(value.String())
	} else {
		data.AutoSmartPort = types.StringNull()
	}
	if value := res.Get("AuthorizationProfile.interfaceTemplate"); value.Exists() && !data.InterfaceTemplate.IsNull() {
		data.InterfaceTemplate = types.StringValue(value.String())
	} else {
		data.InterfaceTemplate = types.StringNull()
	}
	if value := res.Get("AuthorizationProfile.ipv6ACLFilter"); value.Exists() && !data.Ipv6AclFilter.IsNull() {
		data.Ipv6AclFilter = types.StringValue(value.String())
	} else {
		data.Ipv6AclFilter = types.StringNull()
	}
	if value := res.Get("AuthorizationProfile.avcProfile"); value.Exists() && !data.AvcProfile.IsNull() {
		data.AvcProfile = types.StringValue(value.String())
	} else {
		data.AvcProfile = types.StringNull()
	}
	if value := res.Get("AuthorizationProfile.asaVpn"); value.Exists() && !data.AsaVpn.IsNull() {
		data.AsaVpn = types.StringValue(value.String())
	} else {
		data.AsaVpn = types.StringNull()
	}
	if value := res.Get("AuthorizationProfile.uniqueIdentifier"); value.Exists() && !data.UniqueIdentifier.IsNull() {
		data.UniqueIdentifier = types.StringValue(value.String())
	} else {
		data.UniqueIdentifier = types.StringNull()
	}
	if value := res.Get("AuthorizationProfile.trackMovement"); value.Exists() && !data.TrackMovement.IsNull() {
		data.TrackMovement = types.BoolValue(value.Bool())
	} else if data.TrackMovement.ValueBool() != false {
		data.TrackMovement = types.BoolNull()
	}
	if value := res.Get("AuthorizationProfile.serviceTemplate"); value.Exists() && !data.ServiceTemplate.IsNull() {
		data.ServiceTemplate = types.BoolValue(value.Bool())
	} else if data.ServiceTemplate.ValueBool() != false {
		data.ServiceTemplate = types.BoolNull()
	}
	if value := res.Get("AuthorizationProfile.easywiredSessionCandidate"); value.Exists() && !data.EasywiredSessionCandidate.IsNull() {
		data.EasywiredSessionCandidate = types.BoolValue(value.Bool())
	} else if data.EasywiredSessionCandidate.ValueBool() != false {
		data.EasywiredSessionCandidate = types.BoolNull()
	}
	if value := res.Get("AuthorizationProfile.voiceDomainPermission"); value.Exists() && !data.VoiceDomainPermission.IsNull() {
		data.VoiceDomainPermission = types.BoolValue(value.Bool())
	} else if data.VoiceDomainPermission.ValueBool() != false {
		data.VoiceDomainPermission = types.BoolNull()
	}
	if value := res.Get("AuthorizationProfile.neat"); value.Exists() && !data.Neat.IsNull() {
		data.Neat = types.BoolValue(value.Bool())
	} else if data.Neat.ValueBool() != false {
		data.Neat = types.BoolNull()
	}
	if value := res.Get("AuthorizationProfile.webAuth"); value.Exists() && !data.WebAuth.IsNull() {
		data.WebAuth = types.BoolValue(value.Bool())
	} else if data.WebAuth.ValueBool() != false {
		data.WebAuth = types.BoolNull()
	}
	if value := res.Get("AuthorizationProfile.macSecPolicy"); value.Exists() && !data.MacSecPolicy.IsNull() {
		data.MacSecPolicy = types.StringValue(value.String())
	} else {
		data.MacSecPolicy = types.StringNull()
	}
	if value := res.Get("AuthorizationProfile.reauth.connectivity"); value.Exists() && !data.ReauthenticationConnectivity.IsNull() {
		data.ReauthenticationConnectivity = types.StringValue(value.String())
	} else {
		data.ReauthenticationConnectivity = types.StringNull()
	}
	if value := res.Get("AuthorizationProfile.reauth.timer"); value.Exists() && !data.ReauthenticationTimer.IsNull() {
		data.ReauthenticationTimer = types.Int64Value(value.Int())
	} else {
		data.ReauthenticationTimer = types.Int64Null()
	}
	for i := range data.AdvancedAttributes {
		keys := [...]string{"leftHandSideDictionaryAttribue.dictionaryName", "leftHandSideDictionaryAttribue.attributeName", "rightHandSideAttribueValue.AdvancedAttributeValueType", "rightHandSideAttribueValue.value", "rightHandSideAttribueValue.dictionaryName", "rightHandSideAttribueValue.attributeName"}
		keyValues := [...]string{data.AdvancedAttributes[i].AttributeLeftDictionaryName.ValueString(), data.AdvancedAttributes[i].AttributeLeftName.ValueString(), data.AdvancedAttributes[i].AttributeRightValueType.ValueString(), data.AdvancedAttributes[i].AttributeRightValue.ValueString(), data.AdvancedAttributes[i].AttributeRightDictionaryName.ValueString(), data.AdvancedAttributes[i].AttributeRightName.ValueString()}

		var r gjson.Result
		res.Get("AuthorizationProfile.advancedAttributes").ForEach(
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
		if value := r.Get("leftHandSideDictionaryAttribue.dictionaryName"); value.Exists() && !data.AdvancedAttributes[i].AttributeLeftDictionaryName.IsNull() {
			data.AdvancedAttributes[i].AttributeLeftDictionaryName = types.StringValue(value.String())
		} else {
			data.AdvancedAttributes[i].AttributeLeftDictionaryName = types.StringNull()
		}
		if value := r.Get("leftHandSideDictionaryAttribue.attributeName"); value.Exists() && !data.AdvancedAttributes[i].AttributeLeftName.IsNull() {
			data.AdvancedAttributes[i].AttributeLeftName = types.StringValue(value.String())
		} else {
			data.AdvancedAttributes[i].AttributeLeftName = types.StringNull()
		}
		if value := r.Get("rightHandSideAttribueValue.AdvancedAttributeValueType"); value.Exists() && !data.AdvancedAttributes[i].AttributeRightValueType.IsNull() {
			data.AdvancedAttributes[i].AttributeRightValueType = types.StringValue(value.String())
		} else {
			data.AdvancedAttributes[i].AttributeRightValueType = types.StringNull()
		}
		if value := r.Get("rightHandSideAttribueValue.value"); value.Exists() && !data.AdvancedAttributes[i].AttributeRightValue.IsNull() {
			data.AdvancedAttributes[i].AttributeRightValue = types.StringValue(value.String())
		} else {
			data.AdvancedAttributes[i].AttributeRightValue = types.StringNull()
		}
		if value := r.Get("rightHandSideAttribueValue.dictionaryName"); value.Exists() && !data.AdvancedAttributes[i].AttributeRightDictionaryName.IsNull() {
			data.AdvancedAttributes[i].AttributeRightDictionaryName = types.StringValue(value.String())
		} else {
			data.AdvancedAttributes[i].AttributeRightDictionaryName = types.StringNull()
		}
		if value := r.Get("rightHandSideAttribueValue.attributeName"); value.Exists() && !data.AdvancedAttributes[i].AttributeRightName.IsNull() {
			data.AdvancedAttributes[i].AttributeRightName = types.StringValue(value.String())
		} else {
			data.AdvancedAttributes[i].AttributeRightName = types.StringNull()
		}
	}
	if value := res.Get("AuthorizationProfile.ipv6DaclName"); value.Exists() && !data.Ipv6DaclName.IsNull() {
		data.Ipv6DaclName = types.StringValue(value.String())
	} else {
		data.Ipv6DaclName = types.StringNull()
	}
	if value := res.Get("AuthorizationProfile.airespaceIPv6ACL"); value.Exists() && !data.AirespaceIpv6Acl.IsNull() {
		data.AirespaceIpv6Acl = types.StringValue(value.String())
	} else {
		data.AirespaceIpv6Acl = types.StringNull()
	}
}

//template:end updateFromBody

//template:begin isNull
func (data *AuthorizationProfile) isNull(ctx context.Context, res gjson.Result) bool {
	if !data.Name.IsNull() {
		return false
	}
	if !data.Description.IsNull() {
		return false
	}
	if !data.VlanNameId.IsNull() {
		return false
	}
	if !data.VlanTagId.IsNull() {
		return false
	}
	if !data.WebRedirectionType.IsNull() {
		return false
	}
	if !data.WebRedirectionAcl.IsNull() {
		return false
	}
	if !data.WebRedirectionPortalName.IsNull() {
		return false
	}
	if !data.WebRedirectionStaticIpHostNameFqdn.IsNull() {
		return false
	}
	if !data.WebRedirectionDisplayCertificatesRenewalMessages.IsNull() {
		return false
	}
	if !data.AgentlessPosture.IsNull() {
		return false
	}
	if !data.AccessType.IsNull() {
		return false
	}
	if !data.ProfileName.IsNull() {
		return false
	}
	if !data.AirespaceAcl.IsNull() {
		return false
	}
	if !data.Acl.IsNull() {
		return false
	}
	if !data.DaclName.IsNull() {
		return false
	}
	if !data.AutoSmartPort.IsNull() {
		return false
	}
	if !data.InterfaceTemplate.IsNull() {
		return false
	}
	if !data.Ipv6AclFilter.IsNull() {
		return false
	}
	if !data.AvcProfile.IsNull() {
		return false
	}
	if !data.AsaVpn.IsNull() {
		return false
	}
	if !data.UniqueIdentifier.IsNull() {
		return false
	}
	if !data.TrackMovement.IsNull() {
		return false
	}
	if !data.ServiceTemplate.IsNull() {
		return false
	}
	if !data.EasywiredSessionCandidate.IsNull() {
		return false
	}
	if !data.VoiceDomainPermission.IsNull() {
		return false
	}
	if !data.Neat.IsNull() {
		return false
	}
	if !data.WebAuth.IsNull() {
		return false
	}
	if !data.MacSecPolicy.IsNull() {
		return false
	}
	if !data.ReauthenticationConnectivity.IsNull() {
		return false
	}
	if !data.ReauthenticationTimer.IsNull() {
		return false
	}
	if len(data.AdvancedAttributes) > 0 {
		return false
	}
	if !data.Ipv6DaclName.IsNull() {
		return false
	}
	if !data.AirespaceIpv6Acl.IsNull() {
		return false
	}
	return true
}

//template:end isNull
