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

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/netascode/go-ise"
)

//template:end imports

//template:begin model

// Ensure the implementation satisfies the expected interfaces.
var (
	_ datasource.DataSource              = &AuthorizationProfileDataSource{}
	_ datasource.DataSourceWithConfigure = &AuthorizationProfileDataSource{}
)

func NewAuthorizationProfileDataSource() datasource.DataSource {
	return &AuthorizationProfileDataSource{}
}

type AuthorizationProfileDataSource struct {
	client *ise.Client
}

func (d *AuthorizationProfileDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_authorization_profile"
}

func (d *AuthorizationProfileDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		// This description is used by the documentation generator and the language server.
		MarkdownDescription: "This data source can read an authorization profiles policy element.",

		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "The id of the object",
				Required:            true,
			},
			"name": schema.StringAttribute{
				MarkdownDescription: "The name of the authorization profile",
				Computed:            true,
			},
			"description": schema.StringAttribute{
				MarkdownDescription: "Description",
				Computed:            true,
			},
			"vlan_name_id": schema.StringAttribute{
				MarkdownDescription: "Vlan name or ID",
				Computed:            true,
			},
			"vlan_tag_id": schema.Int64Attribute{
				MarkdownDescription: "Vlan tag ID",
				Computed:            true,
			},
			"web_redirection_type": schema.StringAttribute{
				MarkdownDescription: "This type must fit the `web_redirection_portal_name`",
				Computed:            true,
			},
			"web_redirection_acl": schema.StringAttribute{
				MarkdownDescription: "Web redirection ACL",
				Computed:            true,
			},
			"web_redirection_portal_name": schema.StringAttribute{
				MarkdownDescription: "A portal that exist in the DB and fits the `web_redirection_type`",
				Computed:            true,
			},
			"web_redirection_static_ip_host_name_fqdn": schema.StringAttribute{
				MarkdownDescription: "IP, hostname or FQDN",
				Computed:            true,
			},
			"web_redirection_display_certificates_renewal_messages": schema.BoolAttribute{
				MarkdownDescription: "This attribute is mandatory when `web_redirection_type` value is `CentralizedWebAuth`. For all other `web_redirection_type` values the field must be ignored.",
				Computed:            true,
			},
			"agentless_posture": schema.BoolAttribute{
				MarkdownDescription: "Agentless Posture.",
				Computed:            true,
			},
			"access_type": schema.StringAttribute{
				MarkdownDescription: "Allowed Values: `ACCESS_ACCEPT`, `ACCESS_REJECT`",
				Computed:            true,
			},
			"authz_profile_type": schema.StringAttribute{
				MarkdownDescription: "Allowed Values: `SWITCH`, `TRUSTSEC`, `TACACS`. `SWITCH` is used for Standard Authorization Profiles. only `SWITCH` is supported.",
				Computed:            true,
			},
			"profile_name": schema.StringAttribute{
				MarkdownDescription: "Value needs to be an existing Network Device Profile",
				Computed:            true,
			},
			"airespace_acl": schema.StringAttribute{
				MarkdownDescription: "Airespace ACL",
				Computed:            true,
			},
			"acl": schema.StringAttribute{
				MarkdownDescription: "ACL",
				Computed:            true,
			},
			"dacl_name": schema.StringAttribute{
				MarkdownDescription: "DACL name",
				Computed:            true,
			},
			"auto_smart_port": schema.StringAttribute{
				MarkdownDescription: "Auto smart port",
				Computed:            true,
			},
			"interface_template": schema.StringAttribute{
				MarkdownDescription: "Interface template",
				Computed:            true,
			},
			"ipv6_acl_filter": schema.StringAttribute{
				MarkdownDescription: "IPv6 ACL",
				Computed:            true,
			},
			"avc_profile": schema.StringAttribute{
				MarkdownDescription: "AVC profile",
				Computed:            true,
			},
			"asa_vpn": schema.StringAttribute{
				MarkdownDescription: "ASA VPN",
				Computed:            true,
			},
			"unique_identifier": schema.StringAttribute{
				MarkdownDescription: "Unique identifier",
				Computed:            true,
			},
			"track_movement": schema.BoolAttribute{
				MarkdownDescription: "Track movement",
				Computed:            true,
			},
			"service_template": schema.BoolAttribute{
				MarkdownDescription: "Service template",
				Computed:            true,
			},
			"easywired_session_candidate": schema.BoolAttribute{
				MarkdownDescription: "Easy wired session candidate",
				Computed:            true,
			},
			"voice_domain_permission": schema.BoolAttribute{
				MarkdownDescription: "Voice domain permission",
				Computed:            true,
			},
			"neat": schema.BoolAttribute{
				MarkdownDescription: "NEAT",
				Computed:            true,
			},
			"web_auth": schema.BoolAttribute{
				MarkdownDescription: "Web authentication (local)",
				Computed:            true,
			},
			"mac_sec_policy": schema.StringAttribute{
				MarkdownDescription: "MacSec policy",
				Computed:            true,
			},
			"reauthentication_connectivity": schema.StringAttribute{
				MarkdownDescription: "Maintain Connectivity During Reauthentication",
				Computed:            true,
			},
			"reauthentication_timer": schema.Int64Attribute{
				MarkdownDescription: "Reauthentication timer",
				Computed:            true,
			},
			"advanced_attributes": schema.ListNestedAttribute{
				MarkdownDescription: "List of advanced attributes",
				Computed:            true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"attribute_1_value_type": schema.StringAttribute{
							MarkdownDescription: "Advanced attribute value type",
							Computed:            true,
						},
						"attribute_1_dictionary_name": schema.StringAttribute{
							MarkdownDescription: "Dictionary name",
							Computed:            true,
						},
						"attribute_1_name": schema.StringAttribute{
							MarkdownDescription: "Attribute name",
							Computed:            true,
						},
						"attribute_2_value_type": schema.StringAttribute{
							MarkdownDescription: "Advanced attribute value type",
							Computed:            true,
						},
						"attribute_2_value": schema.StringAttribute{
							MarkdownDescription: "Attribute value",
							Computed:            true,
						},
					},
				},
			},
			"ipv6_dacl_name": schema.StringAttribute{
				MarkdownDescription: "IPv6 DACL name",
				Computed:            true,
			},
			"airespace_ipv6_acl": schema.StringAttribute{
				MarkdownDescription: "Airespace IPv6 ACL",
				Computed:            true,
			},
		},
	}
}

func (d *AuthorizationProfileDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, _ *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	d.client = req.ProviderData.(*IseProviderData).Client
}

//template:end model

//template:begin read
func (d *AuthorizationProfileDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config AuthorizationProfile

	// Read config
	diags := req.Config.Get(ctx, &config)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, fmt.Sprintf("%s: Beginning Read", config.Id.String()))

	res, err := d.client.Get(config.getPath() + "/" + config.Id.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Failed to retrieve object, got error: %s", err))
		return
	}

	config.fromBody(ctx, res)

	tflog.Debug(ctx, fmt.Sprintf("%s: Read finished successfully", config.Id.ValueString()))

	diags = resp.State.Set(ctx, &config)
	resp.Diagnostics.Append(diags...)
}

//template:end read