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

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/netascode/go-ise"
)

//template:end imports

//template:begin header

// Ensure the implementation satisfies the expected interfaces.
var (
	_ datasource.DataSource              = &ActiveDirectoryJoinPointDataSource{}
	_ datasource.DataSourceWithConfigure = &ActiveDirectoryJoinPointDataSource{}
)

func NewActiveDirectoryJoinPointDataSource() datasource.DataSource {
	return &ActiveDirectoryJoinPointDataSource{}
}

type ActiveDirectoryJoinPointDataSource struct {
	client *ise.Client
}

func (d *ActiveDirectoryJoinPointDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_active_directory_join_point"
}

//template:end header

//template:begin model
func (d *ActiveDirectoryJoinPointDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		// This description is used by the documentation generator and the language server.
		MarkdownDescription: "This data source can read the Active Directory Join Point.",

		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "The id of the object",
				Required:            true,
			},
			"name": schema.StringAttribute{
				MarkdownDescription: "The name of the active directory join point",
				Computed:            true,
			},
			"description": schema.StringAttribute{
				MarkdownDescription: "Join point description",
				Computed:            true,
			},
			"domain": schema.StringAttribute{
				MarkdownDescription: "AD domain associated with the join point",
				Computed:            true,
			},
			"ad_scopes_names": schema.StringAttribute{
				MarkdownDescription: "String that contains the names of the scopes that the active directory belongs to. Names are separated by comma.",
				Computed:            true,
			},
			"enable_domain_allowed_list": schema.BoolAttribute{
				MarkdownDescription: "",
				Computed:            true,
			},
			"groups": schema.ListNestedAttribute{
				MarkdownDescription: "List of AD Groups",
				Computed:            true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"name": schema.StringAttribute{
							MarkdownDescription: "Required for each group in the group list with no duplication between groups",
							Computed:            true,
						},
						"sid": schema.StringAttribute{
							MarkdownDescription: "Required for each group in the group list with no duplication between groups",
							Computed:            true,
						},
						"type": schema.StringAttribute{
							MarkdownDescription: "",
							Computed:            true,
						},
					},
				},
			},
			"attributes": schema.ListNestedAttribute{
				MarkdownDescription: "List of AD attributes",
				Computed:            true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"name": schema.StringAttribute{
							MarkdownDescription: "Required for each attribute in the attribute list with no duplication between attributes",
							Computed:            true,
						},
						"type": schema.StringAttribute{
							MarkdownDescription: "Required for each group in the group list",
							Computed:            true,
						},
						"internal_name": schema.StringAttribute{
							MarkdownDescription: "Required for each attribute in the attribute list",
							Computed:            true,
						},
						"default_value": schema.StringAttribute{
							MarkdownDescription: "Required for each attribute in the attribute list. Can contain an empty string.",
							Computed:            true,
						},
					},
				},
			},
			"rewrite_rules": schema.ListNestedAttribute{
				MarkdownDescription: "List of Rewrite rules",
				Computed:            true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"row_id": schema.StringAttribute{
							MarkdownDescription: "Required for each rule in the list in serial order",
							Computed:            true,
						},
						"rewrite_match": schema.StringAttribute{
							MarkdownDescription: "Required for each rule in the list with no duplication between rules",
							Computed:            true,
						},
						"rewrite_result": schema.StringAttribute{
							MarkdownDescription: "Required for each rule in the list",
							Computed:            true,
						},
					},
				},
			},
			"enable_rewrites": schema.BoolAttribute{
				MarkdownDescription: "Enable Rewrites",
				Computed:            true,
			},
			"enable_pass_change": schema.BoolAttribute{
				MarkdownDescription: "Enable Password Change",
				Computed:            true,
			},
			"enable_machine_auth": schema.BoolAttribute{
				MarkdownDescription: "Enable Machine Authentication",
				Computed:            true,
			},
			"enable_machine_access": schema.BoolAttribute{
				MarkdownDescription: "Enable Machine Access",
				Computed:            true,
			},
			"enable_dialin_permission_check": schema.BoolAttribute{
				MarkdownDescription: "Enable Dial In Permission Check",
				Computed:            true,
			},
			"plaintext_auth": schema.BoolAttribute{
				MarkdownDescription: "Plain Text Authentication",
				Computed:            true,
			},
			"aging_time": schema.Int64Attribute{
				MarkdownDescription: "Aging Time",
				Computed:            true,
			},
			"enable_callback_for_dialin_client": schema.BoolAttribute{
				MarkdownDescription: "Enable Callback For Dial In Client",
				Computed:            true,
			},
			"identity_not_in_ad_behaviour": schema.StringAttribute{
				MarkdownDescription: "Identity Not In AD Behaviour",
				Computed:            true,
			},
			"unreachable_domains_behaviour": schema.StringAttribute{
				MarkdownDescription: "Unreachable Domains Behaviour",
				Computed:            true,
			},
			"schema": schema.StringAttribute{
				MarkdownDescription: "Schema",
				Computed:            true,
			},
			"first_name": schema.StringAttribute{
				MarkdownDescription: "User info attribute",
				Computed:            true,
			},
			"department": schema.StringAttribute{
				MarkdownDescription: "User info attribute",
				Computed:            true,
			},
			"last_name": schema.StringAttribute{
				MarkdownDescription: "User info attribute",
				Computed:            true,
			},
			"organizational_unit": schema.StringAttribute{
				MarkdownDescription: "User info attribute",
				Computed:            true,
			},
			"job_title": schema.StringAttribute{
				MarkdownDescription: "User info attribute",
				Computed:            true,
			},
			"locality": schema.StringAttribute{
				MarkdownDescription: "User info attribute",
				Computed:            true,
			},
			"email": schema.StringAttribute{
				MarkdownDescription: "User info attribute",
				Computed:            true,
			},
			"state_or_province": schema.StringAttribute{
				MarkdownDescription: "User info attribute",
				Computed:            true,
			},
			"telephone": schema.StringAttribute{
				MarkdownDescription: "User info attribute",
				Computed:            true,
			},
			"country": schema.StringAttribute{
				MarkdownDescription: "User info attribute",
				Computed:            true,
			},
			"street_address": schema.StringAttribute{
				MarkdownDescription: "User info attribute",
				Computed:            true,
			},
			"enable_failed_auth_protection": schema.BoolAttribute{
				MarkdownDescription: "Enable prevent AD account lockout due to too many bad password attempts",
				Computed:            true,
			},
			"failed_auth_threshold": schema.Int64Attribute{
				MarkdownDescription: "Number of bad password attempts",
				Computed:            true,
			},
			"auth_protection_type": schema.StringAttribute{
				MarkdownDescription: "Enable prevent AD account lockout for WIRELESS/WIRED/BOTH",
				Computed:            true,
			},
		},
	}
}

//template:end model

//template:begin configValidators
//template:end configValidators

//template:end configure
func (d *ActiveDirectoryJoinPointDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, _ *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	d.client = req.ProviderData.(*IseProviderData).Client
}

//template:end configure

//template:begin read
func (d *ActiveDirectoryJoinPointDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config ActiveDirectoryJoinPoint

	// Read config
	diags := req.Config.Get(ctx, &config)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, fmt.Sprintf("%s: Beginning Read", config.Id.ValueString()))

	res, err := d.client.Get(config.getPath() + "/" + url.QueryEscape(config.Id.ValueString()))
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
