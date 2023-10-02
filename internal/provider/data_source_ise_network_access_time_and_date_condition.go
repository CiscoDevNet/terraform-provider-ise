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
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/netascode/go-ise"
)

//template:end imports

//template:begin model

// Ensure the implementation satisfies the expected interfaces.
var (
	_ datasource.DataSource              = &NetworkAccessTimeAndDateConditionDataSource{}
	_ datasource.DataSourceWithConfigure = &NetworkAccessTimeAndDateConditionDataSource{}
)

func NewNetworkAccessTimeAndDateConditionDataSource() datasource.DataSource {
	return &NetworkAccessTimeAndDateConditionDataSource{}
}

type NetworkAccessTimeAndDateConditionDataSource struct {
	client *ise.Client
}

func (d *NetworkAccessTimeAndDateConditionDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_network_access_time_and_date_condition"
}

func (d *NetworkAccessTimeAndDateConditionDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		// This description is used by the documentation generator and the language server.
		MarkdownDescription: "This data source can read the Network Access Time And Date Condition.",

		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "The id of the object",
				Required:            true,
			},
			"name": schema.StringAttribute{
				MarkdownDescription: "Condition name",
				Computed:            true,
			},
			"description": schema.StringAttribute{
				MarkdownDescription: "Condition description",
				Computed:            true,
			},
			"is_negate": schema.BoolAttribute{
				MarkdownDescription: "Indicates whereas this condition is in negate mode",
				Computed:            true,
			},
			"week_days": schema.ListAttribute{
				MarkdownDescription: "Defines for which days this condition will be matched. List of weekdays - `Monday`, `Tuesday`, `Wednesday`, `Thursday`, `Friday`, `Saturday`, `Sunday`. Default - List of all week days.",
				ElementType:         types.StringType,
				Computed:            true,
			},
			"week_days_exception": schema.ListAttribute{
				MarkdownDescription: "Defines for which days this condition will NOT be matched. List of weekdays - `Monday`, `Tuesday`, `Wednesday`, `Thursday`, `Friday`, `Saturday`, `Sunday`.",
				ElementType:         types.StringType,
				Computed:            true,
			},
			"start_date": schema.StringAttribute{
				MarkdownDescription: "Start date",
				Computed:            true,
			},
			"end_date": schema.StringAttribute{
				MarkdownDescription: "End date",
				Computed:            true,
			},
			"exception_start_date": schema.StringAttribute{
				MarkdownDescription: "Exception start date",
				Computed:            true,
			},
			"exception_end_date": schema.StringAttribute{
				MarkdownDescription: "Exception end date",
				Computed:            true,
			},
			"start_time": schema.StringAttribute{
				MarkdownDescription: "Start time",
				Computed:            true,
			},
			"end_time": schema.StringAttribute{
				MarkdownDescription: "End time",
				Computed:            true,
			},
			"exception_start_time": schema.StringAttribute{
				MarkdownDescription: "Exception start time",
				Computed:            true,
			},
			"exception_end_time": schema.StringAttribute{
				MarkdownDescription: "Exception end time",
				Computed:            true,
			},
		},
	}
}

func (d *NetworkAccessTimeAndDateConditionDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, _ *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	d.client = req.ProviderData.(*IseProviderData).Client
}

//template:end model

//template:begin read
func (d *NetworkAccessTimeAndDateConditionDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config NetworkAccessTimeAndDateCondition

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
