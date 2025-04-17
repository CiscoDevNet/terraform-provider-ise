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
	"sort"
	"strings"

	"github.com/CiscoDevNet/terraform-provider-ise/internal/provider/helpers"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/netascode/go-ise"
	"github.com/tidwall/sjson"
)

//template:end imports

//template:begin header

// Ensure provider defined types fully satisfy framework interfaces
var _ resource.Resource = &NetworkAccessPolicySetUpdateRanksResource{}

func NewNetworkAccessPolicySetUpdateRanksResource() resource.Resource {
	return &NetworkAccessPolicySetUpdateRanksResource{}
}

type NetworkAccessPolicySetUpdateRanksResource struct {
	client *ise.Client
}

func (r *NetworkAccessPolicySetUpdateRanksResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_network_access_policy_set_update_ranks"
}

//template:end header

//template:begin model
func (r *NetworkAccessPolicySetUpdateRanksResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		// This description is used by the documentation generator and the language server.
		MarkdownDescription: helpers.NewAttributeDescription("This resource is used to bulk update rank field in network access policy set. It serves as a workaround for the ISE API/Backend limitation which restricts rank assignments to a strictly incremental sequence. By utilizing this resource and network_access_policy_set resource, you can bypass the APIs limitation. Creation of this resource is performing PUT operation (Update) and it only tracks rank field. When this resource is destroyed, no action is performed on ISE and resource is just removed from state.").String,

		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "The id of the object",
				Computed:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"policies": schema.ListNestedAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("").String,
				Optional:            true,
				PlanModifiers: []planmodifier.List{
					listplanmodifier.RequiresReplace(),
				},
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							MarkdownDescription: helpers.NewAttributeDescription("Policy set ID").String,
							Optional:            true,
						},
						"rank": schema.Int64Attribute{
							MarkdownDescription: helpers.NewAttributeDescription("The rank (priority) in relation to other rules. Lower rank is higher priority.").String,
							Required:            true,
						},
					},
				},
			},
		},
	}
}

//template:end model

//template:begin configure
func (r *NetworkAccessPolicySetUpdateRanksResource) Configure(_ context.Context, req resource.ConfigureRequest, _ *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	r.client = req.ProviderData.(*IseProviderData).Client
}

//template:end configure

//template:begin create
func (r *NetworkAccessPolicySetUpdateRanksResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan NetworkAccessPolicySetUpdateRanks
	var existingData NetworkAccessPolicySet

	// Read plan
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, fmt.Sprintf("%s: Beginning Create", plan.Id.ValueString()))
	rules := make([]NetworkAccessPolicySetUpdateRanksPolicies, len(plan.Policies))
	copy(rules, plan.Policies)
	sort.Slice(rules, func(i, j int) bool {
		return rules[i].Rank.ValueInt64() < rules[j].Rank.ValueInt64()
	})
	for _, rule := range rules {
		aa := plan.getPath()+"/"+url.QueryEscape(rule.Id.ValueString())
		tflog.Debug(ctx, fmt.Sprintf("%v: 1getting", aa))
		res, err := r.client.Get(plan.getPath()+"/"+url.QueryEscape(rule.Id.ValueString()))
		if err != nil {
			resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Failed to retrieve object (GET), got error: %s", err))
			return
		}
		existingData.fromBody(ctx, res)

		// Use the `toBody` function to construct the body from existingData
		body := existingData.toBody(ctx, existingData)

		// Update rank
		body, _ = sjson.Set(body, "rank", rule.Rank.ValueInt64())
		tflog.Debug(ctx, fmt.Sprintf("%s: bodyyy1", body))
		res, err = r.client.Put(plan.getPath()+"/"+url.QueryEscape(rule.Id.ValueString()), body)
		if err != nil {
			resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Failed to configure object (PUT), got error: %s, %s", err, res.String()))
			return
		}
	}
	plan.Id = types.StringValue("")

	tflog.Debug(ctx, fmt.Sprintf("%s: Create finished successfully", plan.Id.ValueString()))

	diags = resp.State.Set(ctx, &plan)
	resp.Diagnostics.Append(diags...)
}

//template:end create

//template:begin read
func (r *NetworkAccessPolicySetUpdateRanksResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state NetworkAccessPolicySetUpdateRanks

	// Read state
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, fmt.Sprintf("%s: Beginning Read", state.Id.String()))
	res, err := r.client.Get(state.getPath())
	if err != nil && strings.Contains(err.Error(), "StatusCode 404") {
		resp.State.RemoveResource(ctx)
		return
	} else if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Failed to retrieve object (GET), got error: %s, %s", err, res.String()))
		return
	}

	// If every attribute is set to null we are dealing with an import operation and therefore reading all attributes
	if state.isNull(ctx, res) {
		state.fromBody(ctx, res)
	} else {
		state.updateFromBody(ctx, res)
	}

	tflog.Debug(ctx, fmt.Sprintf("%s: Read finished successfully", state.Id.ValueString()))

	diags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
}

//template:end read

//template:begin update
func (r *NetworkAccessPolicySetUpdateRanksResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state NetworkAccessPolicySetUpdateRanks
	var existingData NetworkAccessPolicySet

	// Read plan
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	// Read state
	diags = req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, fmt.Sprintf("%s: Beginning Update", plan.Id.ValueString()))
	rules := make([]NetworkAccessPolicySetUpdateRanksPolicies, len(plan.Policies))
	copy(rules, plan.Policies)
	sort.Slice(rules, func(i, j int) bool {
		return rules[i].Rank.ValueInt64() < rules[j].Rank.ValueInt64()
	})
	for _, rule := range rules {
		res, err := r.client.Get(plan.getPath())
		if err != nil {
			resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Failed to retrieve object (GET), got error: %s", err))
			return
		}
		existingData.fromBody(ctx, res)

		// Use the `toBody` function to construct the body from existingData
		body := existingData.toBody(ctx, existingData)

		// Update rank
		body, _ = sjson.Set(body, "rank", rule.Rank.ValueInt64())
		res, err = r.client.Put(plan.getPath()+"/"+url.QueryEscape(rule.Id.ValueString()), body)
		if err != nil {
			resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Failed to configure object (PUT), got error: %s, %s", err, res.String()))
			return
		}
	}
	plan.Id = types.StringValue("")

	tflog.Debug(ctx, fmt.Sprintf("%s: Update finished successfully", plan.Id.ValueString()))

	diags = resp.State.Set(ctx, &plan)
	resp.Diagnostics.Append(diags...)
}

//template:end update

//template:begin delete
func (r *NetworkAccessPolicySetUpdateRanksResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state NetworkAccessPolicySetUpdateRanks

	// Read state
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, fmt.Sprintf("%s: Beginning Delete", state.Id.ValueString()))

	tflog.Debug(ctx, fmt.Sprintf("%s: Delete finished successfully", state.Id.ValueString()))

	resp.State.RemoveResource(ctx)
}

//template:end delete

//template:begin import
//template:end import
