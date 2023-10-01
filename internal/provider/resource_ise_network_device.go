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

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/netascode/go-ise"
	"github.com/netascode/terraform-provider-ise/internal/provider/helpers"
)

// Ensure provider defined types fully satisfy framework interfaces
var _ resource.Resource = &NetworkDeviceResource{}
var _ resource.ResourceWithImportState = &NetworkDeviceResource{}

func NewNetworkDeviceResource() resource.Resource {
	return &NetworkDeviceResource{}
}

type NetworkDeviceResource struct {
	client *ise.Client
}

func (r *NetworkDeviceResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_network_device"
}

func (r *NetworkDeviceResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		// This description is used by the documentation generator and the language server.
		MarkdownDescription: helpers.NewAttributeDescription("This resource can manage a Network Device.").String,

		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "The id of the object",
				Computed:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("The name of the network device").String,
				Required:            true,
			},
			"description": schema.StringAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("Description").String,
				Optional:            true,
			},
			"authentication_enable_key_wrap": schema.BoolAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("Enable key wrap").String,
				Optional:            true,
			},
			"authentication_encryption_key": schema.StringAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("Encryption key").String,
				Optional:            true,
			},
			"authentication_encryption_key_format": schema.StringAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("Key input format").AddStringEnumDescription("ASCII", "HEXADECIMAL").String,
				Optional:            true,
				Validators: []validator.String{
					stringvalidator.OneOf("ASCII", "HEXADECIMAL"),
				},
			},
			"authentication_message_authenticator_code_key": schema.StringAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("Message authenticator code key").String,
				Optional:            true,
			},
			"authentication_network_protocol": schema.StringAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("Network protocol").AddStringEnumDescription("RADIUS", "TACACS_PLUS").String,
				Optional:            true,
				Validators: []validator.String{
					stringvalidator.OneOf("RADIUS", "TACACS_PLUS"),
				},
			},
			"authentication_radius_shared_secret": schema.StringAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("RADIUS shared secret").String,
				Optional:            true,
			},
			"authentication_enable_multi_secret": schema.BoolAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("Enable multiple RADIUS shared secrets").String,
				Optional:            true,
			},
			"authentication_second_radius_shared_secret": schema.StringAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("Second RADIUS shared secret").String,
				Optional:            true,
			},
			"authentication_dtls_required": schema.BoolAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("Enforce use of DTLS").String,
				Optional:            true,
			},
			"coa_port": schema.Int64Attribute{
				MarkdownDescription: helpers.NewAttributeDescription("CoA port").String,
				Optional:            true,
			},
			"dtls_dns_name": schema.StringAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("This value is used to verify the client identity contained in the X.509 RADIUS/DTLS client certificate").String,
				Optional:            true,
			},
			"ips": schema.ListNestedAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("List of IP subnets").String,
				Required:            true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"ipaddress": schema.StringAttribute{
							MarkdownDescription: helpers.NewAttributeDescription("It can be either single ip address or ip range address").String,
							Optional:            true,
						},
						"ipaddress_exclude": schema.StringAttribute{
							MarkdownDescription: helpers.NewAttributeDescription("It can be either single ip address or ip range address").String,
							Optional:            true,
						},
						"mask": schema.StringAttribute{
							MarkdownDescription: helpers.NewAttributeDescription("Subnet mask length").String,
							Optional:            true,
						},
					},
				},
			},
			"network_device_groups": schema.ListAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("List of network device groups, e.g. `Device Type#All Device Types#ACCESS`").String,
				ElementType:         types.StringType,
				Optional:            true,
			},
			"model_name": schema.StringAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("Model name").String,
				Optional:            true,
			},
			"software_version": schema.StringAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("Software version").String,
				Optional:            true,
			},
			"profile_name": schema.StringAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("Profile name").String,
				Optional:            true,
			},
			"snmp_link_trap_query": schema.BoolAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("SNMP link Trap Query").String,
				Optional:            true,
			},
			"snmp_mac_trap_query": schema.BoolAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("SNMP MAC Trap Query").String,
				Optional:            true,
			},
			"snmp_originating_policy_service_node": schema.StringAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("Originating Policy Services Node").String,
				Optional:            true,
			},
			"snmp_polling_interval": schema.Int64Attribute{
				MarkdownDescription: helpers.NewAttributeDescription("SNMP Polling Interval in seconds").AddIntegerRangeDescription(600, 86400).String,
				Optional:            true,
				Validators: []validator.Int64{
					int64validator.Between(600, 86400),
				},
			},
			"snmp_ro_community": schema.StringAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("SNMP RO Community").String,
				Optional:            true,
			},
			"snmp_version": schema.StringAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("SNMP version").AddStringEnumDescription("ONE", "TWO_C", "THREE").String,
				Optional:            true,
				Validators: []validator.String{
					stringvalidator.OneOf("ONE", "TWO_C", "THREE"),
				},
			},
			"tacacs_connect_mode_options": schema.StringAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("Connect mode options").AddStringEnumDescription("OFF", "ON_LEGACY", "ON_DRAFT_COMPLIANT").String,
				Optional:            true,
				Validators: []validator.String{
					stringvalidator.OneOf("OFF", "ON_LEGACY", "ON_DRAFT_COMPLIANT"),
				},
			},
			"tacacs_shared_secret": schema.StringAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("Shared secret").String,
				Optional:            true,
			},
			"trustsec_device_id": schema.StringAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("TrustSec device ID").String,
				Optional:            true,
			},
			"trustsec_device_password": schema.StringAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("TrustSec device password").String,
				Optional:            true,
			},
			"trustsec_rest_api_username": schema.StringAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("REST API username").String,
				Optional:            true,
			},
			"trustsec_rest_api_password": schema.StringAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("REST API password").String,
				Optional:            true,
			},
			"trustsec_enable_mode_password": schema.StringAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("Enable mode password").String,
				Optional:            true,
			},
			"trustsec_exec_mode_password": schema.StringAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("EXEC mode password").String,
				Optional:            true,
			},
			"trustsec_exec_mode_username": schema.StringAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("EXEC mode username").String,
				Optional:            true,
			},
			"trustsec_include_when_deploying_sgt_updates": schema.BoolAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("Include this device when deploying Security Group Tag Mapping Updates").String,
				Optional:            true,
			},
			"trustsec_download_enviroment_data_every_x_seconds": schema.Int64Attribute{
				MarkdownDescription: helpers.NewAttributeDescription("Download environment data every X seconds").String,
				Optional:            true,
			},
			"trustsec_download_peer_authorization_policy_every_x_seconds": schema.Int64Attribute{
				MarkdownDescription: helpers.NewAttributeDescription("Download peer authorization policy every X seconds").String,
				Optional:            true,
			},
			"trustsec_download_sgacl_lists_every_x_seconds": schema.Int64Attribute{
				MarkdownDescription: helpers.NewAttributeDescription("Download SGACL lists every X seconds").String,
				Optional:            true,
			},
			"trustsec_other_sga_devices_to_trust_this_device": schema.BoolAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("Other TrustSec devices to trust this device").String,
				Optional:            true,
			},
			"trustsec_re_authentication_every_x_seconds": schema.Int64Attribute{
				MarkdownDescription: helpers.NewAttributeDescription("Re-authenticate every X seconds").String,
				Optional:            true,
			},
			"trustsec_send_configuration_to_device": schema.BoolAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("Send configuration to device").String,
				Optional:            true,
			},
			"trustsec_send_configuration_to_device_using": schema.StringAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("Send configuration to device using").AddStringEnumDescription("DISABLE_ALL", "ENABLE_USING_CLI", "ENABLE_USING_COA").String,
				Optional:            true,
				Validators: []validator.String{
					stringvalidator.OneOf("DISABLE_ALL", "ENABLE_USING_CLI", "ENABLE_USING_COA"),
				},
			},
			"trustsec_coa_source_host": schema.StringAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("CoA source host").String,
				Optional:            true,
			},
		},
	}
}

func (r *NetworkDeviceResource) Configure(_ context.Context, req resource.ConfigureRequest, _ *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	r.client = req.ProviderData.(*IseProviderData).Client
}

func (r *NetworkDeviceResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan NetworkDevice

	// Read plan
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, fmt.Sprintf("%s: Beginning Create", plan.Id.ValueString()))

	// Create object
	body := plan.toBody(ctx, NetworkDevice{})
	res, location, err := r.client.Post(plan.getPath(), body)
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Failed to configure object (POST), got error: %s, %s", err, res.String()))
		return
	}
	locationElements := strings.Split(location, "/")
	plan.Id = types.StringValue(locationElements[len(locationElements)-1])

	tflog.Debug(ctx, fmt.Sprintf("%s: Create finished successfully", plan.Id.ValueString()))

	diags = resp.State.Set(ctx, &plan)
	resp.Diagnostics.Append(diags...)
}

func (r *NetworkDeviceResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state NetworkDevice

	// Read state
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, fmt.Sprintf("%s: Beginning Read", state.Id.String()))

	res, err := r.client.Get(state.getPath() + "/" + state.Id.ValueString())
	if err != nil && strings.Contains(err.Error(), "StatusCode 404") {
		resp.State.RemoveResource(ctx)
		return
	} else if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Failed to retrieve object (GET), got error: %s, %s", err, res.String()))
		return
	}

	state.updateFromBody(ctx, res)

	tflog.Debug(ctx, fmt.Sprintf("%s: Read finished successfully", state.Id.ValueString()))

	diags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
}

func (r *NetworkDeviceResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state NetworkDevice

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

	body := plan.toBody(ctx, state)

	res, err := r.client.Put(plan.getPath()+"/"+plan.Id.ValueString(), body)
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Failed to configure object (PUT), got error: %s, %s", err, res.String()))
		return
	}

	tflog.Debug(ctx, fmt.Sprintf("%s: Update finished successfully", plan.Id.ValueString()))

	diags = resp.State.Set(ctx, &plan)
	resp.Diagnostics.Append(diags...)
}

func (r *NetworkDeviceResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state NetworkDevice

	// Read state
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, fmt.Sprintf("%s: Beginning Delete", state.Id.ValueString()))
	res, err := r.client.Delete(state.getPath() + "/" + state.Id.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Failed to delete object (DELETE), got error: %s, %s", err, res.String()))
		return
	}

	tflog.Debug(ctx, fmt.Sprintf("%s: Delete finished successfully", state.Id.ValueString()))

	resp.State.RemoveResource(ctx)
}

func (r *NetworkDeviceResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
