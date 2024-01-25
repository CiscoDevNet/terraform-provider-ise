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
	"strings"

	"github.com/CiscoDevNet/terraform-provider-ise/internal/provider/helpers"
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
)

//template:end imports

//template:begin model

// Ensure provider defined types fully satisfy framework interfaces
var _ resource.Resource = &AllowedProtocolsResource{}
var _ resource.ResourceWithImportState = &AllowedProtocolsResource{}

func NewAllowedProtocolsResource() resource.Resource {
	return &AllowedProtocolsResource{}
}

type AllowedProtocolsResource struct {
	client *ise.Client
}

func (r *AllowedProtocolsResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_allowed_protocols"
}

func (r *AllowedProtocolsResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		// This description is used by the documentation generator and the language server.
		MarkdownDescription: helpers.NewAttributeDescription("This resource can manage an allowed protocols policy element.").String,

		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "The id of the object",
				Computed:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("The name of the allowed protocols").String,
				Required:            true,
			},
			"description": schema.StringAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("Description").String,
				Optional:            true,
			},
			"process_host_lookup": schema.BoolAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("Process host lookup").String,
				Required:            true,
			},
			"allow_pap_ascii": schema.BoolAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("Allow PAP ASCII").String,
				Required:            true,
			},
			"allow_chap": schema.BoolAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("Allow CHAP").String,
				Required:            true,
			},
			"allow_ms_chap_v1": schema.BoolAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("Allow MS CHAP v1").String,
				Required:            true,
			},
			"allow_ms_chap_v2": schema.BoolAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("Allow MS CHAP v2").String,
				Required:            true,
			},
			"allow_eap_md5": schema.BoolAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("Allow EAP MD5").String,
				Required:            true,
			},
			"allow_leap": schema.BoolAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("Allow LEAP").String,
				Required:            true,
			},
			"allow_eap_tls": schema.BoolAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("Allow EAP TLS").String,
				Required:            true,
			},
			"allow_eap_ttls": schema.BoolAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("Allow EAP TTLS").String,
				Required:            true,
			},
			"allow_eap_fast": schema.BoolAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("Allow EAP Fast").String,
				Required:            true,
			},
			"allow_peap": schema.BoolAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("Allow PEAP").String,
				Required:            true,
			},
			"allow_teap": schema.BoolAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("Allow TEAP").String,
				Required:            true,
			},
			"allow_preferred_eap_protocol": schema.BoolAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("Allow preferred EAP protocol").String,
				Required:            true,
			},
			"preferred_eap_protocol": schema.StringAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("Preferred EAP protocol").AddStringEnumDescription("EAP_FAST", "PEAP", "LEAP", "EAP_MD5", "EAP_TLS", "EAP_TTLS", "TEAP").String,
				Optional:            true,
				Validators: []validator.String{
					stringvalidator.OneOf("EAP_FAST", "PEAP", "LEAP", "EAP_MD5", "EAP_TLS", "EAP_TTLS", "TEAP"),
				},
			},
			"eap_tls_l_bit": schema.BoolAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("EAP TLS L-Bit").String,
				Required:            true,
			},
			"allow_weak_ciphers_for_eap": schema.BoolAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("Allow weak ciphers for EAP").String,
				Required:            true,
			},
			"require_message_auth": schema.BoolAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("Require message authentication").String,
				Required:            true,
			},
			"eap_tls_allow_auth_of_expired_certs": schema.BoolAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("Allow authentication of expired certificates").String,
				Optional:            true,
			},
			"eap_tls_enable_stateless_session_resume": schema.BoolAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("Enable stateless session resume").String,
				Optional:            true,
			},
			"eap_tls_session_ticket_ttl": schema.Int64Attribute{
				MarkdownDescription: helpers.NewAttributeDescription("Session ticket TTL. Is required only if `eap_tls_enable_stateless_session_resume` is `true`.").String,
				Optional:            true,
			},
			"eap_tls_session_ticket_ttl_unit": schema.StringAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("Session ticket TTL unit. Is required only if `eap_tls_enable_stateless_session_resume` is `true`.").AddStringEnumDescription("SECONDS", "MINUTES", "HOURS", "DAYS", "WEEKS").String,
				Optional:            true,
				Validators: []validator.String{
					stringvalidator.OneOf("SECONDS", "MINUTES", "HOURS", "DAYS", "WEEKS"),
				},
			},
			"eap_tls_session_ticket_percentage": schema.Int64Attribute{
				MarkdownDescription: helpers.NewAttributeDescription("Session ticket percentage. Is required only if `eap_tls_enable_stateless_session_resume` is `true`.").AddIntegerRangeDescription(1, 100).String,
				Optional:            true,
				Validators: []validator.Int64{
					int64validator.Between(1, 100),
				},
			},
			"peap_allow_peap_eap_ms_chap_v2": schema.BoolAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("Allow PEAP EAP MS CHAP v2").String,
				Optional:            true,
			},
			"peap_allow_peap_eap_ms_chap_v2_pwd_change": schema.BoolAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("Allow PEAP EAP MS CHAP v2 password change. Is required only if `allow_peap_eap_ms_chap_v2` is `true`.").String,
				Optional:            true,
			},
			"peap_allow_peap_eap_ms_chap_v2_pwd_change_retries": schema.Int64Attribute{
				MarkdownDescription: helpers.NewAttributeDescription("Allow PEAP EAP MS CHAP v2 password change retries. Is required only if `allow_peap_eap_ms_chap_v2` is `true`.").AddIntegerRangeDescription(0, 3).String,
				Optional:            true,
				Validators: []validator.Int64{
					int64validator.Between(0, 3),
				},
			},
			"peap_allow_peap_eap_gtc": schema.BoolAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("Allow PEAP EAP GTC").String,
				Optional:            true,
			},
			"peap_allow_peap_eap_gtc_pwd_change": schema.BoolAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("Allow PEAP EAP GTC password change. Is required only if `allow_peap_eap_gtc` is `true`.").String,
				Optional:            true,
			},
			"peap_allow_peap_eap_gtc_pwd_change_retries": schema.Int64Attribute{
				MarkdownDescription: helpers.NewAttributeDescription("PEAP EAP GTC password change retries. Is required only if `allow_peap_eap_gtc` is `true`.").AddIntegerRangeDescription(0, 3).String,
				Optional:            true,
				Validators: []validator.Int64{
					int64validator.Between(0, 3),
				},
			},
			"peap_allow_peap_eap_tls": schema.BoolAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("Allow PEAP EAP TLS").String,
				Optional:            true,
			},
			"peap_allow_peap_eap_tls_auth_of_expired_certs": schema.BoolAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("Allow PEAP EAP TLS authentication of expired certificates. Is required only if `peap_allow_peap_eap_tls` is `true`.").String,
				Optional:            true,
			},
			"require_cryptobinding": schema.BoolAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("Require cryptobinding").String,
				Optional:            true,
			},
			"peap_peap_v0": schema.BoolAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("Allow PEAP v0").String,
				Optional:            true,
			},
			"eap_ttls_pap_ascii": schema.BoolAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("Allow PAP ASCII").String,
				Optional:            true,
			},
			"eap_ttls_chap": schema.BoolAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("Allow CHAP").String,
				Optional:            true,
			},
			"eap_ttls_ms_chap_v1": schema.BoolAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("Allow MS CHAP v1").String,
				Optional:            true,
			},
			"eap_ttls_ms_chap_v2": schema.BoolAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("Allow MS CHAP v2").String,
				Optional:            true,
			},
			"eap_ttls_eap_md5": schema.BoolAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("Allow EAP MD5").String,
				Optional:            true,
			},
			"eap_ttls_eap_ms_chap_v2": schema.BoolAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("Allow EAP MS CHAP v2").String,
				Optional:            true,
			},
			"eap_ttls_eap_ms_chap_v2_pwd_change": schema.BoolAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("Allow EAP MS CHAP v2 password change. Is required only if `eap_ttls_eap_ms_chap_v2` is `true`.").String,
				Optional:            true,
			},
			"eap_ttls_eap_ms_chap_v2_pwd_change_retries": schema.Int64Attribute{
				MarkdownDescription: helpers.NewAttributeDescription("EAP MS CHAP v2 password change retries. Is required only if `eap_ttls_eap_ms_chap_v2` is `true`.").AddIntegerRangeDescription(0, 3).String,
				Optional:            true,
				Validators: []validator.Int64{
					int64validator.Between(0, 3),
				},
			},
			"eap_fast_eap_ms_chap_v2": schema.BoolAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("Allow EAP MS CHAP v2").String,
				Optional:            true,
			},
			"eap_fast_eap_ms_chap_v2_pwd_change": schema.BoolAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("Allow EAP MS CHAP v2 password change. Is required only if `eap_fast_eap_ms_chap_v2` is `true`.").String,
				Optional:            true,
			},
			"eap_fast_eap_ms_chap_v2_pwd_change_retries": schema.Int64Attribute{
				MarkdownDescription: helpers.NewAttributeDescription("EAP MS CHAP v2 password change retries. Is required only if `eap_fast_eap_ms_chap_v2` is `true`.").AddIntegerRangeDescription(0, 3).String,
				Optional:            true,
				Validators: []validator.Int64{
					int64validator.Between(0, 3),
				},
			},
			"eap_fast_eap_gtc": schema.BoolAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("Allow EAP GTC").String,
				Optional:            true,
			},
			"eap_fast_eap_gtc_pwd_change": schema.BoolAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("Allow EAP GTC password change. Is required only if `eap_fast_eap_gtc` is `true`.").String,
				Optional:            true,
			},
			"eap_fast_eap_gtc_pwd_change_retries": schema.Int64Attribute{
				MarkdownDescription: helpers.NewAttributeDescription("EAP GTC password change retries. Is required only if `eap_fast_eap_gtc` is `true`.").AddIntegerRangeDescription(0, 3).String,
				Optional:            true,
				Validators: []validator.Int64{
					int64validator.Between(0, 3),
				},
			},
			"eap_fast_eap_tls": schema.BoolAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("Allow EAP TLS").String,
				Optional:            true,
			},
			"eap_fast_eap_tls_auth_of_expired_certs": schema.BoolAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("Allow EAP TLS authentication of expired certificates. Is required only if `eap_fast_eap_tls` is `true`.").String,
				Optional:            true,
			},
			"eap_fast_enable_eap_chaining": schema.BoolAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("Enable EAP chaining").String,
				Optional:            true,
			},
			"eap_fast_use_pacs": schema.BoolAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("Use PACs").String,
				Optional:            true,
			},
			"eap_fast_pacs_tunnel_pac_ttl": schema.Int64Attribute{
				MarkdownDescription: helpers.NewAttributeDescription("PACs tunnel PAC time to live. Is required only if `eap_fast_use_pacs` is `true`.").String,
				Optional:            true,
			},
			"eap_fast_pacs_tunnel_pac_ttl_unit": schema.StringAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("PACs tunnel PAC time to live unit. Is required only if `eap_fast_use_pacs` is `true`.").AddStringEnumDescription("SECONDS", "MINUTES", "HOURS", "DAYS", "WEEKS").String,
				Optional:            true,
				Validators: []validator.String{
					stringvalidator.OneOf("SECONDS", "MINUTES", "HOURS", "DAYS", "WEEKS"),
				},
			},
			"eap_fast_pacs_use_proactive_pac_update_percentage": schema.Int64Attribute{
				MarkdownDescription: helpers.NewAttributeDescription("Use proactive pac update percentage. Is required only if `eap_fast_use_pacs` is `true`.").AddIntegerRangeDescription(1, 100).String,
				Optional:            true,
				Validators: []validator.Int64{
					int64validator.Between(1, 100),
				},
			},
			"eap_fast_pacs_allow_anonymous_provisioning": schema.BoolAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("Allow anonymous provisioning. Is required only if `eap_fast_use_pacs` is `true`.").String,
				Optional:            true,
			},
			"eap_fast_pacs_allow_authenticated_provisioning": schema.BoolAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("Allow authenticated provisioning. Is required only if `eap_fast_use_pacs` is `true`.").String,
				Optional:            true,
			},
			"eap_fast_pacs_server_returns": schema.BoolAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("Server returns access accept after authenticated provisioning. Is required only if `eap_fast_pacs_allow_authenticated_provisioning` is `true`.").String,
				Optional:            true,
			},
			"eap_fast_pacs_allow_client_cert": schema.BoolAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("Accept client certification for provisioning. Is required only if `eap_fast_pacs_allow_authenticated_provisioning` is `true`.").String,
				Optional:            true,
			},
			"eap_fast_pacs_allow_machine_authentication": schema.BoolAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("Allow machine authentication. Is required only if `eap_fast_use_pacs` is `true`.").String,
				Optional:            true,
			},
			"eap_fast_pacs_machine_pac_ttl": schema.Int64Attribute{
				MarkdownDescription: helpers.NewAttributeDescription("Machine PAC TTL. Is required only if `eap_fast_pacs_allow_machine_authentication` is `true`.").String,
				Optional:            true,
			},
			"eap_fast_pacs_machine_pac_ttl_unit": schema.StringAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("Machine PAC TTL unit. Is required only if `eap_fast_pacs_allow_machine_authentication` is `true`.").AddStringEnumDescription("SECONDS", "MINUTES", "HOURS", "DAYS", "WEEKS").String,
				Optional:            true,
				Validators: []validator.String{
					stringvalidator.OneOf("SECONDS", "MINUTES", "HOURS", "DAYS", "WEEKS"),
				},
			},
			"eap_fast_pacs_stateless_session_resume": schema.BoolAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("Stateless session resume. Is required only if `eap_fast_use_pacs` is `true`.").String,
				Optional:            true,
			},
			"eap_fast_pacs_authorization_pac_ttl": schema.Int64Attribute{
				MarkdownDescription: helpers.NewAttributeDescription("Authorization PAC TTL. Is required only if `eap_fast_pacs_stateless_session_resume` is `true`.").String,
				Optional:            true,
			},
			"eap_fast_pacs_authorization_pac_ttl_unit": schema.StringAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("Authorization PAC TTL unit. Is required only if `eap_fast_pacs_stateless_session_resume` is `true`.").AddStringEnumDescription("SECONDS", "MINUTES", "HOURS", "DAYS", "WEEKS").String,
				Optional:            true,
				Validators: []validator.String{
					stringvalidator.OneOf("SECONDS", "MINUTES", "HOURS", "DAYS", "WEEKS"),
				},
			},
			"eap_fast_accept_client_cert": schema.BoolAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("Accept client certificates. Is required only if `eap_fast_use_pacs` is `false`.").String,
				Optional:            true,
			},
			"eap_fast_allow_machine_authentication": schema.BoolAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("Allow machine authentication. Is required only if `eap_fast_use_pacs` is `false`.").String,
				Optional:            true,
			},
			"teap_eap_ms_chap_v2": schema.BoolAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("Allow EAP MS CHAP v2").String,
				Optional:            true,
			},
			"teap_eap_ms_chap_v2_pwd_change": schema.BoolAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("Allow EAP MS CHAP v2 password change. Is required only if `teap_eap_ms_chap_v2` is `true`.").String,
				Optional:            true,
			},
			"teap_eap_ms_chap_v2_pwd_change_retries": schema.Int64Attribute{
				MarkdownDescription: helpers.NewAttributeDescription("EAP MS CHAP v2 password change retries. Is required only if `teap_eap_ms_chap_v2` is `true`.").AddIntegerRangeDescription(0, 3).String,
				Optional:            true,
				Validators: []validator.Int64{
					int64validator.Between(0, 3),
				},
			},
			"teap_eap_tls": schema.BoolAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("Allow EAP TLS").String,
				Optional:            true,
			},
			"teap_eap_tls_auth_of_expired_certs": schema.BoolAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("Allow EAP TLS authentication of expired certs. Is required only if `teap_eap_tls` is `true`.").String,
				Optional:            true,
			},
			"teap_eap_accept_client_cert_during_tunnel_est": schema.BoolAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("Accept client certificate during tunnel establishment").String,
				Optional:            true,
			},
			"teap_eap_chaining": schema.BoolAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("Allow EAP chaining").String,
				Optional:            true,
			},
			"teap_downgrade_msk": schema.BoolAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("Allow downgrade to MSK").String,
				Optional:            true,
			},
			"teap_request_basic_pwd_auth": schema.BoolAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("Request basic password authentication").String,
				Optional:            true,
			},
			"allow_5g": schema.BoolAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("Allow 5G. This field is only supported from ISE 3.2.").String,
				Optional:            true,
			},
		},
	}
}

func (r *AllowedProtocolsResource) Configure(_ context.Context, req resource.ConfigureRequest, _ *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	r.client = req.ProviderData.(*IseProviderData).Client
}

//template:end model

//template:begin create
func (r *AllowedProtocolsResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan AllowedProtocols

	// Read plan
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, fmt.Sprintf("%s: Beginning Create", plan.Id.ValueString()))

	// Create object
	body := plan.toBody(ctx, AllowedProtocols{})
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

//template:end create

//template:begin read
func (r *AllowedProtocolsResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state AllowedProtocols

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
func (r *AllowedProtocolsResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state AllowedProtocols

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

//template:end update

//template:begin delete
func (r *AllowedProtocolsResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state AllowedProtocols

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

//template:end delete

//template:begin import
func (r *AllowedProtocolsResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

//template:end import
