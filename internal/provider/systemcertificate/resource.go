// Copyright 2026 Stegra.
// SPDX-License-Identifier: MPL-2.0

package systemcertificate

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type DeploymentResource struct{ client *client }

func (r *DeploymentResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_system_certificate_deployment"
}
func (r *DeploymentResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{MarkdownDescription: "This resource can manage a System Certificate Deployment. It coordinates Admin and optional shared EAP certificate assignments across all listed ISE nodes, with the live primary administration node last. Omit a node's Admin inputs to leave its Admin role unmanaged. Set its eap flag only when explicitly managing EAP.\n\nRequired CA trust must already be installed on every node; manage trusted certificates separately. The provider reuses its configured credentials and HTTPS transport for the explicitly supplied node IPs. Nodes must belong to the same deployment, use the same credentials, and have API Gateway enabled where certificates are changed.\n\nAdmin certificate changes restart ISE services and a primary PAN change can trigger additional deployment-wide restarts. After a write the resource waits at least 60 seconds for Admin changes and requires three consecutive healthy checks, including the served HTTPS certificate and every node's API/deployment status. This is ordered recovery, not a zero-downtime guarantee.\n\nPrivate keys are write-only and require Terraform 1.11 or later. Increment private_keys_wo_version when the key map changes. Portal transfers require explicit admin_portal_group_tag opt-in; unrelated certificate roles are retained. Reads never export private keys. Destroy relinquishes management and retains installed certificates.", Attributes: map[string]schema.Attribute{
		"id":                   schema.StringAttribute{Computed: true},
		"root_certificate_pem": schema.StringAttribute{Required: true, MarkdownDescription: "Root CA used to verify desired and installed certificates. Root and issuer CAs must already be trusted for Infrastructure on every node; this resource does not import or alter CA trust."},
		"nodes": schema.ListNestedAttribute{Required: true, MarkdownDescription: "All deployment nodes in Admin rollout order; the live primary PAN must be last.", NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
			"hostname": schema.StringAttribute{Required: true}, "address": schema.StringAttribute{Required: true},
			"admin_certificate_pem": schema.StringAttribute{Optional: true, MarkdownDescription: "Omit to leave this node's Admin certificate entirely unmanaged."}, "admin_ca_pem": schema.StringAttribute{Optional: true},
			"admin_portal_group_tag": schema.StringAttribute{Optional: true, MarkdownDescription: "Explicitly transfer Portal with Admin while retaining this existing portal group tag. Omit to leave Portal unmanaged."},
			"eap":                    schema.BoolAttribute{Required: true},
		}}},
		"eap_certificate_pem":     schema.StringAttribute{Optional: true, MarkdownDescription: "Shared EAP certificate. Required with eap_ca_pem when any node enables EAP management."},
		"eap_ca_pem":              schema.StringAttribute{Optional: true, MarkdownDescription: "EAP issuing CA chain. Required only when managing EAP."},
		"private_keys_wo":         schema.MapAttribute{Required: true, Sensitive: true, WriteOnly: true, ElementType: types.StringType, MarkdownDescription: "Private keys keyed by node FQDN, plus eap. Not retained in this resource state; public certificate changes trigger rotation."},
		"private_keys_wo_version": schema.Int64Attribute{Required: true, Validators: []validator.Int64{int64validator.AtLeast(1)}, MarkdownDescription: "Rotation trigger for private_keys_wo. Increment when the write-only key map changes; keys are never stored in state."},
		"timeout_seconds":         schema.Int64Attribute{Optional: true, Computed: true, Default: int64default.StaticInt64(1800), Validators: []validator.Int64{int64validator.Between(120, 7200)}},
		"active_fingerprints":     schema.MapAttribute{Computed: true, ElementType: types.StringType, MarkdownDescription: "Observed SHA256 fingerprint keyed by node FQDN/admin or /eap."},
		"in_sync":                 schema.BoolAttribute{Computed: true, MarkdownDescription: "Whether live role assignments, certificate identities, managed CA trust and Admin TLS endpoints satisfy the desired configuration."},
	}}
}

// A refreshed computed output alone does not schedule an update. Explicitly
// plan in_sync=true when refresh found drift, so Update reconciles live roles.
func (r *DeploymentResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.State.Raw.IsNull() || req.Plan.Raw.IsNull() {
		return
	}
	var state deploymentModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if !resp.Diagnostics.HasError() && !state.InSync.IsNull() && !state.InSync.IsUnknown() && !state.InSync.ValueBool() {
		resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("in_sync"), true)...)
		resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("active_fingerprints"), types.MapUnknown(types.StringType))...)
	}
}
func (r *DeploymentResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var model, config deploymentModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &model)...)
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	r.reconcile(ctx, &model, config, &resp.Diagnostics)
	if !model.ID.IsNull() && !model.ID.IsUnknown() {
		resp.Diagnostics.Append(resp.State.Set(ctx, &model)...)
	}
}
func (r *DeploymentResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var model, config deploymentModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &model)...)
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	r.reconcile(ctx, &model, config, &resp.Diagnostics)
	if !model.ID.IsNull() && !model.ID.IsUnknown() {
		resp.Diagnostics.Append(resp.State.Set(ctx, &model)...)
	}
}
func (r *DeploymentResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var model deploymentModel
	resp.Diagnostics.Append(req.State.Get(ctx, &model)...)
	if resp.Diagnostics.HasError() {
		return
	}
	rollout, err := r.client.prepare(model, nil)
	if err != nil {
		resp.Diagnostics.AddError("Invalid managed certificate configuration", err.Error())
		return
	}
	active, synced, err := rollout.observe(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Unable to refresh ISE certificates", err.Error())
		return
	}
	model.InSync = types.BoolValue(synced)
	model.Active, _ = types.MapValueFrom(ctx, types.StringType, active)
	model.Keys = types.MapNull(types.StringType)
	resp.Diagnostics.Append(resp.State.Set(ctx, &model)...)
}
func (r *DeploymentResource) Delete(_ context.Context, _ resource.DeleteRequest, resp *resource.DeleteResponse) {
	resp.Diagnostics.AddWarning("Certificates retained in ISE", "Removing this resource only relinquishes management. Active certificates remain installed to avoid a deployment outage.")
}

func validateModel(m deploymentModel) error {
	if len(m.Nodes) == 0 {
		return fmt.Errorf("at least one node is required")
	}
	if m.Timeout.ValueInt64() < 120 || m.Timeout.ValueInt64() > 7200 {
		return fmt.Errorf("timeout_seconds must be between 120 and 7200")
	}
	return nil
}

var _ resource.ResourceWithModifyPlan = (*DeploymentResource)(nil)

// Each operation has its own cancellation-aware recovery deadline, bounded by
// Terraform's parent context. No retry replays a potentially successful write.
func operationContext(ctx context.Context, seconds int64) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, time.Duration(seconds)*time.Second)
}
