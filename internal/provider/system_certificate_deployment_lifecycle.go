// Copyright 2026 Stegra.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type systemCertificateCoordinator struct{ client *systemCertificateClient }

// A refreshed computed output alone does not schedule an update. Explicitly
// plan in_sync=true when refresh found drift, so Update reconciles live roles.
func (r *systemCertificateCoordinator) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.State.Raw.IsNull() || req.Plan.Raw.IsNull() {
		return
	}
	var state SystemCertificateDeployment
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if !resp.Diagnostics.HasError() && !state.InSync.IsNull() && !state.InSync.IsUnknown() && !state.InSync.ValueBool() {
		resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("in_sync"), true)...)
		resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("active_fingerprints"), types.MapUnknown(types.StringType))...)
	}
}
func (r *systemCertificateCoordinator) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var model, config SystemCertificateDeployment
	resp.Diagnostics.Append(req.Plan.Get(ctx, &model)...)
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	r.reconcile(ctx, &model, config, &resp.Diagnostics)
	if !model.Id.IsNull() && !model.Id.IsUnknown() {
		resp.Diagnostics.Append(resp.State.Set(ctx, &model)...)
	}
}
func (r *systemCertificateCoordinator) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var model, config SystemCertificateDeployment
	resp.Diagnostics.Append(req.Plan.Get(ctx, &model)...)
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	r.reconcile(ctx, &model, config, &resp.Diagnostics)
	if !model.Id.IsNull() && !model.Id.IsUnknown() {
		resp.Diagnostics.Append(resp.State.Set(ctx, &model)...)
	}
}
func (r *systemCertificateCoordinator) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var model SystemCertificateDeployment
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
	model.ActiveFingerprints, _ = types.MapValueFrom(ctx, types.StringType, active)
	model.PrivateKeysWo = types.MapNull(types.StringType)
	resp.Diagnostics.Append(resp.State.Set(ctx, &model)...)
}
func (r *systemCertificateCoordinator) Delete(_ context.Context, _ resource.DeleteRequest, resp *resource.DeleteResponse) {
	resp.Diagnostics.AddWarning("Certificates retained in ISE", "Removing this resource only relinquishes management. Active certificates remain installed to avoid a deployment outage.")
}

func systemCertificateValidateModel(m SystemCertificateDeployment) error {
	if len(m.Nodes) == 0 {
		return fmt.Errorf("at least one node is required")
	}
	if m.TimeoutSeconds.ValueInt64() < 120 || m.TimeoutSeconds.ValueInt64() > 7200 {
		return fmt.Errorf("timeout_seconds must be between 120 and 7200")
	}
	return nil
}

// Each operation has its own cancellation-aware recovery deadline, bounded by
// Terraform's parent context. No retry replays a potentially successful write.
func systemCertificateOperationContext(ctx context.Context, seconds int64) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, time.Duration(seconds)*time.Second)
}
