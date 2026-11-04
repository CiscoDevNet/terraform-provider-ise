// Copyright 2026 Stegra.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/resource"
)

// Generated schema/model/configuration are shared with the normal resources.
// Assignment and recovery stay coordinated instead of using generic REST CRUD.
func (r *SystemCertificateDeploymentResource) coordinator() (*systemCertificateCoordinator, error) {
	if r.client == nil {
		return nil, fmt.Errorf("expected the configured ISE client")
	}
	c := &systemCertificateCoordinator{}
	if err := c.ConfigureHTTPClient(r.client.HttpClient, r.client.Usr, r.client.Pwd); err != nil {
		return nil, err
	}
	return c, nil
}
func (r *SystemCertificateDeploymentResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	c, err := r.coordinator()
	if err != nil {
		resp.Diagnostics.AddError("Invalid provider configuration", err.Error())
		return
	}
	c.Create(ctx, req, resp)
}
func (r *SystemCertificateDeploymentResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	c, err := r.coordinator()
	if err != nil {
		resp.Diagnostics.AddError("Invalid provider configuration", err.Error())
		return
	}
	c.Read(ctx, req, resp)
}
func (r *SystemCertificateDeploymentResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	c, err := r.coordinator()
	if err != nil {
		resp.Diagnostics.AddError("Invalid provider configuration", err.Error())
		return
	}
	c.Update(ctx, req, resp)
}
func (r *SystemCertificateDeploymentResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	(&systemCertificateCoordinator{}).Delete(ctx, req, resp)
}
func (r *SystemCertificateDeploymentResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	(&systemCertificateCoordinator{}).ModifyPlan(ctx, req, resp)
}

var _ resource.ResourceWithModifyPlan = &SystemCertificateDeploymentResource{}
