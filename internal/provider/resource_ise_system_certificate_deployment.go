// Copyright 2026 Stegra.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"

	"github.com/CiscoDevNet/terraform-provider-ise/internal/provider/systemcertificate"
	"github.com/hashicorp/terraform-plugin-framework/resource"
)

// The coordinator owns the ordered deployment so Terraform parallelism cannot
// restart its nodes concurrently. CA trust is managed by separate resources.
type SystemCertificateDeploymentResource struct {
	systemcertificate.DeploymentResource
}

func NewSystemCertificateDeploymentResource() resource.Resource {
	return &SystemCertificateDeploymentResource{}
}

func (r *SystemCertificateDeploymentResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	data, ok := req.ProviderData.(*IseProviderData)
	if !ok || data.Client == nil {
		resp.Diagnostics.AddError("Invalid provider configuration", "Expected the configured ISE client.")
		return
	}
	if err := r.ConfigureHTTPClient(data.Client.HttpClient, data.Client.Usr, data.Client.Pwd); err != nil {
		resp.Diagnostics.AddError("Invalid provider configuration", err.Error())
	}
}

var _ resource.ResourceWithConfigure = &SystemCertificateDeploymentResource{}
var _ resource.ResourceWithModifyPlan = &SystemCertificateDeploymentResource{}
