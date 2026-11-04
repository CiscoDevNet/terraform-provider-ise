// Copyright 2026 Stegra.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/CiscoDevNet/terraform-provider-ise/internal/provider/helpers"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ resource.ResourceWithValidateConfig = &TrustedCertificateResource{}
var _ resource.ResourceWithModifyPlan = &TrustedCertificateResource{}

func (r *TrustedCertificateResource) certificateAPI() certificateClient {
	return certificateClient{client: r.client}
}

// PEM formatting is not certificate identity. Only DER changes replace a CA.
func (r *TrustedCertificateResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.State.Raw.IsNull() || req.Plan.Raw.IsNull() {
		return
	}
	var before, after types.String
	resp.Diagnostics.Append(req.State.GetAttribute(ctx, path.Root("certificate_pem"), &before)...)
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("certificate_pem"), &after)...)
	if resp.Diagnostics.HasError() || after.IsUnknown() {
		return
	}
	a, e1 := helpers.ParseCertificatePEM(before.ValueString())
	b, e2 := helpers.ParseCertificatePEM(after.ValueString())
	if e1 != nil || e2 != nil || certificateFingerprint(a) != certificateFingerprint(b) {
		resp.RequiresReplace = append(resp.RequiresReplace, path.Root("certificate_pem"))
	}
}

func (*TrustedCertificateResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var model TrustedCertificate
	resp.Diagnostics.Append(req.Config.Get(ctx, &model)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if !model.CertificatePem.IsUnknown() && !model.CertificatePem.IsNull() {
		cert, err := helpers.ParseCertificatePEM(model.CertificatePem.ValueString())
		if err != nil || !cert.IsCA || !cert.BasicConstraintsValid {
			resp.Diagnostics.AddAttributeError(path.Root("certificate_pem"), "Invalid CA certificate", "Provide exactly one PEM-encoded X.509 certificate with CA basic constraints.")
		}
	}
	for _, flag := range []types.Bool{model.TrustForIseAuth, model.TrustForClientAuth, model.TrustForCertificateBasedAdminAuth, model.TrustForCiscoServicesAuth} {
		if flag.IsUnknown() || flag.ValueBool() {
			return
		}
	}
	resp.Diagnostics.AddError("Missing trust purpose", "Enable at least one trusted certificate authentication purpose.")
}

func trustedPurposes(value string) (map[string]bool, bool) {
	purposes := map[string]bool{}
	known := true
	for _, purpose := range strings.Split(value, ",") {
		purpose = strings.TrimSpace(purpose)
		if purpose == "" {
			continue
		}
		purposes[purpose] = true
		switch purpose {
		case "Infrastructure", "Endpoints", "AdminAuth", "Cisco Services":
		default:
			known = false
		}
	}
	return purposes, known
}

func (r *TrustedCertificateResource) find(ctx context.Context, cert *x509.Certificate) (*trustedCertificateMetadata, error) {
	items, err := r.certificateAPI().list(ctx)
	if err != nil {
		return nil, err
	}
	var found *trustedCertificateMetadata
	for _, item := range items {
		if matchesCertificateFingerprint(item.Fingerprint, cert) {
			if found != nil {
				return nil, fmt.Errorf("multiple trusted certificates match the fingerprint")
			}
			copy := item
			found = &copy
		}
	}
	return found, nil
}

func (r *TrustedCertificateResource) refresh(ctx context.Context, model *TrustedCertificate) error {
	item, _, err := r.certificateAPI().detail(ctx, model.Id.ValueString())
	if err != nil {
		return err
	}
	encoded, cert, err := r.certificateAPI().export(ctx, item)
	if err != nil {
		// Only a missing detail object means the managed resource disappeared.
		// A missing export endpoint must remain a read error.
		return fmt.Errorf("unable to export trusted certificate: %v", err)
	}
	if !model.CertificatePem.IsNull() && !model.CertificatePem.IsUnknown() {
		expected, err := helpers.ParseCertificatePEM(model.CertificatePem.ValueString())
		if err != nil {
			return err
		}
		if certificateFingerprint(expected) != certificateFingerprint(cert) {
			return fmt.Errorf("certificate ID refers to a different certificate; refusing ownership change")
		}
	} else {
		model.CertificatePem = types.StringValue(encoded)
	}
	if !cert.IsCA || !cert.BasicConstraintsValid {
		return fmt.Errorf("trusted certificate is not a CA certificate")
	}
	model.Sha256Fingerprint = types.StringValue(certificateFingerprint(cert))
	model.Name = types.StringValue(item.Name)
	if item.Description != "" || !model.Description.IsNull() {
		model.Description = types.StringValue(item.Description)
	}
	purposes, _ := trustedPurposes(item.TrustedFor)
	model.TrustForIseAuth = types.BoolValue(purposes["Infrastructure"])
	model.TrustForClientAuth = types.BoolValue(purposes["Endpoints"])
	model.TrustForCertificateBasedAdminAuth = types.BoolValue(purposes["AdminAuth"])
	model.TrustForCiscoServicesAuth = types.BoolValue(purposes["Cisco Services"])
	if model.RetainOnDestroy.IsNull() {
		model.RetainOnDestroy = types.BoolValue(true)
	}
	if model.CreateTimeoutSeconds.IsNull() {
		model.CreateTimeoutSeconds = types.Int64Value(120)
	}
	return nil
}

func (r *TrustedCertificateResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var model TrustedCertificate
	resp.Diagnostics.Append(req.Plan.Get(ctx, &model)...)
	if resp.Diagnostics.HasError() {
		return
	}
	cert, err := helpers.ParseCertificatePEM(model.CertificatePem.ValueString())
	if err != nil || !cert.IsCA || !cert.BasicConstraintsValid {
		resp.Diagnostics.AddError("Invalid CA certificate", "Provide one CA certificate.")
		return
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(model.CreateTimeoutSeconds.ValueInt64())*time.Second)
	defer cancel()
	found, err := r.find(ctx, cert)
	if err != nil {
		resp.Diagnostics.AddError("Unable to inspect trusted certificates", err.Error())
		return
	}
	if found != nil {
		resp.Diagnostics.AddError("Trusted certificate already exists", "Import the existing certificate by ID before Terraform can manage or delete it.")
		return
	}
	body := model.requestBody()
	body["data"] = model.CertificatePem.ValueString()
	body["allowOutOfDateCert"] = false
	body["allowSHA1Certificates"] = false
	body["allowBasicConstraintCAFalse"] = false
	body["validateCertificateExtensions"] = true
	response, writeErr := r.certificateAPI().request(ctx, http.MethodPost, trustedCertificatePath+"/import", body)
	if writeErr == nil {
		writeErr = decodeCertificateResponse(response, nil)
	}
	if writeErr != nil {
		var transportErr *certificateTransportError
		var httpErr *certificateHTTPError
		recoverable := errors.As(writeErr, &transportErr) || (errors.As(writeErr, &httpErr) && httpErr.status >= 500)
		if !recoverable {
			resp.Diagnostics.AddError("Unable to import trusted certificate", writeErr.Error())
			return
		}
	}
	// Never repeat POST, even if the response was lost. Recover by identity.
	for {
		found, err = r.find(ctx, cert)
		if err == nil && found != nil {
			model.Id = types.StringValue(found.ID)
			break
		}
		select {
		case <-ctx.Done():
			resp.Diagnostics.AddError("Trusted certificate import not confirmed", "The import response could not be confirmed before timeout or cancellation. Inspect ISE and import any created certificate by ID; do not blindly repeat the import.")
			return
		case <-time.After(time.Second):
		}
	}
	if !model.matches(*found) {
		model.Sha256Fingerprint = types.StringValue(certificateFingerprint(cert))
		resp.Diagnostics.Append(resp.State.Set(ctx, model)...)
		resp.Diagnostics.AddError("Imported certificate settings differ", "ISE returned different managed settings. The certificate identity was retained in state for inspection.")
		return
	}

	model.Sha256Fingerprint = types.StringValue(certificateFingerprint(cert))
	if err := r.refresh(ctx, &model); err != nil {
		resp.Diagnostics.Append(resp.State.Set(ctx, model)...)
		resp.Diagnostics.AddError("Unable to verify trusted certificate", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, model)...)
}

func (r *TrustedCertificateResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var model TrustedCertificate
	resp.Diagnostics.Append(req.State.Get(ctx, &model)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.refresh(ctx, &model); err != nil {
		if certificateNotFound(err) {
			resp.State.RemoveResource(ctx)
		} else {
			resp.Diagnostics.AddError("Unable to read trusted certificate", err.Error())
		}
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, model)...)
}

func (r *TrustedCertificateResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var model, previous TrustedCertificate
	resp.Diagnostics.Append(req.Plan.Get(ctx, &model)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &previous)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if model.Name.Equal(previous.Name) && model.Description.Equal(previous.Description) && model.TrustForIseAuth.Equal(previous.TrustForIseAuth) && model.TrustForClientAuth.Equal(previous.TrustForClientAuth) && model.TrustForCertificateBasedAdminAuth.Equal(previous.TrustForCertificateBasedAdminAuth) && model.TrustForCiscoServicesAuth.Equal(previous.TrustForCiscoServicesAuth) {
		if err := r.refresh(ctx, &model); err != nil {
			resp.Diagnostics.AddError("Unable to verify trusted certificate", err.Error())
			return
		}
		resp.Diagnostics.Append(resp.State.Set(ctx, model)...)
		return
	}
	item, current, err := r.certificateAPI().detail(ctx, model.Id.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Unable to inspect trusted certificate", err.Error())
		return
	}
	if _, known := trustedPurposes(item.TrustedFor); !known {
		resp.Diagnostics.AddError("Unsupported certificate trust purposes", "Refusing to modify a certificate with additional trust purposes that this resource cannot preserve.")
		return
	}
	_, actual, err := r.certificateAPI().export(ctx, item)
	if err != nil {
		resp.Diagnostics.AddError("Unable to verify trusted certificate", err.Error())
		return
	}
	expected, err := helpers.ParseCertificatePEM(model.CertificatePem.ValueString())
	if err != nil || certificateFingerprint(expected) != certificateFingerprint(actual) {
		resp.Diagnostics.AddError("Certificate identity changed", "Refusing to modify a different certificate at the stored ID.")
		return
	}
	body := model.requestBody()
	if err := preserveTrustedCertificateSettings(body, current); err != nil {
		resp.Diagnostics.AddError("Unable to preserve trusted certificate settings", err.Error())
		return
	}
	response, err := r.certificateAPI().request(ctx, http.MethodPut, trustedCertificatePath+"/"+url.PathEscape(model.Id.ValueString()), body)
	if err == nil {
		err = decodeCertificateResponse(response, nil)
	}
	if err != nil {
		resp.Diagnostics.AddError("Unable to update trusted certificate", err.Error())
		return
	}
	if err := r.refresh(ctx, &model); err != nil {
		resp.Diagnostics.AddError("Unable to verify trusted certificate", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, model)...)
}

func (r *TrustedCertificateResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var model TrustedCertificate
	resp.Diagnostics.Append(req.State.Get(ctx, &model)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if model.RetainOnDestroy.IsNull() || model.RetainOnDestroy.ValueBool() {
		resp.Diagnostics.AddWarning("Trusted certificate retained", "Terraform relinquished ownership without deleting the live CA certificate.")
		return
	}
	item, _, err := r.certificateAPI().detail(ctx, model.Id.ValueString())
	if certificateNotFound(err) {
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Unable to inspect trusted certificate", err.Error())
		return
	}
	_, actual, err := r.certificateAPI().export(ctx, item)
	if err != nil {
		resp.Diagnostics.AddError("Unable to verify trusted certificate", err.Error())
		return
	}
	if certificateFingerprint(actual) != model.Sha256Fingerprint.ValueString() {
		resp.Diagnostics.AddError("Certificate identity changed", "Refusing to delete a different certificate at the stored ID.")
		return
	}
	response, err := r.certificateAPI().request(ctx, http.MethodDelete, trustedCertificatePath+"/"+url.PathEscape(model.Id.ValueString()), nil)
	if certificateNotFound(err) {
		return
	}
	if err == nil {
		err = decodeCertificateResponse(response, nil)
	}
	if err != nil {
		resp.Diagnostics.AddError("Unable to delete trusted certificate", err.Error())
	}
}

func (m TrustedCertificate) matches(item trustedCertificateMetadata) bool {
	purposes, known := trustedPurposes(item.TrustedFor)
	return known && item.Name == m.Name.ValueString() &&
		item.Description == m.Description.ValueString() &&
		purposes["Infrastructure"] == m.TrustForIseAuth.ValueBool() &&
		purposes["Endpoints"] == m.TrustForClientAuth.ValueBool() &&
		purposes["AdminAuth"] == m.TrustForCertificateBasedAdminAuth.ValueBool() &&
		purposes["Cisco Services"] == m.TrustForCiscoServicesAuth.ValueBool()
}

func (m TrustedCertificate) requestBody() map[string]any {
	return map[string]any{
		"name":                              m.Name.ValueString(),
		"description":                       m.Description.ValueString(),
		"trustForIseAuth":                   m.TrustForIseAuth.ValueBool(),
		"trustForClientAuth":                m.TrustForClientAuth.ValueBool(),
		"trustForCertificateBasedAdminAuth": m.TrustForCertificateBasedAdminAuth.ValueBool(),
		"trustForCiscoServicesAuth":         m.TrustForCiscoServicesAuth.ValueBool(),
	}
}
