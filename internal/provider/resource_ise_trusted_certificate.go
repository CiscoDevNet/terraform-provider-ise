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
	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource                   = &TrustedCertificateResource{}
	_ resource.ResourceWithConfigure      = &TrustedCertificateResource{}
	_ resource.ResourceWithImportState    = &TrustedCertificateResource{}
	_ resource.ResourceWithValidateConfig = &TrustedCertificateResource{}
)

func NewTrustedCertificateResource() resource.Resource {
	return &TrustedCertificateResource{}
}

type TrustedCertificateResource struct {
	client certificateClient
}

func (*TrustedCertificateResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_trusted_certificate"
}

func (r *TrustedCertificateResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	boolean := func(description string) schema.BoolAttribute {
		return schema.BoolAttribute{
			MarkdownDescription: helpers.NewAttributeDescription(description).AddDefaultValueDescription("false").String,
			Optional:            true,
			Computed:            true,
			Default:             booldefault.StaticBool(false),
		}
	}
	resp.Schema = schema.Schema{
		MarkdownDescription: helpers.NewAttributeDescription("This resource can manage a Trusted Certificate. Configure the provider against the primary administration node. Certificate identity is immutable. Existing certificates must be explicitly imported by ID before Terraform can manage them. Certificates are retained on destroy by default. Unmanaged CRL, OCSP and status settings are preserved on update. Updates are refused when ISE reports additional, unsupported trust purposes.").String,
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "The id of the object",
				Computed:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"name": schema.StringAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("Friendly name of the trusted certificate.").String,
				Required:            true,
				Validators:          []validator.String{stringvalidator.LengthAtLeast(1)},
			},
			"description": schema.StringAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("Description of the trusted certificate.").String,
				Optional:            true,
			},
			"certificate_pem": schema.StringAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("Exactly one PEM-encoded CA certificate. Equivalent PEM formatting is compared by DER identity.").String,
				Required:            true,
				CustomType:          helpers.CertificatePEMType{},
				PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplaceIf(requiresCertificateReplacement, "Replace when certificate DER identity changes.", "Replace when certificate DER identity changes.")},
			},
			"sha256_fingerprint": schema.StringAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("Canonical SHA-256 fingerprint of the certificate DER.").String,
				Computed:            true,
			},
			"trust_for_ise_auth":                     boolean("Trust for authentication within ISE (Infrastructure)."),
			"trust_for_client_auth":                  boolean("Trust for client authentication and syslog (Endpoints)."),
			"trust_for_certificate_based_admin_auth": boolean("Trust for certificate-based administrator authentication (AdminAuth)."),
			"trust_for_cisco_services_auth":          boolean("Trust for authentication of Cisco services."),
			"retain_on_destroy": schema.BoolAttribute{
				MarkdownDescription: helpers.NewAttributeDescription("Retain the live CA certificate when removing this resource. Set false explicitly to delete the certificate from ISE.").AddDefaultValueDescription("true").String,
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(true),
			},
			"create_timeout_seconds": schema.Int64Attribute{
				MarkdownDescription: helpers.NewAttributeDescription("Maximum time in seconds to discover and verify an imported certificate, including recovery after an interrupted import.").AddDefaultValueDescription("120").AddIntegerRangeDescription(10, 3600).String,
				Optional:            true,
				Computed:            true,
				Default:             int64default.StaticInt64(120),
				Validators:          []validator.Int64{int64validator.Between(10, 3600)},
			},
		},
	}
}

func requiresCertificateReplacement(ctx context.Context, req planmodifier.StringRequest, resp *stringplanmodifier.RequiresReplaceIfFuncResponse) {
	if req.StateValue.IsNull() || req.PlanValue.IsUnknown() {
		return
	}
	before, beforeErr := helpers.ParseCertificatePEM(req.StateValue.ValueString())
	after, afterErr := helpers.ParseCertificatePEM(req.PlanValue.ValueString())
	resp.RequiresReplace = beforeErr != nil || afterErr != nil || certificateFingerprint(before) != certificateFingerprint(after)
}

func (r *TrustedCertificateResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	data, ok := req.ProviderData.(*IseProviderData)
	if !ok || data.Client == nil {
		resp.Diagnostics.AddError("Invalid provider configuration", "Expected the configured ISE client.")
		return
	}
	r.client = certificateClient{client: data.Client}
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
	items, err := r.client.list(ctx)
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
	item, _, err := r.client.detail(ctx, model.Id.ValueString())
	if err != nil {
		return err
	}
	encoded, cert, err := r.client.export(ctx, item)
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
		model.CertificatePem = helpers.NewCertificatePEMValue(encoded)
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
	body := model.toBody()
	body["data"] = model.CertificatePem.ValueString()
	body["allowOutOfDateCert"] = false
	body["allowSHA1Certificates"] = false
	body["allowBasicConstraintCAFalse"] = false
	body["validateCertificateExtensions"] = true
	response, writeErr := r.client.request(ctx, http.MethodPost, trustedCertificatePath+"/import", body)
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
	item, current, err := r.client.detail(ctx, model.Id.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Unable to inspect trusted certificate", err.Error())
		return
	}
	if _, known := trustedPurposes(item.TrustedFor); !known {
		resp.Diagnostics.AddError("Unsupported certificate trust purposes", "Refusing to modify a certificate with additional trust purposes that this resource cannot preserve.")
		return
	}
	_, actual, err := r.client.export(ctx, item)
	if err != nil {
		resp.Diagnostics.AddError("Unable to verify trusted certificate", err.Error())
		return
	}
	expected, err := helpers.ParseCertificatePEM(model.CertificatePem.ValueString())
	if err != nil || certificateFingerprint(expected) != certificateFingerprint(actual) {
		resp.Diagnostics.AddError("Certificate identity changed", "Refusing to modify a different certificate at the stored ID.")
		return
	}
	body := model.toBody()
	if err := preserveTrustedCertificateSettings(body, current); err != nil {
		resp.Diagnostics.AddError("Unable to preserve trusted certificate settings", err.Error())
		return
	}
	response, err := r.client.request(ctx, http.MethodPut, trustedCertificatePath+"/"+url.PathEscape(model.Id.ValueString()), body)
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
	item, _, err := r.client.detail(ctx, model.Id.ValueString())
	if certificateNotFound(err) {
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Unable to inspect trusted certificate", err.Error())
		return
	}
	_, actual, err := r.client.export(ctx, item)
	if err != nil {
		resp.Diagnostics.AddError("Unable to verify trusted certificate", err.Error())
		return
	}
	if certificateFingerprint(actual) != model.Sha256Fingerprint.ValueString() {
		resp.Diagnostics.AddError("Certificate identity changed", "Refusing to delete a different certificate at the stored ID.")
		return
	}
	response, err := r.client.request(ctx, http.MethodDelete, trustedCertificatePath+"/"+url.PathEscape(model.Id.ValueString()), nil)
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

func (*TrustedCertificateResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
