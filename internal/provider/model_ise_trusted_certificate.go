// Copyright 2026 Stegra.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"github.com/CiscoDevNet/terraform-provider-ise/internal/provider/helpers"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type TrustedCertificate struct {
	Id                                types.String                `tfsdk:"id"`
	Name                              types.String                `tfsdk:"name"`
	Description                       types.String                `tfsdk:"description"`
	CertificatePem                    helpers.CertificatePEMValue `tfsdk:"certificate_pem"`
	Sha256Fingerprint                 types.String                `tfsdk:"sha256_fingerprint"`
	TrustForIseAuth                   types.Bool                  `tfsdk:"trust_for_ise_auth"`
	TrustForClientAuth                types.Bool                  `tfsdk:"trust_for_client_auth"`
	TrustForCertificateBasedAdminAuth types.Bool                  `tfsdk:"trust_for_certificate_based_admin_auth"`
	TrustForCiscoServicesAuth         types.Bool                  `tfsdk:"trust_for_cisco_services_auth"`
	RetainOnDestroy                   types.Bool                  `tfsdk:"retain_on_destroy"`
	CreateTimeoutSeconds              types.Int64                 `tfsdk:"create_timeout_seconds"`
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

func (m TrustedCertificate) toBody() map[string]any {
	return map[string]any{
		"name":                              m.Name.ValueString(),
		"description":                       m.Description.ValueString(),
		"trustForIseAuth":                   m.TrustForIseAuth.ValueBool(),
		"trustForClientAuth":                m.TrustForClientAuth.ValueBool(),
		"trustForCertificateBasedAdminAuth": m.TrustForCertificateBasedAdminAuth.ValueBool(),
		"trustForCiscoServicesAuth":         m.TrustForCiscoServicesAuth.ValueBool(),
	}
}
