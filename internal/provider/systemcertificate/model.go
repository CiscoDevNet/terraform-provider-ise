// Copyright 2026 Stegra.
// SPDX-License-Identifier: MPL-2.0

package systemcertificate

import "github.com/hashicorp/terraform-plugin-framework/types"

type nodeModel struct {
	Hostname    types.String `tfsdk:"hostname"`
	Address     types.String `tfsdk:"address"`
	Certificate types.String `tfsdk:"admin_certificate_pem"`
	Chain       types.String `tfsdk:"admin_ca_pem"`
	PortalGroup types.String `tfsdk:"admin_portal_group_tag"`
	EAP         types.Bool   `tfsdk:"eap"`
}
type deploymentModel struct {
	ID             types.String `tfsdk:"id"`
	Root           types.String `tfsdk:"root_certificate_pem"`
	Nodes          []nodeModel  `tfsdk:"nodes"`
	EAPCertificate types.String `tfsdk:"eap_certificate_pem"`
	EAPChain       types.String `tfsdk:"eap_ca_pem"`
	KeysVersion    types.Int64  `tfsdk:"private_keys_wo_version"`
	Keys           types.Map    `tfsdk:"private_keys_wo"`
	Timeout        types.Int64  `tfsdk:"timeout_seconds"`
	Active         types.Map    `tfsdk:"active_fingerprints"`
	InSync         types.Bool   `tfsdk:"in_sync"`
}
