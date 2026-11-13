// Copyright 2026 Stegra.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"crypto/rsa"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type systemCertificateNode struct {
	hostname, address string
	admin             *systemCertificateCertificate
	chain             []*systemCertificateCertificate
	eap               bool
	key               *rsa.PrivateKey
	portalGroup       string
}
type systemCertificateRollout struct {
	client    *systemCertificateClient
	root, eap *systemCertificateCertificate
	eapChain  []*systemCertificateCertificate
	eapKey    *rsa.PrivateKey
	nodes     []systemCertificateNode
	cas       []*systemCertificateCertificate
	timeout   int64
}

func (c *systemCertificateClient) prepare(m SystemCertificateDeployment, keys map[string]string) (*systemCertificateRollout, error) {
	if err := systemCertificateValidateModel(m); err != nil {
		return nil, err
	}
	root, err := systemCertificateParseCertificate(m.RootCertificatePem.ValueString())
	if err != nil {
		return nil, err
	}
	if err = systemCertificateValidateCA(root); keys != nil && err != nil {
		return nil, err
	}
	r := &systemCertificateRollout{client: c, root: root, timeout: m.TimeoutSeconds.ValueInt64(), cas: []*systemCertificateCertificate{root}}
	manageEAP := false
	for _, n := range m.Nodes {
		manageEAP = manageEAP || n.Eap.ValueBool()
	}
	if manageEAP {
		r.eap, err = systemCertificateParseCertificate(m.EapCertificatePem.ValueString())
		if err != nil {
			return nil, err
		}
		r.eapChain, err = systemCertificateParseCertificates(m.EapCaPem.ValueString())
		if err != nil {
			return nil, err
		}
		if keys != nil {
			if !systemCertificateVerifies(r.eap, root, r.eapChain) {
				return nil, fmt.Errorf("EAP certificate is expired or does not verify against the managed root/chain")
			}
			r.eapKey, err = systemCertificateParseKey(keys["eap"], r.eap)
			if err != nil {
				return nil, err
			}
		}
	}
	seen := map[string]bool{}
	addresses := map[string]bool{}
	for _, model := range m.Nodes {
		n := systemCertificateNode{hostname: model.Hostname.ValueString(), address: model.Address.ValueString(), eap: model.Eap.ValueBool(), portalGroup: model.AdminPortalGroupTag.ValueString()}
		if seen[strings.ToLower(n.hostname)] || addresses[n.address] {
			return nil, fmt.Errorf("node hostnames and IP addresses must be unique")
		}
		seen[strings.ToLower(n.hostname)], addresses[n.address] = true, true
		if model.AdminCertificatePem.IsNull() != model.AdminCaPem.IsNull() {
			return nil, fmt.Errorf("Admin certificate and CA chain must either both be set or both omitted")
		}
		if model.AdminCertificatePem.IsNull() {
			if n.portalGroup != "" {
				return nil, fmt.Errorf("Portal transfer requires an explicitly managed Admin certificate")
			}
			if err = systemCertificateValidateNodeIdentity(n); err != nil {
				return nil, err
			}
			r.nodes = append(r.nodes, n)
			continue
		}
		n.admin, err = systemCertificateParseCertificate(model.AdminCertificatePem.ValueString())
		if err != nil {
			return nil, err
		}
		n.chain, err = systemCertificateParseCertificates(model.AdminCaPem.ValueString())
		if err != nil {
			return nil, err
		}
		if err = systemCertificateValidateNodeIdentity(n); err != nil {
			return nil, err
		}
		if keys != nil && !systemCertificateVerifies(n.admin, root, n.chain) {
			return nil, fmt.Errorf("%s: Admin certificate is expired or does not verify against the managed root/chain", n.hostname)
		}
		if keys != nil {
			n.key, err = systemCertificateParseKey(keys[n.hostname], n.admin)
			if err != nil {
				return nil, fmt.Errorf("%s: %s", n.hostname, err)
			}
		}
		r.nodes = append(r.nodes, n)
		r.cas = append(r.cas, n.chain...)
	}
	r.cas = append(r.cas, r.eapChain...)
	unique := map[string]bool{}
	var cas []*systemCertificateCertificate
	for _, ca := range r.cas {
		if err := systemCertificateValidateCA(ca); keys != nil && err != nil {
			return nil, err
		}
		if keys != nil && !systemCertificateVerifies(ca, root, r.cas) {
			return nil, fmt.Errorf("issuing CA does not verify against the managed root")
		}
		if !unique[ca.fingerprint] {
			unique[ca.fingerprint] = true
			cas = append(cas, ca)
		}
	}
	r.cas = cas
	return r, nil
}
func (r *systemCertificateRollout) primary() systemCertificateNode { return r.nodes[len(r.nodes)-1] }
func (r *systemCertificateRollout) preflight(ctx context.Context) error {
	deployment, err := systemCertificateCollection[systemCertificateDeploymentNode](ctx, r.client, r.primary().address, "/api/v1/deployment/node")
	if err != nil {
		return err
	}
	supplied := map[string]bool{}
	for _, n := range r.nodes {
		supplied[strings.ToLower(n.hostname)] = true
	}
	if len(deployment) != len(r.nodes) {
		return fmt.Errorf("nodes must include every live deployment node")
	}
	for _, n := range deployment {
		if !supplied[strings.ToLower(n.FQDN)] {
			return fmt.Errorf("nodes must include every live deployment node")
		}
	}
	primaryCount := 0
	for _, n := range deployment {
		for _, role := range n.Roles {
			if role == "PrimaryAdmin" {
				primaryCount++
				if !strings.EqualFold(n.FQDN, r.primary().hostname) {
					return fmt.Errorf("Admin rollout order must end with the live primary administration node")
				}
			}
		}
	}
	if primaryCount != 1 {
		return fmt.Errorf("expected exactly one live primary administration node")
	}
	var gateways []struct {
		Hostname string `json:"hostname"`
		Enabled  bool   `json:"isEnabled"`
	}
	if err := r.client.json(ctx, r.primary().address, "/admin/API/apiGateway/get", "GET", nil, &gateways); err != nil {
		return err
	}
	enabled := map[string]bool{}
	for _, g := range gateways {
		if g.Enabled {
			enabled[strings.ToLower(g.Hostname)] = true
		}
	}
	for _, n := range r.nodes {
		if n.admin == nil && !n.eap {
			continue
		}
		if !enabled[strings.ToLower(systemCertificateShortHostname(n.hostname))] {
			return fmt.Errorf("enable ISE API Gateway on %s before certificate rollout", n.hostname)
		}
		if n.portalGroup != "" {
			items, err := r.client.certificates(ctx, n)
			if err != nil {
				return err
			}
			matching := 0
			for _, item := range items {
				if systemCertificateHasRole(item, "portal") && item.GroupTag == n.portalGroup {
					matching++
				}
			}
			if matching != 1 {
				return fmt.Errorf("%s: expected exactly one existing Portal certificate with the configured group tag before transfer", n.hostname)
			}
		}
	}
	healthy, err := r.healthy(ctx)
	if err != nil {
		return err
	}
	if !healthy {
		return fmt.Errorf("every managed ISE node must be connected and its API reachable before rollout")
	}
	return nil
}
func (r *systemCertificateRollout) healthy(ctx context.Context) (bool, error) {
	deployment, err := systemCertificateCollection[systemCertificateDeploymentNode](ctx, r.client, r.primary().address, "/api/v1/deployment/node")
	if err != nil {
		return false, err
	}
	connected := map[string]bool{}
	for _, n := range deployment {
		if n.Status == "Connected" {
			connected[n.FQDN] = true
		}
	}
	for _, n := range r.nodes {
		if !connected[n.hostname] {
			return false, nil
		}
		if _, err = r.client.certificates(ctx, n); err != nil {
			return false, err
		}
	}
	return true, nil
}
func systemCertificateTrustedForInfrastructure(value string) bool {
	for _, purpose := range strings.Split(value, ",") {
		if strings.TrimSpace(purpose) == "Infrastructure" {
			return true
		}
	}
	return false
}

func systemCertificateTrusted(items []systemCertificateCertificateItem, ca *systemCertificateCertificate) bool {
	for _, item := range items {
		if systemCertificateSystemFingerprintMatches(item.Fingerprint, ca) && systemCertificateTrustedForInfrastructure(item.TrustedFor) {
			return true
		}
	}
	return false
}
func (r *systemCertificateRollout) trustReady(ctx context.Context, ca *systemCertificateCertificate) (bool, error) {
	for _, n := range r.nodes {
		items, err := systemCertificateCollection[systemCertificateCertificateItem](ctx, r.client, n.address, "/api/v1/certs/trusted-certificate")
		if err != nil {
			return false, err
		}
		if !systemCertificateTrusted(items, ca) {
			return false, nil
		}
	}
	return true, nil
}
func (r *systemCertificateRollout) waitForTrust(ctx context.Context, ca *systemCertificateCertificate) error {
	ctx, cancel := systemCertificateOperationContext(ctx, r.timeout)
	defer cancel()
	items, err := systemCertificateCollection[systemCertificateCertificateItem](ctx, r.client, r.primary().address, "/api/v1/certs/trusted-certificate")
	if err != nil {
		return err
	}
	if !systemCertificateTrusted(items, ca) {
		return fmt.Errorf("required CA is absent or lacks Infrastructure trust; manage trusted certificates before system-certificate rollout")
	}
	return r.client.wait(ctx, false, func(ctx context.Context) (bool, error) { return r.trustReady(ctx, ca) })
}
func systemCertificateCurrent(items []systemCertificateCertificateItem, role string) (systemCertificateCertificateItem, bool, error) {
	var found []systemCertificateCertificateItem
	for _, item := range items {
		if systemCertificateHasRole(item, role) {
			found = append(found, item)
		}
	}
	if len(found) > 1 {
		return systemCertificateCertificateItem{}, false, fmt.Errorf("multiple active %s certificates; refusing ambiguous role ownership", role)
	}
	if len(found) == 0 {
		return systemCertificateCertificateItem{}, false, nil
	}
	return found[0], true, nil
}
func (r *systemCertificateRollout) activated(ctx context.Context, n systemCertificateNode, role, fingerprint string) (bool, error) {
	items, err := r.client.certificates(ctx, n)
	if err != nil {
		return false, err
	}
	item, found, err := systemCertificateCurrent(items, role)
	if err != nil || !found {
		return false, err
	}
	installed, err := r.client.export(ctx, n, item)
	if err != nil {
		return false, err
	}
	if installed.fingerprint != fingerprint {
		return false, nil
	}
	if role == "admin" {
		if !systemCertificatePortalAssigned(item, n) {
			return false, nil
		}
		served, err := r.client.servedFingerprint(ctx, n)
		if err != nil {
			return false, err
		}
		return served == fingerprint, nil
	}
	return true, nil
}
func systemCertificatePortalAssigned(item systemCertificateCertificateItem, n systemCertificateNode) bool {
	return n.portalGroup == "" || (systemCertificateHasRole(item, "portal") && item.GroupTag == n.portalGroup)
}
func (r *systemCertificateRollout) assign(ctx context.Context, n systemCertificateNode, role string, desired *systemCertificateCertificate, chain []*systemCertificateCertificate, key *rsa.PrivateKey) error {
	ctx, cancel := systemCertificateOperationContext(ctx, r.timeout)
	defer cancel()
	items, err := r.client.certificates(ctx, n)
	if err != nil {
		return err
	}
	item, found, err := systemCertificateCurrent(items, role)
	if err != nil {
		return err
	}
	if found {
		installed, err := r.client.export(ctx, n, item)
		if err != nil {
			return err
		}
		keep, err := systemCertificatePreferred(installed, desired, r.root, chain)
		if err != nil {
			return fmt.Errorf("%s %s: %s", n.hostname, role, err)
		}
		if keep && (role != "admin" || systemCertificatePortalAssigned(item, n)) {
			active, err := r.activated(ctx, n, role, installed.fingerprint)
			if err == nil && active {
				healthy, err := r.healthy(ctx)
				if err == nil && healthy {
					return nil
				}
			}
			return r.client.wait(ctx, role == "admin", func(ctx context.Context) (bool, error) {
				ok, err := r.activated(ctx, n, role, installed.fingerprint)
				if err != nil || !ok {
					return false, err
				}
				return r.healthy(ctx)
			})
		}
	}
	payload := map[string]any{
		"admin": role == "admin", "eap": role == "eap", "portal": false, "radius": false, "pxgrid": false, "ims": false, "saml": false,
		"allowRoleTransferForSameSubject": false, "allowPortalTagTransferForSameSubject": false, "allowReplacementOfPortalGroupTag": false,
	}
	if role == "admin" && n.portalGroup != "" {
		payload["portal"] = true
		payload["portalGroupTag"] = n.portalGroup
		payload["allowRoleTransferForSameSubject"] = true
		payload["allowPortalTagTransferForSameSubject"] = true
		payload["allowReplacementOfPortalGroupTag"] = true
	}
	matching := ""
	for _, item := range items {
		if systemCertificateSystemFingerprintMatches(item.Fingerprint, desired) {
			if role == "admin" && n.portalGroup != "" && item.GroupTag != "" && item.GroupTag != n.portalGroup {
				return fmt.Errorf("%s: refusing to replace a candidate's different portal group tag", n.hostname)
			}
			if role == "eap" && n.admin == nil && systemCertificateHasRole(item, "admin") {
				return fmt.Errorf("%s: EAP candidate already serves Admin; refusing an Admin-affecting update in EAP-only mode", n.hostname)
			}
			matching = item.ID
			// PUT updates the stored certificate, so preserve any roles it
			// already serves instead of clearing them with false defaults.
			fields := map[string]string{"admin": "Admin", "eap": "EAP Authentication", "portal": "Portal", "radius": "RADIUS DTLS", "pxgrid": "pxGrid", "ims": "ISE Messaging Service", "saml": "SAML"}
			for _, used := range strings.Split(item.UsedBy, ",") {
				used = strings.TrimSpace(used)
				if used == "" || strings.EqualFold(used, "Not in use") {
					continue
				}
				known := false
				for attribute, label := range fields {
					if strings.EqualFold(used, label) {
						payload[attribute] = true
						known = true
						break
					}
				}
				if !known {
					return fmt.Errorf("refusing to update a stored candidate with unsupported certificate roles")
				}
			}
			if item.GroupTag != "" {
				payload["portalGroupTag"] = item.GroupTag
			}
		}
	}
	if matching != "" {
		err = r.client.json(ctx, n.address, "/api/v1/certs/system-certificate/"+url.PathEscape(systemCertificateShortHostname(n.hostname))+"/"+url.PathEscape(matching), "PUT", payload, nil)
	} else {
		if key == nil {
			return fmt.Errorf("missing private key for certificate import")
		}
		encrypted, password, encryptErr := systemCertificateEncryptedKey(key)
		if encryptErr != nil {
			return encryptErr
		}
		payload["name"], payload["data"], payload["privateKeyData"], payload["password"] = "Terraform "+role+" "+desired.fingerprint[:12], desired.pem, encrypted, password
		payload["allowReplacementOfCertificates"], payload["allowOutOfDateCert"], payload["allowSHA1Certificates"] = true, false, false
		payload["allowExtendedValidity"], payload["allowWildCardCertificates"], payload["validateCertificateExtensions"] = false, false, true
		err = r.client.json(ctx, n.address, "/api/v1/certs/system-certificate/import", "POST", payload, nil)
	}
	if err != nil && !systemCertificateRecoverable(err) {
		return err
	}
	return r.client.wait(ctx, role == "admin" || payload["admin"] == true, func(ctx context.Context) (bool, error) {
		ok, err := r.activated(ctx, n, role, desired.fingerprint)
		if err != nil || !ok {
			return false, err
		}
		return r.healthy(ctx)
	})
}
func (r *systemCertificateRollout) run(ctx context.Context) error {
	if err := r.preflight(ctx); err != nil {
		return err
	}
	for _, ca := range r.cas {
		if err := r.waitForTrust(ctx, ca); err != nil {
			return err
		}
	}
	for _, n := range r.nodes {
		if n.eap && n.admin == nil {
			if err := r.assign(ctx, n, "eap", r.eap, r.eapChain, r.eapKey); err != nil {
				return err
			}
		}
	}
	for _, n := range r.nodes {
		if n.admin == nil {
			continue
		}
		// A stored EAP candidate may already serve Admin. Keep any resulting
		// Admin-affecting write in the ordered node phase, with primary last.
		if n.eap {
			if err := r.assign(ctx, n, "eap", r.eap, r.eapChain, r.eapKey); err != nil {
				return err
			}
		}
		if err := r.assign(ctx, n, "admin", n.admin, n.chain, n.key); err != nil {
			return err
		}
	}
	return nil
}
func (r *systemCertificateRollout) observe(ctx context.Context) (map[string]string, bool, error) {
	active := map[string]string{}
	synced := true
	for _, ca := range r.cas {
		if systemCertificateValidateCA(ca) != nil {
			synced = false
		}
		ready, err := r.trustReady(ctx, ca)
		if err != nil {
			return nil, false, err
		}
		synced = synced && ready
	}
	for _, n := range r.nodes {
		items, err := r.client.certificates(ctx, n)
		if err != nil {
			return nil, false, err
		}
		roles := []string{}
		if n.admin != nil {
			roles = append(roles, "admin")
		}
		if n.eap {
			roles = append(roles, "eap")
		}
		for _, role := range roles {
			item, found, err := systemCertificateCurrent(items, role)
			if err != nil {
				return nil, false, err
			}
			if !found {
				synced = false
				continue
			}
			installed, err := r.client.export(ctx, n, item)
			if err != nil {
				return nil, false, err
			}
			active[n.hostname+"/"+role] = installed.fingerprint
			desired, chain := n.admin, n.chain
			if role == "eap" {
				desired, chain = r.eap, r.eapChain
			}
			keep, err := systemCertificatePreferred(installed, desired, r.root, chain)
			if err != nil {
				return nil, false, fmt.Errorf("%s %s: %s", n.hostname, role, err)
			}
			if !keep {
				synced = false
			}
			if role == "admin" {
				synced = synced && systemCertificatePortalAssigned(item, n)
				served, err := r.client.servedFingerprint(ctx, n)
				if err != nil {
					return nil, false, err
				}
				synced = synced && served == installed.fingerprint
			}
		}
	}
	return active, synced, nil
}
func (r *systemCertificateCoordinator) reconcile(ctx context.Context, m *SystemCertificateDeployment, config SystemCertificateDeployment, diagnostics *diag.Diagnostics) {
	keys := map[string]string{}
	diagnostics.Append(config.PrivateKeysWo.ElementsAs(ctx, &keys, false)...)
	if diagnostics.HasError() {
		return
	}
	rollout, err := r.client.prepare(*m, keys)
	if err != nil {
		diagnostics.AddError("Invalid ISE certificate inputs", err.Error())
		return
	}
	m.Id = types.StringValue(rollout.primary().hostname)
	m.PrivateKeysWo = types.MapNull(types.StringType)
	m.InSync = types.BoolValue(false)
	m.ActiveFingerprints = types.MapNull(types.StringType)
	if err := rollout.run(ctx); err != nil {
		diagnostics.AddError("ISE certificate rollout stopped", err.Error())
		return
	}
	active, synced, err := rollout.observe(ctx)
	if err != nil {
		diagnostics.AddError("Unable to verify ISE certificate rollout", err.Error())
		return
	}
	if !synced {
		diagnostics.AddError("ISE certificates not synchronized", "Observed certificates and CA trust do not satisfy the desired configuration; inspect ISE before retrying.")
		return
	}
	m.ActiveFingerprints, _ = types.MapValueFrom(ctx, types.StringType, active)
	m.InSync = types.BoolValue(true)
}
