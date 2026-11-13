// Copyright 2026 Stegra.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func systemCertificateNewClient(username, password string, insecure bool) *systemCertificateClient {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: insecure} // Explicit bootstrap opt-in.
	return &systemCertificateClient{
		http: &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsConfig},
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }},
		username: username, password: password, tls: tlsConfig, poll: 10 * time.Second, settle: 60 * time.Second,
	}
}

type systemCertificateFixtures struct {
	root, issuer, desired, old, newer, missing *systemCertificateCertificate
	key, issuerKey                             *rsa.PrivateKey
}

func systemCertificateIssue(t *testing.T, parent *systemCertificateCertificate, parentKey *rsa.PrivateKey, ca bool, days int, sans []string, key *rsa.PrivateKey) *systemCertificateCertificate {
	t.Helper()
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		t.Fatal(err)
	}
	cn := "node.example.test"
	if ca {
		cn = "CA " + serial.String()
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: cn}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Duration(days) * 24 * time.Hour), BasicConstraintsValid: true, IsCA: ca, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, DNSNames: sans, IPAddresses: []net.IP{net.ParseIP("192.0.2.4"), net.ParseIP("192.0.2.5")}}
	if ca {
		template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	}
	parentCert := template
	if parent != nil {
		parentCert = parent.x509
	} else {
		parentKey = key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parentCert, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := systemCertificateParseCertificate(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})))
	if err != nil {
		t.Fatal(err)
	}
	return cert
}
func systemCertificateNewFixtures(t *testing.T) systemCertificateFixtures {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	issuerKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	root := systemCertificateIssue(t, nil, nil, true, 100, nil, rootKey)
	issuer := systemCertificateIssue(t, root, rootKey, true, 90, nil, issuerKey)
	sans := []string{"node.example.test", "alias.example.test", "secondary.example.test", "primary.example.test"}
	return systemCertificateFixtures{root: root, issuer: issuer, key: key, issuerKey: issuerKey,
		desired: systemCertificateIssue(t, issuer, issuerKey, false, 20, sans, key), newer: systemCertificateIssue(t, issuer, issuerKey, false, 40, sans, key),
		missing: systemCertificateIssue(t, issuer, issuerKey, false, 40, []string{"node.example.test"}, key), old: systemCertificateIssue(t, nil, nil, false, 80, sans, key)}
}
func TestSystemCertificateCertificateSafety(t *testing.T) {
	f := systemCertificateNewFixtures(t)
	chain := []*systemCertificateCertificate{f.issuer}
	t.Run("candidate chain verified", func(t *testing.T) {
		if !systemCertificateVerifies(f.desired, f.root, chain) {
			t.Fatal("valid chain refused")
		}
		if systemCertificateVerifies(f.old, f.root, chain) {
			t.Fatal("unmanaged certificate verified")
		}
	})
	for _, test := range []struct {
		name            string
		cert            *systemCertificateCertificate
		keep, wantError bool
	}{
		{"exact", f.desired, true, false}, {"newer managed", f.newer, true, false}, {"newer missing identities", f.missing, false, true}, {"newer unmanaged", f.old, false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			keep, err := systemCertificatePreferred(test.cert, f.desired, f.root, chain)
			if keep != test.keep || (err != nil) != test.wantError {
				t.Fatalf("keep=%v err=%v", keep, err)
			}
		})
	}
	t.Run("wrong key refused", func(t *testing.T) {
		value := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(f.issuerKey)}))
		if _, err := systemCertificateParseKey(value, f.desired); err == nil {
			t.Fatal("wrong key accepted")
		}
	})
	t.Run("encrypted upload decrypts", func(t *testing.T) {
		encoded, password, err := systemCertificateEncryptedKey(f.key)
		if err != nil {
			t.Fatal(err)
		}
		block, _ := pem.Decode([]byte(encoded))
		der, err := x509.DecryptPEMBlock(block, []byte(password))
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := x509.ParsePKCS1PrivateKey(der)
		if err != nil || !parsed.Equal(f.key) {
			t.Fatal("encrypted upload did not retain key")
		}
	})
}

type systemCertificateFakeISE struct {
	t               *testing.T
	fixture         systemCertificateFixtures
	server          *httptest.Server
	client          *systemCertificateClient
	nodes           []systemCertificateNode
	certs           map[string]*systemCertificateCertificate
	trust           map[string]bool
	writes          []string
	enabled         bool
	interrupt       bool
	httpFailure     bool
	stored          bool
	pemFingerprints bool
	unexportable    bool
	portalTag       string
}

func (f *systemCertificateFakeISE) exportedPEM(cert *systemCertificateCertificate) string {
	if f.pemFingerprints {
		return strings.ReplaceAll(cert.pem, "\n", "\r\n")
	}
	return cert.pem
}

func (f *systemCertificateFakeISE) fingerprint(cert *systemCertificateCertificate) string {
	if f.pemFingerprints {
		return fmt.Sprintf("%x", sha256.Sum256([]byte(f.exportedPEM(cert))))
	}
	return cert.fingerprint
}

func systemCertificateNewFakeISE(t *testing.T) *systemCertificateFakeISE {
	f := &systemCertificateFakeISE{t: t, fixture: systemCertificateNewFixtures(t), certs: map[string]*systemCertificateCertificate{}, trust: map[string]bool{}, enabled: true}
	f.server = httptest.NewTLSServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.server.Close)
	f.trust[f.fixture.root.fingerprint] = true
	f.trust[f.fixture.issuer.fingerprint] = true
	f.client = systemCertificateNewClient("test", "test-secret", true)
	f.client.poll = time.Microsecond
	f.client.settle = time.Microsecond
	f.nodes = []systemCertificateNode{{hostname: "secondary.example.test", address: strings.TrimPrefix(f.server.URL, "https://"), admin: f.fixture.desired, chain: []*systemCertificateCertificate{f.fixture.issuer}, key: f.fixture.key, eap: true},
		{hostname: "primary.example.test", address: strings.TrimPrefix(f.server.URL, "https://"), admin: f.fixture.desired, chain: []*systemCertificateCertificate{f.fixture.issuer}, key: f.fixture.key}}
	for _, n := range f.nodes {
		f.certs[systemCertificateShortHostname(n.hostname)+"/admin"] = f.fixture.old
		if n.eap {
			f.certs[systemCertificateShortHostname(n.hostname)+"/eap"] = f.fixture.old
		}
	}
	f.client.probe = func(_ context.Context, n systemCertificateNode) (string, error) {
		return f.certs[systemCertificateShortHostname(n.hostname)+"/admin"].fingerprint, nil
	}
	return f
}
func (f *systemCertificateFakeISE) rollout() *systemCertificateRollout {
	return &systemCertificateRollout{client: f.client, root: f.fixture.root, eap: f.fixture.desired, eapChain: []*systemCertificateCertificate{f.fixture.issuer}, eapKey: f.fixture.key, nodes: f.nodes, cas: []*systemCertificateCertificate{f.fixture.root, f.fixture.issuer}, timeout: 120}
}
func (f *systemCertificateFakeISE) handle(w http.ResponseWriter, r *http.Request) {
	username, password, ok := r.BasicAuth()
	if !ok || username != "test" || password != "test-secret" {
		f.t.Error("missing basic auth")
		w.WriteHeader(401)
		return
	}
	write := func(v any) {
		if err := json.NewEncoder(w).Encode(v); err != nil {
			f.t.Error(err)
		}
	}
	p := r.URL.Path
	switch {
	case p == "/api/v1/deployment/node":
		write(map[string]any{"response": []systemCertificateDeploymentNode{{FQDN: "secondary.example.test", Status: "Connected"}, {FQDN: "primary.example.test", Status: "Connected", Roles: []string{"PrimaryAdmin"}}}})
	case p == "/admin/API/apiGateway/get":
		write([]map[string]any{{"hostname": "primary", "isEnabled": true}, {"hostname": "secondary", "isEnabled": f.enabled}})
	case p == "/api/v1/certs/trusted-certificate/import":
		f.t.Error("system certificate deployment must never modify CA trust")
		w.WriteHeader(400)
	case p == "/api/v1/certs/trusted-certificate":
		items := []systemCertificateCertificateItem{}
		for hash := range f.trust {
			items = append(items, systemCertificateCertificateItem{Fingerprint: hash, TrustedFor: "Infrastructure"})
		}
		write(map[string]any{"response": items})
	case p == "/api/v1/certs/system-certificate/export":
		var payload map[string]string
		json.NewDecoder(r.Body).Decode(&payload)
		if payload["id"] == "unrelated" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		cert := f.certs[payload["id"]]
		if payload["id"] == "candidate" && f.stored {
			cert = f.fixture.desired
		}
		if cert == nil {
			f.t.Error("unknown exported certificate")
			return
		}
		var buffer bytes.Buffer
		archive := zip.NewWriter(&buffer)
		entry, _ := archive.Create("certificate.pem")
		entry.Write([]byte(f.exportedPEM(cert)))
		archive.Close()
		w.Write(buffer.Bytes())
	case p == "/api/v1/certs/system-certificate/import" || r.Method == "PUT":
		var payload map[string]any
		json.NewDecoder(r.Body).Decode(&payload)
		role := "eap"
		if payload["admin"] == true {
			role = "admin"
		}
		for _, key := range []string{"radius", "pxgrid", "ims", "saml"} {
			if payload[key] != false {
				f.t.Errorf("unexpected role/transfer %s", key)
			}
		}
		transfer := role == "admin" && f.portalTag != "" && payload["portal"] == true
		for _, key := range []string{"portal", "allowRoleTransferForSameSubject", "allowPortalTagTransferForSameSubject", "allowReplacementOfPortalGroupTag"} {
			if payload[key] != transfer {
				f.t.Errorf("unexpected Portal transfer setting %s: %v", key, payload[key])
			}
		}
		if transfer && payload["portalGroupTag"] != f.portalTag {
			f.t.Error("Portal group tag changed")
		}
		// Rollout sequence identifies the direct target in this one-server fixture.
		host := "secondary"
		if role == "eap" && f.certs["primary/eap"] != nil && f.certs["secondary/eap"].fingerprint == f.fixture.desired.fingerprint {
			host = "primary"
		}
		if role == "admin" && f.certs["secondary/admin"].fingerprint == f.fixture.desired.fingerprint {
			host = "primary"
		}
		if r.Method == "PUT" {
			host = strings.Split(strings.TrimPrefix(p, "/api/v1/certs/system-certificate/"), "/")[0]
		}
		if r.Method == "POST" {
			block, _ := pem.Decode([]byte(payload["privateKeyData"].(string)))
			if _, err := x509.DecryptPEMBlock(block, []byte(payload["password"].(string))); err != nil {
				f.t.Error("invalid encrypted upload")
			}
		}
		f.certs[host+"/"+role] = f.fixture.desired
		if transfer {
			f.certs[host+"/portal"] = f.fixture.desired
		}
		// PUT can retain another role already served by the stored candidate.
		if r.Method == "PUT" {
			if payload["admin"] == true {
				f.certs[host+"/admin"] = f.fixture.desired
			}
			if payload["eap"] == true {
				f.certs[host+"/eap"] = f.fixture.desired
			}
		}
		f.writes = append(f.writes, host+"/"+role+"/"+r.Method)
		if f.httpFailure {
			f.httpFailure = false
			w.WriteHeader(503)
			return
		}
		if f.interrupt {
			f.interrupt = false
			connection, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				connection.Close()
			}
			return
		}
		write(map[string]any{})
	case strings.HasPrefix(p, "/api/v1/certs/system-certificate/"):
		host := strings.TrimPrefix(p, "/api/v1/certs/system-certificate/")
		items := []systemCertificateCertificateItem{}
		for _, role := range []string{"admin", "eap"} {
			if cert := f.certs[host+"/"+role]; cert != nil {
				used := "Admin"
				if role == "eap" {
					used = "EAP Authentication"
				}
				groupTag := ""
				if portal := f.certs[host+"/portal"]; role == "admin" && portal != nil && portal.fingerprint == cert.fingerprint {
					used += ", Portal"
					groupTag = f.portalTag
				}
				items = append(items, systemCertificateCertificateItem{ID: host + "/" + role, Fingerprint: f.fingerprint(cert), UsedBy: used, GroupTag: groupTag})
			}
		}
		if portal := f.certs[host+"/portal"]; portal != nil {
			admin := f.certs[host+"/admin"]
			if admin == nil || admin.fingerprint != portal.fingerprint {
				items = append(items, systemCertificateCertificateItem{ID: host + "/portal", Fingerprint: f.fingerprint(portal), UsedBy: "Portal", GroupTag: f.portalTag})
			}
		}
		if f.stored {
			items = append(items, systemCertificateCertificateItem{ID: "candidate", Fingerprint: f.fingerprint(f.fixture.desired), UsedBy: "Not in use"})
		}
		if f.unexportable {
			items = append(items, systemCertificateCertificateItem{ID: "unrelated", Fingerprint: strings.Repeat("0", 64), UsedBy: "Not in use"})
		}
		write(map[string]any{"response": items})
	default:
		f.t.Errorf("unexpected API route %s", p)
		w.WriteHeader(404)
	}
}
func TestSystemCertificateRolloutAndRefresh(t *testing.T) {
	f := systemCertificateNewFakeISE(t)
	r := f.rollout()
	if err := r.run(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := "secondary/eap/POST,secondary/admin/PUT,primary/admin/POST"
	if strings.Join(f.writes, ",") != want {
		t.Fatalf("wrong rollout order: %v", f.writes)
	}
	active, synced, err := r.observe(context.Background())
	if err != nil || !synced || len(active) != 3 {
		t.Fatalf("refresh: %v %v %v", active, synced, err)
	}
	f.writes = nil
	if err := r.run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(f.writes) != 0 {
		t.Fatal("matching certificates reimported")
	}
	f.certs["secondary/eap"] = f.fixture.old
	_, synced, err = r.observe(context.Background())
	if err != nil || synced {
		t.Fatalf("role drift not detected: %v", err)
	}
}
func TestSystemCertificateRolloutPreflight(t *testing.T) {
	for _, test := range []string{"disabled gateway", "primary not last"} {
		t.Run(test, func(t *testing.T) {
			f := systemCertificateNewFakeISE(t)
			r := f.rollout()
			if test == "disabled gateway" {
				f.enabled = false
			} else {
				r.nodes[0], r.nodes[1] = r.nodes[1], r.nodes[0]
			}
			if err := r.run(context.Background()); err == nil {
				t.Fatal("unsafe rollout accepted")
			}
			if len(f.writes) != 0 {
				t.Fatal("preflight made writes")
			}
		})
	}
}
func TestSystemCertificateInterruptedWriteNotReplayed(t *testing.T) {
	f := systemCertificateNewFakeISE(t)
	f.interrupt = true
	r := f.rollout()
	if err := r.assign(context.Background(), r.nodes[0], "eap", r.eap, r.eapChain, r.eapKey); err != nil {
		t.Fatal(err)
	}
	if len(f.writes) != 1 {
		t.Fatalf("ambiguous write replayed: %v", f.writes)
	}
}
func TestSystemCertificateStoredCandidateAssignedWithoutUpload(t *testing.T) {
	f := systemCertificateNewFakeISE(t)
	f.stored = true
	r := f.rollout()
	if err := r.assign(context.Background(), r.nodes[0], "eap", r.eap, r.eapChain, r.eapKey); err != nil {
		t.Fatal(err)
	}
	if len(f.writes) != 1 || !strings.HasSuffix(f.writes[0], "/PUT") {
		t.Fatalf("stored certificate reimported: %v", f.writes)
	}
}
func TestSystemCertificateNewerCertificatePreservedOrRefused(t *testing.T) {
	for _, missing := range []bool{false, true} {
		t.Run(fmt.Sprintf("missing=%v", missing), func(t *testing.T) {
			f := systemCertificateNewFakeISE(t)
			r := f.rollout()
			cert := f.fixture.newer
			if missing {
				cert = f.fixture.missing
			}
			f.certs["secondary/eap"] = cert
			err := r.assign(context.Background(), r.nodes[0], "eap", r.eap, r.eapChain, r.eapKey)
			if (err != nil) != missing {
				t.Fatalf("unexpected newer certificate result: %v", err)
			}
			if len(f.writes) != 0 {
				t.Fatal("newer managed certificate replaced")
			}
		})
	}
}
func TestSystemCertificateAPIErrorRedactionAndLogicalFailure(t *testing.T) {
	for _, body := range []string{"secret echoed by HTTP error", `{"response":{"status":"FAILURE"}}`, `{"response":{"status":"Fail"}}`} {
		t.Run(body, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if strings.HasPrefix(body, "secret") {
					w.WriteHeader(400)
				}
				fmt.Fprint(w, body)
			}))
			defer server.Close()
			c := systemCertificateNewClient("test", "secret", true)
			err := c.json(context.Background(), strings.TrimPrefix(server.URL, "https://"), "/test", "POST", map[string]string{"privateKeyData": "secret"}, nil)
			if err == nil || strings.Contains(err.Error(), "secret") {
				t.Fatalf("unsafe diagnostic: %v", err)
			}
		})
	}
}
func TestSystemCertificateRecoveryCancellation(t *testing.T) {
	c := systemCertificateNewClient("test", "test", true)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := c.wait(ctx, true, func(context.Context) (bool, error) { return false, nil }); err == nil {
		t.Fatal("cancelled recovery succeeded")
	}
}
func TestSystemCertificateResourceSchemaAndDriftPlanning(t *testing.T) {
	ctx := context.Background()
	r := &systemCertificateCoordinator{}
	var schemaResponse resource.SchemaResponse
	r.Schema(ctx, resource.SchemaRequest{}, &schemaResponse)
	if diagnostics := schemaResponse.Schema.ValidateImplementation(ctx); diagnostics.HasError() {
		t.Fatal(diagnostics)
	}
	model := SystemCertificateDeployment{Id: types.StringValue("primary.example.test"), RootCertificatePem: types.StringValue("root"), EapCertificatePem: types.StringValue("eap"), EapCaPem: types.StringValue("ca"), PrivateKeysWo: types.MapNull(types.StringType), TimeoutSeconds: types.Int64Value(1800), ActiveFingerprints: types.MapNull(types.StringType), InSync: types.BoolValue(false), Nodes: []SystemCertificateDeploymentNodes{}}
	state := tfsdk.State{Schema: schemaResponse.Schema}
	if diagnostics := state.Set(ctx, model); diagnostics.HasError() {
		t.Fatal(diagnostics)
	}
	plan := tfsdk.Plan{Schema: schemaResponse.Schema, Raw: state.Raw}
	resp := resource.ModifyPlanResponse{Plan: plan}
	r.ModifyPlan(ctx, resource.ModifyPlanRequest{State: state, Plan: plan}, &resp)
	var changed SystemCertificateDeployment
	if diagnostics := resp.Plan.Get(ctx, &changed); diagnostics.HasError() {
		t.Fatal(diagnostics)
	}
	if !changed.InSync.ValueBool() {
		t.Fatal("drift did not schedule reconciliation")
	}
}
func TestSystemCertificateDeleteDoesNotContactISE(t *testing.T) {
	r := &systemCertificateCoordinator{}
	var response resource.DeleteResponse
	r.Delete(context.Background(), resource.DeleteRequest{}, &response)
	if response.Diagnostics.HasError() || len(response.Diagnostics) != 1 {
		t.Fatal("unsafe delete behavior")
	}
}

type systemCertificateRouteTransport struct {
	base    http.RoundTripper
	address string
}

func (r systemCertificateRouteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	clone.URL.Host = r.address
	return r.base.RoundTrip(clone)
}
func (f *systemCertificateFakeISE) model(t *testing.T) SystemCertificateDeployment {
	t.Helper()
	f.client.http.Transport = systemCertificateRouteTransport{f.server.Client().Transport, strings.TrimPrefix(f.server.URL, "https://")}
	f.nodes[0].address = "192.0.2.4"
	f.nodes[1].address = "192.0.2.5"
	keys := map[string]string{"eap": string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(f.fixture.key)}))}
	model := SystemCertificateDeployment{Id: types.StringNull(), RootCertificatePem: types.StringValue(f.fixture.root.pem), EapCertificatePem: types.StringValue(f.fixture.desired.pem), EapCaPem: types.StringValue(f.fixture.issuer.pem), PrivateKeysWoVersion: types.Int64Value(1), TimeoutSeconds: types.Int64Value(120), ActiveFingerprints: types.MapNull(types.StringType), InSync: types.BoolNull()}
	for _, n := range f.nodes {
		model.Nodes = append(model.Nodes, SystemCertificateDeploymentNodes{Hostname: types.StringValue(n.hostname), Address: types.StringValue(n.address), AdminCertificatePem: types.StringValue(n.admin.pem), AdminCaPem: types.StringValue(f.fixture.issuer.pem), Eap: types.BoolValue(n.eap)})
		keys[n.hostname] = keys["eap"]
	}
	model.PrivateKeysWo, _ = types.MapValueFrom(context.Background(), types.StringType, keys)
	return model
}
func TestSystemCertificateResourceCreateReadAndUpdateOffline(t *testing.T) {
	f := systemCertificateNewFakeISE(t)
	ctx := context.Background()
	r := &systemCertificateCoordinator{client: f.client}
	var schemaResponse resource.SchemaResponse
	r.Schema(ctx, resource.SchemaRequest{}, &schemaResponse)
	configModel := f.model(t)
	configState := tfsdk.State{Schema: schemaResponse.Schema}
	if d := configState.Set(ctx, configModel); d.HasError() {
		t.Fatal(d)
	}
	config := tfsdk.Config{Schema: schemaResponse.Schema, Raw: configState.Raw}
	planModel := configModel
	planModel.PrivateKeysWo = types.MapNull(types.StringType)
	planModel.Id = types.StringUnknown()
	planModel.InSync = types.BoolUnknown()
	planModel.ActiveFingerprints = types.MapUnknown(types.StringType)
	plan := tfsdk.Plan{Schema: schemaResponse.Schema}
	if d := plan.Set(ctx, planModel); d.HasError() {
		t.Fatal(d)
	}
	created := resource.CreateResponse{State: tfsdk.State{Schema: schemaResponse.Schema}}
	r.Create(ctx, resource.CreateRequest{Plan: plan, Config: config}, &created)
	if created.Diagnostics.HasError() {
		t.Fatal(created.Diagnostics)
	}
	var state SystemCertificateDeployment
	if d := created.State.Get(ctx, &state); d.HasError() {
		t.Fatal(d)
	}
	if !state.PrivateKeysWo.IsNull() || !state.InSync.ValueBool() || state.Id.ValueString() != "primary.example.test" {
		t.Fatal("invalid creation state or private key persisted")
	}
	f.certs["secondary/eap"] = f.fixture.old
	refreshed := resource.ReadResponse{State: created.State}
	r.Read(ctx, resource.ReadRequest{State: created.State}, &refreshed)
	if refreshed.Diagnostics.HasError() {
		t.Fatal(refreshed.Diagnostics)
	}
	if d := refreshed.State.Get(ctx, &state); d.HasError() {
		t.Fatal(d)
	}
	if state.InSync.ValueBool() {
		t.Fatal("refresh did not expose role drift")
	}
	updatePlan := tfsdk.Plan{Schema: schemaResponse.Schema, Raw: refreshed.State.Raw}
	modified := resource.ModifyPlanResponse{Plan: updatePlan}
	r.ModifyPlan(ctx, resource.ModifyPlanRequest{State: refreshed.State, Plan: updatePlan}, &modified)
	updated := resource.UpdateResponse{State: refreshed.State}
	r.Update(ctx, resource.UpdateRequest{Plan: modified.Plan, Config: config, State: refreshed.State}, &updated)
	if updated.Diagnostics.HasError() {
		t.Fatal(updated.Diagnostics)
	}
	if d := updated.State.Get(ctx, &state); d.HasError() {
		t.Fatal(d)
	}
	if !state.InSync.ValueBool() || !state.PrivateKeysWo.IsNull() {
		t.Fatal("drift not reconciled or private keys persisted")
	}
}
func TestSystemCertificateFailedCreateKeepsRecoverableStateWithoutKeys(t *testing.T) {
	f := systemCertificateNewFakeISE(t)
	f.enabled = false
	ctx := context.Background()
	r := &systemCertificateCoordinator{client: f.client}
	var schemaResponse resource.SchemaResponse
	r.Schema(ctx, resource.SchemaRequest{}, &schemaResponse)
	model := f.model(t)
	configured := tfsdk.State{Schema: schemaResponse.Schema}
	configured.Set(ctx, model)
	plan := tfsdk.Plan{Schema: schemaResponse.Schema, Raw: configured.Raw}
	response := resource.CreateResponse{State: tfsdk.State{Schema: schemaResponse.Schema}}
	r.Create(ctx, resource.CreateRequest{Plan: plan, Config: tfsdk.Config{Schema: schemaResponse.Schema, Raw: configured.Raw}}, &response)
	if !response.Diagnostics.HasError() || len(f.writes) > 0 {
		t.Fatal("gateway prerequisite failed open")
	}
	var state SystemCertificateDeployment
	if d := response.State.Get(ctx, &state); d.HasError() {
		t.Fatal(d)
	}
	if state.Id.IsNull() || !state.PrivateKeysWo.IsNull() || state.InSync.ValueBool() {
		t.Fatal("failed rollout state cannot be recovered safely")
	}
}

func TestSystemCertificateEAPOnlyLeavesEveryAdminCertificateUntouched(t *testing.T) {
	f := systemCertificateNewFakeISE(t)
	model := f.model(t)
	for i := range model.Nodes {
		model.Nodes[i].AdminCertificatePem = types.StringNull()
		model.Nodes[i].AdminCaPem = types.StringNull()
	}
	keys := map[string]string{"eap": string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(f.fixture.key)}))}
	r, err := f.client.prepare(model, keys)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if strings.Join(f.writes, ",") != "secondary/eap/POST" {
		t.Fatalf("unexpected EAP-only writes: %v", f.writes)
	}
	for _, n := range f.nodes {
		if f.certs[systemCertificateShortHostname(n.hostname)+"/admin"].fingerprint != f.fixture.old.fingerprint {
			t.Fatal("Admin certificate changed")
		}
	}
	active, synced, err := r.observe(context.Background())
	if err != nil || !synced || len(active) != 1 {
		t.Fatalf("unexpected EAP-only refresh: %v %v %v", active, synced, err)
	}
	if _, found := active["secondary.example.test/admin"]; found {
		t.Fatal("unmanaged Admin drift is being tracked")
	}
}
func TestSystemCertificateEAPOnlyRefusesAdminCandidateReuse(t *testing.T) {
	f := systemCertificateNewFakeISE(t)
	r := f.rollout()
	n := r.nodes[0]
	n.admin = nil
	f.certs["secondary/admin"] = f.fixture.desired
	if err := r.assign(context.Background(), n, "eap", r.eap, r.eapChain, r.eapKey); err == nil {
		t.Fatal("Admin-affecting EAP update allowed")
	}
	if len(f.writes) != 0 {
		t.Fatal("Admin candidate was mutated")
	}
}

func TestSystemCertificateEAPOnlyWithPEMFileFingerprints(t *testing.T) {
	for _, stored := range []bool{false, true} {
		t.Run(fmt.Sprintf("stored=%v", stored), func(t *testing.T) {
			f := systemCertificateNewFakeISE(t)
			f.pemFingerprints = true
			f.unexportable = true
			f.stored = stored
			model := f.model(t)
			for i := range model.Nodes {
				model.Nodes[i].AdminCertificatePem = types.StringNull()
				model.Nodes[i].AdminCaPem = types.StringNull()
			}
			keys := map[string]string{"eap": string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(f.fixture.key)}))}
			r, err := f.client.prepare(model, keys)
			if err != nil {
				t.Fatal(err)
			}
			if err := r.run(context.Background()); err != nil {
				t.Fatal(err)
			}
			method := "POST"
			if stored {
				method = "PUT"
			}
			if strings.Join(f.writes, ",") != "secondary/eap/"+method {
				t.Fatalf("unexpected writes: %v", f.writes)
			}
			active, synced, err := r.observe(context.Background())
			if err != nil || !synced || active["secondary.example.test/eap"] != f.fixture.desired.fingerprint {
				t.Fatalf("refresh did not retain canonical DER fingerprint: %v %v %v", active, synced, err)
			}
			f.writes = nil
			if err := r.run(context.Background()); err != nil || len(f.writes) != 0 {
				t.Fatalf("matching certificate was not adopted: %v %v", err, f.writes)
			}
			for _, n := range f.nodes {
				if f.certs[systemCertificateShortHostname(n.hostname)+"/admin"].fingerprint != f.fixture.old.fingerprint {
					t.Fatal("unmanaged Admin certificate changed")
				}
			}
		})
	}
}

func TestSystemCertificateExportRefusesUnmatchedFingerprint(t *testing.T) {
	f := systemCertificateNewFakeISE(t)
	f.pemFingerprints = true
	_, err := f.client.export(context.Background(), f.nodes[0], systemCertificateCertificateItem{ID: "secondary/eap", Fingerprint: strings.Repeat("0", 64)})
	if err == nil {
		t.Fatal("unmatched exported certificate accepted")
	}
}

func TestSystemCertificateAdminPortalTransferPreservesTagAndEAP(t *testing.T) {
	f := systemCertificateNewFakeISE(t)
	f.pemFingerprints = true
	f.portalTag = "Existing Portal Group"
	f.certs["secondary/portal"] = f.fixture.old
	f.trust[f.fixture.root.fingerprint] = true
	f.trust[f.fixture.issuer.fingerprint] = true
	r := f.rollout()
	r.eap = f.fixture.newer
	f.certs["secondary/eap"] = f.fixture.newer
	r.nodes[0].portalGroup = f.portalTag
	r.nodes[1].admin = nil
	if err := r.preflight(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := r.assign(context.Background(), r.nodes[0], "admin", r.nodes[0].admin, r.nodes[0].chain, r.nodes[0].key); err != nil {
		t.Fatal(err)
	}
	if f.certs["secondary/portal"].fingerprint != f.fixture.desired.fingerprint || f.certs["secondary/admin"].fingerprint != f.fixture.desired.fingerprint {
		t.Fatal("Admin and Portal did not activate together")
	}
	if f.certs["secondary/eap"].fingerprint != f.fixture.newer.fingerprint {
		t.Fatal("EAP assignment changed")
	}
	_, synced, err := r.observe(context.Background())
	if err != nil || !synced {
		t.Fatalf("Portal activation not observed: %v %v", synced, err)
	}
	f.certs["secondary/portal"] = f.fixture.old
	_, synced, err = r.observe(context.Background())
	if err != nil || synced {
		t.Fatalf("Portal drift was not detected: %v %v", synced, err)
	}
	if err := r.assign(context.Background(), r.nodes[0], "admin", r.nodes[0].admin, r.nodes[0].chain, r.nodes[0].key); err != nil {
		t.Fatal(err)
	}
	if f.certs["secondary/portal"].fingerprint != f.fixture.desired.fingerprint || !strings.HasSuffix(f.writes[len(f.writes)-1], "/PUT") {
		t.Fatal("Portal drift did not reuse the installed Admin certificate")
	}
}

func TestSystemCertificateAdminPortalTransferRequiresExistingTag(t *testing.T) {
	f := systemCertificateNewFakeISE(t)
	f.portalTag = "Existing Portal Group"
	f.certs["secondary/portal"] = f.fixture.old
	r := f.rollout()
	r.nodes[0].portalGroup = "Another Portal Group"
	if err := r.preflight(context.Background()); err == nil || len(f.writes) != 0 {
		t.Fatal("Portal group mismatch did not stop before writes")
	}
}

func TestSystemCertificateAdminLeavesPortalUnmanagedWithoutOptIn(t *testing.T) {
	f := systemCertificateNewFakeISE(t)
	f.portalTag = "Existing Portal Group"
	f.certs["secondary/portal"] = f.fixture.old
	r := f.rollout()
	if err := r.assign(context.Background(), r.nodes[0], "admin", r.nodes[0].admin, r.nodes[0].chain, r.nodes[0].key); err != nil {
		t.Fatal(err)
	}
	if f.certs["secondary/portal"].fingerprint != f.fixture.old.fingerprint {
		t.Fatal("Portal transferred without opt-in")
	}
}

func TestSystemCertificatePortalTransferRequiresManagedAdmin(t *testing.T) {
	f := systemCertificateNewFakeISE(t)
	model := f.model(t)
	model.Nodes[0].AdminCertificatePem = types.StringNull()
	model.Nodes[0].AdminCaPem = types.StringNull()
	model.Nodes[0].AdminPortalGroupTag = types.StringValue("Existing Portal Group")
	if _, err := f.client.prepare(model, nil); err == nil {
		t.Fatal("Portal transfer accepted without Admin management")
	}
}

func TestSystemCertificateMissingTrustStopsBeforeSystemWrites(t *testing.T) {
	f := systemCertificateNewFakeISE(t)
	delete(f.trust, f.fixture.issuer.fingerprint)
	if err := f.rollout().run(context.Background()); err == nil {
		t.Fatal("missing pre-installed issuer trust accepted")
	}
	if len(f.writes) != 0 {
		t.Fatal("missing trust did not stop rollout before writes")
	}
}

func TestSystemCertificateAdminOnlyDoesNotRequireEAPMaterial(t *testing.T) {
	f := systemCertificateNewFakeISE(t)
	model := f.model(t)
	model.EapCertificatePem = types.StringNull()
	model.EapCaPem = types.StringNull()
	for i := range model.Nodes {
		model.Nodes[i].Eap = types.BoolValue(false)
	}
	keys := map[string]string{}
	model.PrivateKeysWo.ElementsAs(context.Background(), &keys, false)
	delete(keys, "eap")
	r, err := f.client.prepare(model, keys)
	if err != nil {
		t.Fatal(err)
	}
	if err = r.run(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, write := range f.writes {
		if strings.Contains(write, "/eap/") {
			t.Fatal("Admin-only deployment changed EAP")
		}
	}
}

func TestSystemCertificateRecoveryRequiresConsecutiveHealthyChecks(t *testing.T) {
	c := systemCertificateNewClient("test", "test", true)
	c.poll = time.Microsecond
	c.settle = time.Millisecond
	sequence := []bool{true, false, true, true, true}
	checks := 0
	start := time.Now()
	if err := c.wait(context.Background(), true, func(context.Context) (bool, error) {
		if time.Since(start) < c.settle {
			t.Error("readiness checked before the Admin restart settlement period")
		}
		value := sequence[checks]
		checks++
		return value, nil
	}); err != nil {
		t.Fatal(err)
	}
	if checks != 5 {
		t.Fatal("recovery did not reset the healthy streak after a failure")
	}
}

func TestSystemCertificateMissingDeploymentMemberStopsBeforeWrites(t *testing.T) {
	f := systemCertificateNewFakeISE(t)
	r := f.rollout()
	r.nodes = r.nodes[1:]
	if err := r.run(context.Background()); err == nil || len(f.writes) != 0 {
		t.Fatal("incomplete deployment health coverage accepted")
	}
}

func TestSystemCertificateInheritedTransportAndRedirectPolicy(t *testing.T) {
	transport := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: false}}
	configured := &http.Client{Transport: transport, Timeout: 23 * time.Second}
	r := &systemCertificateCoordinator{}
	if err := r.ConfigureHTTPClient(configured, "user", "password"); err != nil {
		t.Fatal(err)
	}
	if r.client.tls.InsecureSkipVerify || r.client.http.Timeout != configured.Timeout || r.client.tls.MinVersion < tls.VersionTLS12 {
		t.Fatal("configured transport security or timeout was not preserved")
	}
	if r.client.http.CheckRedirect(nil, nil) != http.ErrUseLastResponse {
		t.Fatal("redirects are not refused")
	}
	if transport.TLSClientConfig.MinVersion != 0 {
		t.Fatal("shared provider transport mutated")
	}
}

func TestSystemCertificateServerFailureAfterWriteIsNotReplayed(t *testing.T) {
	f := systemCertificateNewFakeISE(t)
	f.httpFailure = true
	r := f.rollout()
	if err := r.assign(context.Background(), r.nodes[0], "eap", r.eap, r.eapChain, r.eapKey); err != nil {
		t.Fatal(err)
	}
	if len(f.writes) != 1 {
		t.Fatal("HTTP 503 caused a potentially successful write to be replayed")
	}
}

func TestSystemCertificateUnexpectedServedCertificateStopsBeforeNextNode(t *testing.T) {
	f := systemCertificateNewFakeISE(t)
	f.client.probe = func(context.Context, systemCertificateNode) (string, error) { return strings.Repeat("0", 64), nil }
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := f.rollout().run(ctx); err == nil {
		t.Fatal("incorrect served HTTPS certificate accepted")
	}
	for _, write := range f.writes {
		if strings.HasPrefix(write, "primary/") {
			t.Fatal("rollout continued to the primary PAN after a failed recovery")
		}
	}
}

func TestSystemCertificateSharedEAPAndAdminUsesOrderedNodePhase(t *testing.T) {
	f := systemCertificateNewFakeISE(t)
	r := f.rollout()
	r.nodes[1].eap = true
	f.certs["primary/eap"] = f.fixture.old
	if err := r.run(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := "secondary/eap/POST,secondary/admin/PUT,primary/eap/POST,primary/admin/PUT"
	if strings.Join(f.writes, ",") != want {
		t.Fatalf("unexpected order: %v", f.writes)
	}
}

// Offline lifecycle tests use the actual generated schema, never a second copy.
func (r *systemCertificateCoordinator) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	(&SystemCertificateDeploymentResource{}).Schema(ctx, req, resp)
}

func TestSystemCertificateGeneratedSchemaSecurity(t *testing.T) {
	var response resource.SchemaResponse
	(&SystemCertificateDeploymentResource{}).Schema(context.Background(), resource.SchemaRequest{}, &response)
	secret := response.Schema.Attributes["private_keys_wo"]
	if !secret.IsRequired() || !secret.IsWriteOnly() || !secret.IsSensitive() {
		t.Fatal("generated keys must be required, sensitive and write-only")
	}
	for _, name := range []string{"active_fingerprints", "in_sync"} {
		attr := response.Schema.Attributes[name]
		if !attr.IsComputed() || attr.IsOptional() || attr.IsRequired() {
			t.Fatalf("%s must be a read-only output", name)
		}
	}
}
