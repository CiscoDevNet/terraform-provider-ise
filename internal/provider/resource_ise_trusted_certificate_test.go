// Copyright 2026 Stegra.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"archive/zip"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func testCertificate(t *testing.T, serial int64) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "Example Test CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// All lifecycle traffic is confined to this local server, including when TF_ACC is unset.
type trustedCertificateFixture struct {
	sync.Mutex
	pem                  string
	metadata             map[string]any
	posts, puts, deletes int
	lostResponse         bool
}

func (f *trustedCertificateFixture) serve(t *testing.T, w http.ResponseWriter, r *http.Request) {
	t.Helper()
	f.Lock()
	defer f.Unlock()
	user, password, ok := r.BasicAuth()
	if !ok || user != "test-user" || password != "test-password" {
		t.Error("missing configured authentication")
		w.WriteHeader(401)
		return
	}
	respond := func(value any) {
		if err := json.NewEncoder(w).Encode(value); err != nil {
			t.Error(err)
		}
	}
	switch {
	case r.Method == "GET" && r.URL.Path == trustedCertificatePath:
		items := []any{}
		if f.metadata != nil {
			items = append(items, f.metadata)
		}
		respond(map[string]any{"response": items})
	case r.Method == "GET" && r.URL.Path == trustedCertificatePath+"/test-id":
		if f.metadata == nil {
			w.WriteHeader(404)
			return
		}
		respond(map[string]any{"response": f.metadata})
	case r.Method == "GET" && r.URL.Path == trustedCertificatePath+"/export/test-id":
		var archive bytes.Buffer
		writer := zip.NewWriter(&archive)
		entry, _ := writer.Create("ca.pem")
		_, _ = entry.Write([]byte(strings.ReplaceAll(f.pem, "\n", "\r\n")))
		_ = writer.Close()
		_, _ = w.Write(archive.Bytes())
	case r.Method == "POST" && r.URL.Path == trustedCertificatePath+"/import":
		f.posts++
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		if body["data"] != f.pem || body["validateCertificateExtensions"] != true || body["allowOutOfDateCert"] != false || body["allowSHA1Certificates"] != false || body["allowBasicConstraintCAFalse"] != false {
			t.Error("unexpected certificate import or validation flags")
		}
		f.metadata = map[string]any{"id": "test-id", "sha256Fingerprint": testFingerprint(t, f.pem), "status": "Enabled", "crlDistributionUrl": "https://example.com/ca.crl",
			"downloadCRL": "true", "automaticCRLUpdate": "false", "automaticCRLUpdatePeriod": "0", "automaticCRLUpdateUnits": "Minutes",
			"nonAutomaticCRLUpdatePeriod": "2", "nonAutomaticCRLUpdateUnits": "Hours", "crlDownloadFailureRetries": "10", "crlDownloadFailureRetriesUnits": "Minutes",
			"authenticateBeforeCRLReceived": "false", "ignoreCRLExpiration": "false", "enableOCSPValidation": "true", "enableServerIdentityCheck": "true",
			"selectedOCSPService": "Example OCSP", "rejectIfNoStatusFromOCSP": "true", "rejectIfUnreachableFromOCSP": "true"}
		f.apply(body)
		if f.lostResponse {
			connection, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			_ = connection.Close()
			return
		}
		respond(map[string]any{"response": map[string]any{"status": "Success"}})
	case r.Method == "PUT" && r.URL.Path == trustedCertificatePath+"/test-id":
		f.puts++
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		// GET returns strings; PUT must retain the settings using native JSON types.
		expected := map[string]any{
			"status": "Enabled", "crlDistributionUrl": "https://example.com/ca.crl",
			"downloadCRL": true, "automaticCRLUpdate": false, "automaticCRLUpdatePeriod": float64(0), "automaticCRLUpdateUnits": "Minutes",
			"nonAutomaticCRLUpdatePeriod": float64(2), "nonAutomaticCRLUpdateUnits": "Hours", "crlDownloadFailureRetries": float64(10), "crlDownloadFailureRetriesUnits": "Minutes",
			"authenticateBeforeCRLReceived": false, "ignoreCRLExpiration": false, "enableOCSPValidation": true, "enableServerIdentityCheck": true,
			"selectedOCSPService": "Example OCSP", "rejectIfNoStatusFromOCSP": true, "rejectIfUnreachableFromOCSP": true,
		}
		for key, value := range expected {
			if body[key] != value {
				t.Errorf("update lost or mistyped unmanaged setting %s: got %#v, want %#v", key, body[key], value)
			}
		}
		f.apply(body)
		respond(map[string]any{"response": map[string]any{"status": "Success"}})
	case r.Method == "DELETE" && r.URL.Path == trustedCertificatePath+"/test-id":
		f.deletes++
		f.metadata = nil
		w.WriteHeader(204)
	default:
		t.Errorf("unexpected request %s %s", r.Method, r.URL)
		w.WriteHeader(400)
	}
}

func (f *trustedCertificateFixture) apply(body map[string]any) {
	f.metadata["friendlyName"] = body["name"]
	f.metadata["description"] = body["description"]
	purposes := []string{}
	for _, pair := range [][2]string{{"trustForIseAuth", "Infrastructure"}, {"trustForClientAuth", "Endpoints"}, {"trustForCertificateBasedAdminAuth", "AdminAuth"}, {"trustForCiscoServicesAuth", "Cisco Services"}} {
		if body[pair[0]] == true {
			purposes = append(purposes, pair[1])
		}
	}
	f.metadata["trustedFor"] = strings.Join(purposes, ", ")
}

func testFingerprint(t *testing.T, encoded string) string {
	t.Helper()
	block, _ := pem.Decode([]byte(encoded))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return certificateFingerprint(cert)
}

func trustedTestConfig(url, encoded, name string, retain bool) string {
	return fmt.Sprintf(`provider "ise" {
 url = %q
 username = "test-user"
 password = "test-password"
}
resource "ise_trusted_certificate" "test" {
 name = %q
 certificate_pem = %q
 trust_for_ise_auth = true
 trust_for_client_auth = true
 retain_on_destroy = %t
}
`, url, name, encoded, retain)
}

func TestTrustedCertificateLifecycle(t *testing.T) {
	for _, lost := range []bool{false, true} {
		t.Run(fmt.Sprintf("lost_import_response_%t", lost), func(t *testing.T) {
			f := &trustedCertificateFixture{pem: testCertificate(t, 1), lostResponse: lost}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { f.serve(t, w, r) }))
			defer server.Close()
			resource.UnitTest(t, resource.TestCase{ProtoV6ProviderFactories: testAccProtoV6ProviderFactories, Steps: []resource.TestStep{
				{Config: trustedTestConfig(server.URL, f.pem, "Test CA", false), Check: resource.ComposeTestCheckFunc(resource.TestCheckResourceAttr("ise_trusted_certificate.test", "id", "test-id"), resource.TestCheckResourceAttr("ise_trusted_certificate.test", "sha256_fingerprint", testFingerprint(t, f.pem)))},
				{ResourceName: "ise_trusted_certificate.test", ImportState: true, ImportStateVerify: true, ImportStateVerifyIgnore: []string{"retain_on_destroy", "certificate_pem"}},
				{Config: trustedTestConfig(server.URL, strings.ReplaceAll(f.pem, "\n", "\r\n"), "Test CA", false)},
				{Config: trustedTestConfig(server.URL, f.pem, "Renamed CA", false)},
				{Config: strings.Replace(trustedTestConfig(server.URL, f.pem, "Renamed CA", false), " trust_for_client_auth = true", " trust_for_client_auth = true\n trust_for_certificate_based_admin_auth = true\n trust_for_cisco_services_auth = true", 1), Check: resource.ComposeTestCheckFunc(resource.TestCheckResourceAttr("ise_trusted_certificate.test", "trust_for_certificate_based_admin_auth", "true"), resource.TestCheckResourceAttr("ise_trusted_certificate.test", "trust_for_cisco_services_auth", "true"))},
			}})
			f.Lock()
			defer f.Unlock()
			if f.posts != 1 || f.puts != 2 || f.deletes != 1 {
				t.Fatalf("writes POST=%d PUT=%d DELETE=%d", f.posts, f.puts, f.deletes)
			}
		})
	}
}

func TestTrustedCertificateRetention(t *testing.T) {
	f := &trustedCertificateFixture{pem: testCertificate(t, 2)}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { f.serve(t, w, r) }))
	defer server.Close()
	config := strings.ReplaceAll(trustedTestConfig(server.URL, f.pem, "Test CA", true), " retain_on_destroy = true\n", "")
	resource.UnitTest(t, resource.TestCase{ProtoV6ProviderFactories: testAccProtoV6ProviderFactories, Steps: []resource.TestStep{{Config: config, Check: resource.TestCheckResourceAttr("ise_trusted_certificate.test", "retain_on_destroy", "true")}}})
	f.Lock()
	defer f.Unlock()
	if f.posts != 1 || f.puts != 0 || f.deletes != 0 || f.metadata == nil {
		t.Fatalf("retention failed: POST=%d PUT=%d DELETE=%d", f.posts, f.puts, f.deletes)
	}
}

func TestTrustedCertificateRequiresExplicitImport(t *testing.T) {
	for _, name := range []string{"Test CA", "Other CA"} {
		for _, retain := range []bool{true, false} {
			t.Run(fmt.Sprintf("existing_name_%s_retain_%t", name, retain), func(t *testing.T) {
				f := &trustedCertificateFixture{pem: testCertificate(t, 40)}
				f.metadata = map[string]any{"id": "test-id", "friendlyName": name, "description": "", "trustedFor": "Infrastructure, Endpoints", "sha256Fingerprint": testFingerprint(t, f.pem)}
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { f.serve(t, w, r) }))
				defer server.Close()
				resource.UnitTest(t, resource.TestCase{ProtoV6ProviderFactories: testAccProtoV6ProviderFactories, Steps: []resource.TestStep{{Config: trustedTestConfig(server.URL, f.pem, "Test CA", retain), ExpectError: regexp.MustCompile("Trusted certificate already exists")}}})
				f.Lock()
				defer f.Unlock()
				if f.posts+f.puts+f.deletes != 0 || f.metadata == nil {
					t.Fatal("existing certificate was modified or deleted without explicit import")
				}
			})
		}
	}
}

func TestTrustedCertificateExplicitImportOwnership(t *testing.T) {
	for _, retain := range []bool{true, false} {
		t.Run(fmt.Sprintf("retain_%t", retain), func(t *testing.T) {
			f := &trustedCertificateFixture{pem: testCertificate(t, 41)}
			f.metadata = map[string]any{"id": "test-id", "friendlyName": "Test CA", "description": "", "trustedFor": "Infrastructure, Endpoints", "sha256Fingerprint": testFingerprint(t, f.pem)}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { f.serve(t, w, r) }))
			defer server.Close()
			config := trustedTestConfig(server.URL, f.pem, "Test CA", retain)
			resource.UnitTest(t, resource.TestCase{ProtoV6ProviderFactories: testAccProtoV6ProviderFactories, Steps: []resource.TestStep{
				{Config: config, ResourceName: "ise_trusted_certificate.test", ImportState: true, ImportStateId: "test-id", ImportStatePersist: true},
				{Config: config, Check: resource.TestCheckResourceAttr("ise_trusted_certificate.test", "retain_on_destroy", fmt.Sprint(retain))},
			}})
			f.Lock()
			defer f.Unlock()
			expectedDeletes := 0
			if !retain {
				expectedDeletes = 1
			}
			if f.posts != 0 || f.puts != 0 || f.deletes != expectedDeletes {
				t.Fatalf("POST=%d PUT=%d DELETE=%d", f.posts, f.puts, f.deletes)
			}
		})
	}
}
