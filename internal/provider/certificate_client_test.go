// Copyright 2026 Stegra.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/CiscoDevNet/terraform-provider-ise/internal/provider/helpers"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	ise "github.com/netascode/go-ise"
)

func TestTrustedCertificateFingerprintAndPEM(t *testing.T) {
	encoded := testCertificate(t, 10)
	cert, err := helpers.ParseCertificatePEM(encoded)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{certificateFingerprint(cert), strings.ToUpper(certificateFingerprint(cert)), func() string { sum := sha256.Sum256([]byte(encoded)); return hex.EncodeToString(sum[:]) }(), func() string {
		sum := sha256.Sum256([]byte(strings.ReplaceAll(encoded, "\n", "\r\n")))
		return hex.EncodeToString(sum[:])
	}()} {
		if !matchesCertificateFingerprint(value, cert) {
			t.Errorf("fingerprint not recognized: %s", value)
		}
	}
	if matchesCertificateFingerprint(strings.Repeat("0", 64), cert) {
		t.Error("accepted different fingerprint")
	}
	for _, invalid := range []string{encoded + encoded, "private-key-material", encoded + "\n-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----"} {
		if _, err := helpers.ParseCertificatePEM(invalid); err == nil {
			t.Error("accepted certificate bundle or non-certificate content")
		}
	}
	equal, diagnostics := helpers.NewCertificatePEMValue(encoded).StringSemanticEquals(context.Background(), helpers.NewCertificatePEMValue("\n"+strings.ReplaceAll(encoded, "\n", "\r\n")))
	if !equal || diagnostics.HasError() {
		t.Fatal("equivalent PEM not semantically equal")
	}
	equal, _ = helpers.NewCertificatePEMValue(encoded).StringSemanticEquals(context.Background(), helpers.NewCertificatePEMValue(testCertificate(t, 11)))
	if equal {
		t.Error("different certificate semantically equal")
	}
}
func TestTrustedCertificateAPIErrorRedaction(t *testing.T) {
	for _, body := range []string{`{"response":{"status":"Fail","message":"secret-key"}}`, `{"errors":["secret-key"]}`, `{"status":"ERROR","message":"secret-key"}`, `secret-key`} {
		err := decodeCertificateResponse([]byte(body), nil)
		if err == nil || strings.Contains(err.Error(), "secret-key") {
			t.Fatalf("failure not redacted: %v", err)
		}
	}
	var leaked bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = true }))
	defer target.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, 302) }))
	defer server.Close()
	client, err := ise.NewClient(server.URL, "user", "secret-key")
	if err != nil {
		t.Fatal(err)
	}
	_, err = (certificateClient{client: &client}).request(context.Background(), "POST", "/import", map[string]string{"data": "secret-key"})
	if err == nil || leaked || strings.Contains(err.Error(), "secret-key") {
		t.Fatalf("redirect followed or error leaked: %v", err)
	}
}
func TestTrustedCertificatePaginationAndIdentity(t *testing.T) {
	pages := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == trustedCertificatePath+"/wrong-id" {
			_, _ = w.Write([]byte(`{"response":{"id":"different-id"}}`))
			return
		}
		pages++
		if r.URL.Query().Get("page") != []string{"1", "2"}[pages-1] {
			t.Error("incorrect pagination")
		}
		value := map[string]any{"response": []any{map[string]string{"id": "test"}}}
		if pages == 1 {
			value["nextPage"] = map[string]string{"href": "https://untrusted.example/steal-credentials"}
		}
		_ = json.NewEncoder(w).Encode(value)
	}))
	defer server.Close()
	client, _ := ise.NewClient(server.URL, "user", "password")
	c := certificateClient{client: &client}
	items, err := c.list(context.Background())
	if err != nil || len(items) != 2 || pages != 2 {
		t.Fatalf("pagination failed: %v", err)
	}
	if _, _, err := c.detail(context.Background(), "wrong-id"); err == nil {
		t.Error("accepted wrong certificate ID")
	}
}
func TestTrustedCertificateRefusesImplicitTakeover(t *testing.T) {
	f := &trustedCertificateFixture{pem: testCertificate(t, 12)}
	f.metadata = map[string]any{"id": "test-id", "friendlyName": "Other name", "description": "", "trustedFor": "Infrastructure, Endpoints", "sha256Fingerprint": testFingerprint(t, f.pem)}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { f.serve(t, w, r) }))
	defer server.Close()
	resource.UnitTest(t, resource.TestCase{ProtoV6ProviderFactories: testAccProtoV6ProviderFactories, Steps: []resource.TestStep{{Config: trustedTestConfig(server.URL, f.pem, "Test CA", false), ExpectError: regexp.MustCompile("Trusted certificate already exists")}}})
	f.Lock()
	defer f.Unlock()
	if f.posts+f.puts+f.deletes != 0 {
		t.Fatal("mismatching existing certificate was modified")
	}
}

func TestTrustedCertificateExportRejectsIdentityMismatch(t *testing.T) {
	encoded := testCertificate(t, 20)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(encoded)) }))
	defer server.Close()
	client, _ := ise.NewClient(server.URL, "user", "password")
	c := certificateClient{client: &client}
	if _, _, err := c.export(context.Background(), trustedCertificateMetadata{ID: "test-id", Fingerprint: testFingerprint(t, testCertificate(t, 21))}); err == nil {
		t.Fatal("accepted an export of a different certificate")
	}
	if _, _, err := c.export(context.Background(), trustedCertificateMetadata{ID: "test-id", Fingerprint: testFingerprint(t, encoded)}); err != nil {
		t.Fatal(err)
	}
}
