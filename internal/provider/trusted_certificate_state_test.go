// Copyright 2026 Stegra.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/CiscoDevNet/terraform-provider-ise/internal/provider/helpers"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	ise "github.com/netascode/go-ise"
)

func trustedCertificateState(t *testing.T, encoded string) tfsdk.State {
	t.Helper()
	var response resource.SchemaResponse
	(&TrustedCertificateResource{}).Schema(context.Background(), resource.SchemaRequest{}, &response)
	state := tfsdk.State{Schema: response.Schema}
	model := trustedCertificateModel{ID: types.StringValue("test-id"), Name: types.StringValue("Test CA"), Description: types.StringNull(), Certificate: helpers.NewCertificatePEMValue(encoded), Fingerprint: types.StringValue(testFingerprint(t, encoded)), ISEAuth: types.BoolValue(true), ClientAuth: types.BoolValue(false), AdminAuth: types.BoolValue(false), CiscoAuth: types.BoolValue(false), Retain: types.BoolValue(false), Timeout: types.Int64Value(120)}
	if diagnostics := state.Set(context.Background(), model); diagnostics.HasError() {
		t.Fatal(diagnostics)
	}
	return state
}
func TestTrustedCertificateReadMissingVersusError(t *testing.T) {
	encoded := testCertificate(t, 30)
	for _, test := range []struct {
		name                       string
		detailStatus, exportStatus int
		removed                    bool
	}{
		{"missing_object", 404, 200, true},
		{"forbidden", 403, 200, false},
		{"missing_export", 200, 404, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == trustedCertificatePath+"/test-id" {
					w.WriteHeader(test.detailStatus)
					if test.detailStatus == 200 {
						_ = json.NewEncoder(w).Encode(map[string]any{"response": map[string]string{"id": "test-id", "sha256Fingerprint": testFingerprint(t, encoded)}})
					}
				} else {
					w.WriteHeader(test.exportStatus)
				}
			}))
			defer server.Close()
			client, _ := ise.NewClient(server.URL, "user", "password")
			r := &TrustedCertificateResource{client: certificateClient{client: &client}}
			state := trustedCertificateState(t, encoded)
			response := resource.ReadResponse{State: state}
			r.Read(context.Background(), resource.ReadRequest{State: state}, &response)
			if response.State.Raw.IsNull() != test.removed || response.Diagnostics.HasError() == test.removed {
				t.Fatalf("removed=%t diagnostics=%v", response.State.Raw.IsNull(), response.Diagnostics)
			}
		})
	}
}
func TestTrustedCertificateDeleteRefusesReusedID(t *testing.T) {
	original, replacement := testCertificate(t, 31), testCertificate(t, 32)
	writes := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method != "GET":
			writes++
			w.WriteHeader(204)
		case r.URL.Path == trustedCertificatePath+"/test-id":
			_ = json.NewEncoder(w).Encode(map[string]any{"response": map[string]string{"id": "test-id", "sha256Fingerprint": testFingerprint(t, replacement)}})
		default:
			_, _ = w.Write([]byte(replacement))
		}
	}))
	defer server.Close()
	client, _ := ise.NewClient(server.URL, "user", "password")
	r := &TrustedCertificateResource{client: certificateClient{client: &client}}
	response := resource.DeleteResponse{}
	r.Delete(context.Background(), resource.DeleteRequest{State: trustedCertificateState(t, original)}, &response)
	if !response.Diagnostics.HasError() || writes != 0 {
		t.Fatalf("deleted different certificate: %v", response.Diagnostics)
	}
}
