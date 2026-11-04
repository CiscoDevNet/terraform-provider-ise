// Copyright 2026 Stegra.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	ise "github.com/netascode/go-ise"
)

func TestTrustedCertificateSettingsTypes(t *testing.T) {
	for _, test := range []struct {
		name, input string
		want        map[string]any
	}{
		{"string values", `{"downloadCRL":"true","ignoreCRLExpiration":"false","nonAutomaticCRLUpdatePeriod":"2","nonAutomaticCRLUpdateUnits":"Hours","automaticCRLUpdatePeriod":"0"}`, map[string]any{"downloadCRL": true, "ignoreCRLExpiration": false, "nonAutomaticCRLUpdatePeriod": int64(2), "nonAutomaticCRLUpdateUnits": "Hours", "automaticCRLUpdatePeriod": int64(0)}},
		{"native values", `{"downloadCRL":false,"ignoreCRLExpiration":false,"nonAutomaticCRLUpdatePeriod":2,"nonAutomaticCRLUpdateUnits":"Hours","automaticCRLUpdatePeriod":0}`, map[string]any{"downloadCRL": false, "ignoreCRLExpiration": false, "nonAutomaticCRLUpdatePeriod": int64(2), "nonAutomaticCRLUpdateUnits": "Hours", "automaticCRLUpdatePeriod": int64(0)}},
		{"unset ISE settings", `{"downloadCRL":"false","crlDistributionUrl":null,"automaticCRLUpdatePeriod":null,"nonAutomaticCRLUpdateUnits":null,"enableOCSPValidation":null,"rejectIfNoStatusFromOCSP":null}`, map[string]any{"downloadCRL": false}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var current map[string]json.RawMessage
			if err := json.Unmarshal([]byte(test.input), &current); err != nil {
				t.Fatal(err)
			}
			body := map[string]any{}
			if err := preserveTrustedCertificateSettings(body, current); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(body, test.want) {
				t.Fatalf("got %#v, want %#v", body, test.want)
			}
		})
	}
}

func TestTrustedCertificateInvalidSettingsPreventUpdate(t *testing.T) {
	encoded := testCertificate(t, 42)
	for _, test := range []struct{ name, key, raw string }{
		{"unrecognized boolean", "downloadCRL", `"unexpected-secret-value"`},
		{"empty boolean", "downloadCRL", `""`},

		{"numeric boolean", "enableOCSPValidation", `1`},
		{"fractional period", "nonAutomaticCRLUpdatePeriod", `1.5`},
		{"negative period", "crlDownloadFailureRetries", `"-1"`},
		{"overflow period", "automaticCRLUpdatePeriod", `"9223372036854775808"`},
		{"empty period", "nonAutomaticCRLUpdatePeriod", `""`},
		{"invalid units type", "nonAutomaticCRLUpdateUnits", `2`},
	} {
		t.Run(test.name, func(t *testing.T) {
			writes := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "GET" {
					writes++
					w.WriteHeader(204)
					return
				}
				if strings.Contains(r.URL.Path, "/export/") {
					_, _ = w.Write([]byte(encoded))
					return
				}
				item := map[string]any{"id": "test-id", "friendlyName": "Test CA", "trustedFor": "Infrastructure", "sha256Fingerprint": testFingerprint(t, encoded), test.key: json.RawMessage(test.raw)}
				_ = json.NewEncoder(w).Encode(map[string]any{"response": item})
			}))
			defer server.Close()
			client, _ := ise.NewClient(server.URL, "user", "password")
			r := &TrustedCertificateResource{client: &client}
			state := trustedCertificateState(t, encoded)
			planned := trustedCertificateState(t, encoded)
			if d := planned.SetAttribute(context.Background(), path.Root("description"), "Updated description"); d.HasError() {
				t.Fatal(d)
			}
			response := resource.UpdateResponse{State: state}
			r.Update(context.Background(), resource.UpdateRequest{State: state, Plan: tfsdk.Plan{Schema: planned.Schema, Raw: planned.Raw}}, &response)
			if !response.Diagnostics.HasError() || writes != 0 {
				t.Fatalf("invalid setting permitted update: writes=%d diagnostics=%v", writes, response.Diagnostics)
			}
			for _, d := range response.Diagnostics {
				if strings.Contains(d.Detail(), "unexpected-secret-value") {
					t.Fatal("error leaked raw API value")
				}
			}
		})
	}
}
