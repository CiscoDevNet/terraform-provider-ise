// Copyright 2026 Stegra.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// ISE GET encodes CRL/OCSP switches as on/off and periods as strings, while PUT expects
// booleans and integers. Accept native JSON values too, for ISE versions that
// already return them. Never guess a default for an unrecognized value.
func preserveTrustedCertificateSettings(body map[string]any, current map[string]json.RawMessage) error {
	fields := map[string]string{
		"status":                         "string",
		"crlDistributionUrl":             "string",
		"downloadCRL":                    "bool",
		"automaticCRLUpdate":             "bool",
		"automaticCRLUpdatePeriod":       "int",
		"automaticCRLUpdateUnits":        "string",
		"nonAutomaticCRLUpdatePeriod":    "int",
		"nonAutomaticCRLUpdateUnits":     "string",
		"crlDownloadFailureRetries":      "int",
		"crlDownloadFailureRetriesUnits": "string",
		"authenticateBeforeCRLReceived":  "bool",
		"ignoreCRLExpiration":            "bool",
		"enableOCSPValidation":           "bool",
		"enableServerIdentityCheck":      "bool",
		"selectedOCSPService":            "string",
		"rejectIfNoStatusFromOCSP":       "bool",
		"rejectIfUnreachableFromOCSP":    "bool",
	}
	for key, kind := range fields {
		raw, ok := current[key]
		if !ok {
			continue
		}
		value := strings.TrimSpace(string(raw))
		invalid := func() error {
			return fmt.Errorf("cannot preserve ISE field %s: expected %s; refusing to update certificate", key, kind)
		}
		if value == "null" {
			// ISE returns null for optional settings that have never been
			// configured. Match the API's omitempty semantics: do not invent
			// false/zero values that could overwrite inherited/default policy.
			continue
		}
		var text string
		quoted := json.Unmarshal(raw, &text) == nil
		if quoted {
			value = text
		}
		switch kind {
		case "string":
			if !quoted {
				return invalid()
			}
			body[key] = text
		case "bool":
			switch value {
			case "true", "on":
				body[key] = true
			case "false", "off":
				body[key] = false
			default:
				return invalid()
			}
		case "int":
			number, err := strconv.ParseInt(value, 10, 64)
			if err != nil || number < 0 {
				return invalid()
			}
			body[key] = number
		}
	}
	return nil
}
