// Copyright 2026 Stegra.
// SPDX-License-Identifier: MPL-2.0

package helpers

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// ParseCertificatePEM accepts exactly one X.509 certificate and no private keys.
func ParseCertificatePEM(value string) (*x509.Certificate, error) {
	value = string(bytes.TrimSpace([]byte(value)))
	if !bytes.HasPrefix([]byte(value), []byte("-----BEGIN CERTIFICATE-----")) {
		return nil, fmt.Errorf("expected one PEM-encoded X.509 certificate")
	}
	block, rest := pem.Decode([]byte(value))
	if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || bytes.Count([]byte(value), []byte("-----BEGIN ")) != 1 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("expected exactly one PEM-encoded X.509 certificate")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("invalid X.509 certificate")
	}
	return certificate, nil
}
