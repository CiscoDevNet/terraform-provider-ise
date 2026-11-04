// Copyright 2026 Stegra.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/CiscoDevNet/terraform-provider-ise/internal/provider/helpers"
	"github.com/netascode/go-ise"
)

const trustedCertificatePath = "/api/v1/certs/trusted-certificate"

type certificateHTTPError struct{ status int }

func (e *certificateHTTPError) Error() string {
	return fmt.Sprintf("ISE certificate API returned HTTP %d", e.status)
}

type certificateTransportError struct{}

func (*certificateTransportError) Error() string { return "ISE certificate API connection interrupted" }

type certificateClient struct{ client *ise.Client }

// Use the configured transport/authentication, but never replay certificate
// imports automatically or log payloads. A timed-out write may have succeeded.
func (c certificateClient) request(ctx context.Context, method, path string, payload any) ([]byte, error) {
	var body io.Reader
	if payload != nil {
		encoded, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("unable to encode certificate request")
		}
		body = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, c.client.Url+path, body)
	if err != nil {
		return nil, fmt.Errorf("invalid certificate API endpoint")
	}
	request.SetBasicAuth(c.client.Usr, c.client.Pwd)
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/json")
	client := *c.client.HttpClient
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	response, err := client.Do(request)
	if err != nil {
		return nil, &certificateTransportError{}
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, &certificateHTTPError{response.StatusCode}
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 8*1024*1024+1))
	if err != nil {
		return nil, &certificateTransportError{}
	}
	if len(data) > 8*1024*1024 {
		return nil, fmt.Errorf("certificate response exceeds size limit")
	}
	return data, nil
}

func decodeCertificateResponse(data []byte, destination any) error {
	if len(data) == 0 && destination == nil {
		return nil
	}
	var envelope struct {
		Status   string          `json:"status"`
		Response json.RawMessage `json:"response"`
		Errors   any             `json:"errors"`
		Error    any             `json:"error"`
	}
	if json.Unmarshal(data, &envelope) != nil {
		return fmt.Errorf("invalid certificate API response")
	}
	var nested struct {
		Status string `json:"status"`
	}
	_ = json.Unmarshal(envelope.Response, &nested)
	for _, status := range []string{envelope.Status, nested.Status} {
		switch strings.ToUpper(status) {
		case "FAIL", "FAILED", "FAILURE", "ERROR":
			return fmt.Errorf("ISE certificate API reported failure")
		}
	}
	for _, value := range []any{envelope.Errors, envelope.Error} {
		switch v := value.(type) {
		case string:
			if v != "" {
				return fmt.Errorf("ISE certificate API reported failure")
			}
		case []any:
			if len(v) > 0 {
				return fmt.Errorf("ISE certificate API reported failure")
			}
		case map[string]any:
			if len(v) > 0 {
				return fmt.Errorf("ISE certificate API reported failure")
			}
		}
	}
	if destination != nil && json.Unmarshal(data, destination) != nil {
		return fmt.Errorf("unexpected certificate API response")
	}
	return nil
}

type trustedCertificateMetadata struct {
	ID          string `json:"id"`
	Name        string `json:"friendlyName"`
	Description string `json:"description"`
	Fingerprint string `json:"sha256Fingerprint"`
	TrustedFor  string `json:"trustedFor"`
}

func (c certificateClient) list(ctx context.Context) ([]trustedCertificateMetadata, error) {
	var items []trustedCertificateMetadata
	for page := 1; page <= 100; page++ {
		body, err := c.request(ctx, http.MethodGet, fmt.Sprintf("%s?size=100&page=%d", trustedCertificatePath, page), nil)
		if err != nil {
			return nil, err
		}
		var result struct {
			Response *[]trustedCertificateMetadata `json:"response"`
			NextPage json.RawMessage               `json:"nextPage"`
		}
		if err = decodeCertificateResponse(body, &result); err != nil {
			return nil, err
		}
		if result.Response == nil {
			return nil, fmt.Errorf("certificate API response has no certificate collection")
		}
		items = append(items, (*result.Response)...)
		if len(result.NextPage) == 0 || string(result.NextPage) == "null" {
			return items, nil
		}
	}
	return nil, fmt.Errorf("certificate pagination limit exceeded")
}

func (c certificateClient) detail(ctx context.Context, id string) (trustedCertificateMetadata, map[string]json.RawMessage, error) {
	body, err := c.request(ctx, http.MethodGet, trustedCertificatePath+"/"+url.PathEscape(id), nil)
	if err != nil {
		return trustedCertificateMetadata{}, nil, err
	}
	var result struct {
		Response *trustedCertificateMetadata `json:"response"`
	}
	if err = decodeCertificateResponse(body, &result); err != nil {
		return trustedCertificateMetadata{}, nil, err
	}
	if result.Response == nil || result.Response.ID != id {
		return trustedCertificateMetadata{}, nil, fmt.Errorf("certificate API returned an unexpected certificate ID")
	}
	var raw struct {
		Response map[string]json.RawMessage `json:"response"`
	}
	_ = json.Unmarshal(body, &raw)
	return *result.Response, raw.Response, nil
}

func normalizeCertificateFingerprint(value string) string {
	return strings.ToLower(strings.NewReplacer(":", "", " ", "", "-", "").Replace(value))
}
func certificateFingerprint(cert *x509.Certificate) string {
	hash := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(hash[:])
}
func matchesCertificateFingerprint(value string, cert *x509.Certificate) bool {
	value = normalizeCertificateFingerprint(value)
	if value == certificateFingerprint(cert) {
		return true
	}
	encoded := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
	for _, data := range []string{encoded, strings.ReplaceAll(encoded, "\n", "\r\n")} {
		hash := sha256.Sum256([]byte(data))
		if value == hex.EncodeToString(hash[:]) {
			return true
		}
	}
	return false
}

func (c certificateClient) export(ctx context.Context, item trustedCertificateMetadata) (string, *x509.Certificate, error) {
	body, err := c.request(ctx, http.MethodGet, trustedCertificatePath+"/export/"+url.PathEscape(item.ID), nil)
	if err != nil {
		return "", nil, err
	}
	candidates := [][]byte{body}
	if archive, err := zip.NewReader(bytes.NewReader(body), int64(len(body))); err == nil {
		candidates = nil
		totalSize := 0
		if len(archive.File) > 100 {
			return "", nil, fmt.Errorf("too many certificate archive entries")
		}
		for _, file := range archive.File {
			if file.FileInfo().IsDir() {
				continue
			}
			if file.UncompressedSize64 > 1024*1024 {
				return "", nil, fmt.Errorf("certificate archive entry exceeds size limit")
			}
			reader, err := file.Open()
			if err != nil {
				return "", nil, fmt.Errorf("invalid certificate archive")
			}
			data, readErr := io.ReadAll(io.LimitReader(reader, 1024*1024+1))
			reader.Close()
			if readErr != nil || len(data) > 1024*1024 {
				return "", nil, fmt.Errorf("invalid certificate archive entry")
			}
			totalSize += len(data)
			if totalSize > 8*1024*1024 {
				return "", nil, fmt.Errorf("certificate archive exceeds size limit")
			}
			candidates = append(candidates, data)
		}
	}
	for _, data := range candidates {
		cert, err := helpers.ParseCertificatePEM(string(data))
		if err != nil {
			continue
		}
		hash := sha256.Sum256(data)
		if normalizeCertificateFingerprint(item.Fingerprint) != certificateFingerprint(cert) && normalizeCertificateFingerprint(item.Fingerprint) != hex.EncodeToString(hash[:]) {
			continue
		}
		return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})), cert, nil
	}
	return "", nil, fmt.Errorf("certificate export did not match the reported fingerprint")
}

func certificateNotFound(err error) bool {
	var httpError *certificateHTTPError
	return errors.As(err, &httpError) && httpError.status == http.StatusNotFound
}
