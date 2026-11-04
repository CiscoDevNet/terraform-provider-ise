// Copyright 2026 Stegra.
// SPDX-License-Identifier: MPL-2.0

package systemcertificate

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type client struct {
	http               *http.Client
	username, password string
	tls                *tls.Config
	poll, settle       time.Duration
	probe              func(context.Context, node) (string, error)
}
type transportError struct{ message string }

func (e *transportError) Error() string { return e.message }
func interrupted(err error) bool        { var e *transportError; return errors.As(err, &e) }

type httpError struct{ status int }

func (e *httpError) Error() string {
	return fmt.Sprintf("ISE certificate API returned HTTP %d", e.status)
}
func recoverable(err error) bool {
	var h *httpError
	return interrupted(err) || (errors.As(err, &h) && h.status >= 500)
}

// ConfigureHTTPClient reuses the provider transport, credentials and timeout.
// Node endpoints come only from explicit Terraform inputs, never API links.
func (r *DeploymentResource) ConfigureHTTPClient(httpClient *http.Client, username, password string) error {
	transport, ok := httpClient.Transport.(*http.Transport)
	if !ok {
		return fmt.Errorf("expected the configured ISE HTTP transport")
	}
	config := &tls.Config{MinVersion: tls.VersionTLS12}
	if transport.TLSClientConfig != nil {
		config = transport.TLSClientConfig.Clone()
		config.MinVersion = tls.VersionTLS12
	}
	clone := *httpClient
	clone.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	clonedTransport := transport.Clone()
	clonedTransport.TLSClientConfig = config
	clone.Transport = clonedTransport
	r.client = &client{http: &clone, username: username, password: password, tls: config, poll: 10 * time.Second, settle: 60 * time.Second}
	return nil
}

func normalizeFingerprint(s string) string {
	return strings.ToLower(strings.NewReplacer(":", "", " ", "", "-", "").Replace(s))
}
func systemFingerprintMatches(fingerprint string, cert *certificate) bool {
	fingerprint = normalizeFingerprint(fingerprint)
	if fingerprint == cert.fingerprint {
		return true
	}
	for _, value := range []string{cert.pem, strings.ReplaceAll(cert.pem, "\n", "\r\n")} {
		hash := sha256.Sum256([]byte(value))
		if hex.EncodeToString(hash[:]) == fingerprint {
			return true
		}
	}
	return false
}
func (c *client) request(ctx context.Context, address, path, method string, payload any) ([]byte, error) {
	var body io.Reader
	if payload != nil {
		encoded, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("unable to encode ISE request")
		}
		body = bytes.NewReader(encoded)
	}
	host := address
	if net.ParseIP(address) != nil && strings.Contains(address, ":") {
		host = "[" + address + "]"
	}
	u := "https://" + host + path
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return nil, fmt.Errorf("invalid ISE endpoint")
	}
	req.SetBasicAuth(c.username, c.password)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, &transportError{fmt.Sprintf("ISE %s: %s %s connection interrupted", address, method, path)}
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// ISE may echo secrets in an error body; never return it or request data.
		return nil, &httpError{status: resp.StatusCode}
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 8*1024*1024+1))
	if err != nil {
		return nil, &transportError{fmt.Sprintf("ISE %s: response interrupted", address)}
	}
	if len(data) > 8*1024*1024 {
		return nil, fmt.Errorf("ISE response exceeded size limit")
	}
	return data, nil
}
func (c *client) json(ctx context.Context, address, path, method string, payload, result any) error {
	body, err := c.request(ctx, address, path, method, payload)
	if err != nil {
		return err
	}
	if len(body) == 0 && method != "GET" {
		return nil
	}
	var generic any
	if json.Unmarshal(body, &generic) != nil {
		return fmt.Errorf("ISE %s: %s returned invalid JSON", address, path)
	}
	if obj, ok := generic.(map[string]any); ok {
		failure := func(v any) bool {
			s, _ := v.(string)
			return strings.EqualFold(s, "FAIL") || strings.EqualFold(s, "FAILURE") || strings.EqualFold(s, "FAILED") || strings.EqualFold(s, "ERROR")
		}
		response, _ := obj["response"].(map[string]any)
		if failure(obj["status"]) || failure(response["status"]) || nonempty(obj["errors"]) || nonempty(obj["error"]) {
			return fmt.Errorf("ISE %s: %s reported API failure", address, path)
		}
	}
	if result == nil {
		return nil
	}
	if json.Unmarshal(body, result) != nil {
		return fmt.Errorf("ISE %s: %s returned an unexpected JSON shape", address, path)
	}
	return nil
}
func nonempty(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case string:
		return x != ""
	case []any:
		return len(x) > 0
	case map[string]any:
		return len(x) > 0
	default:
		return true
	}
}

type certificateItem struct {
	ID          string `json:"id"`
	Fingerprint string `json:"sha256Fingerprint"`
	UsedBy      string `json:"usedBy"`
	TrustedFor  string `json:"trustedFor"`
	GroupTag    string `json:"groupTag"`
}
type deploymentNode struct {
	FQDN   string   `json:"fqdn"`
	Status string   `json:"nodeStatus"`
	Roles  []string `json:"roles"`
}

func collection[T any](ctx context.Context, c *client, address, path string) ([]T, error) {
	var items []T
	for page := 1; page <= 100; page++ {
		var result struct {
			Response *[]T            `json:"response"`
			NextPage json.RawMessage `json:"nextPage"`
		}
		if err := c.json(ctx, address, fmt.Sprintf("%s?size=100&page=%d", path, page), "GET", nil, &result); err != nil {
			return nil, err
		}
		if result.Response == nil {
			return nil, fmt.Errorf("ISE %s: expected collection at %s", address, path)
		}
		if len(items)+len(*result.Response) > 10000 {
			return nil, fmt.Errorf("ISE collection size limit exceeded")
		}
		items = append(items, (*result.Response)...)
		if len(result.NextPage) == 0 || string(result.NextPage) == "null" {
			return items, nil
		}
	}
	return nil, fmt.Errorf("ISE collection pagination limit exceeded")
}
func shortHostname(host string) string { return strings.SplitN(host, ".", 2)[0] }
func (c *client) certificates(ctx context.Context, n node) ([]certificateItem, error) {
	return collection[certificateItem](ctx, c, n.address, "/api/v1/certs/system-certificate/"+url.PathEscape(shortHostname(n.hostname)))
}
func hasRole(item certificateItem, role string) bool {
	wanted := "Admin"
	if role == "eap" {
		wanted = "EAP Authentication"
	}
	if role == "portal" {
		wanted = "Portal"
	}
	for _, value := range strings.Split(item.UsedBy, ",") {
		if strings.TrimSpace(value) == wanted {
			return true
		}
	}
	return false
}
func (c *client) export(ctx context.Context, n node, item certificateItem) (*certificate, error) {
	body, err := c.request(ctx, n.address, "/api/v1/certs/system-certificate/export", "POST", map[string]any{
		"hostName": shortHostname(n.hostname), "id": item.ID, "export": "CERTIFICATE",
	})
	if err != nil {
		return nil, err
	}
	var candidates [][]byte
	if archive, err := zip.NewReader(bytes.NewReader(body), int64(len(body))); err == nil {
		if len(archive.File) > 100 {
			return nil, fmt.Errorf("too many certificate archive entries")
		}
		total := 0
		for _, file := range archive.File {
			if file.FileInfo().IsDir() {
				continue
			}
			if file.UncompressedSize64 > 1024*1024 {
				return nil, fmt.Errorf("ISE public certificate export exceeded size limit")
			}
			reader, err := file.Open()
			if err != nil {
				return nil, fmt.Errorf("invalid ISE certificate archive")
			}
			data, readErr := io.ReadAll(io.LimitReader(reader, 1024*1024+1))
			reader.Close()
			if readErr != nil || len(data) > 1024*1024 {
				return nil, fmt.Errorf("invalid ISE certificate archive entry")
			}
			total += len(data)
			if total > 8*1024*1024 {
				return nil, fmt.Errorf("certificate archive exceeded size limit")
			}
			candidates = append(candidates, data)
		}
	} else {
		candidates = append(candidates, body)
	}
	for _, data := range candidates {
		// ISE system-certificate metadata can hash the exported PEM file,
		// whereas TLS and our state use the certificate's DER fingerprint.
		fileHash := sha256.Sum256(data)
		if hex.EncodeToString(fileHash[:]) == normalizeFingerprint(item.Fingerprint) {
			cert, err := parseCertificate(string(data))
			if err == nil {
				return cert, nil
			}
		}
		for {
			block, rest := pem.Decode(data)
			if block == nil {
				break
			}
			data = rest
			if block.Type != "CERTIFICATE" {
				continue
			}
			cert, err := parseCertificate(string(pem.EncodeToMemory(block)))
			if err != nil {
				continue
			}
			if cert.fingerprint == normalizeFingerprint(item.Fingerprint) {
				return cert, nil
			}
		}
	}
	return nil, fmt.Errorf("%s: export did not contain the selected active certificate", n.hostname)
}
func (c *client) servedFingerprint(ctx context.Context, n node) (string, error) {
	if c.probe != nil {
		return c.probe(ctx, n)
	}
	config := c.tls.Clone()
	config.ServerName = n.hostname
	dialer := tls.Dialer{NetDialer: &net.Dialer{Timeout: 10 * time.Second}, Config: config}
	connection, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(n.address, "443"))
	if err != nil {
		return "", &transportError{"ISE HTTPS endpoint unavailable"}
	}
	defer connection.Close()
	tlsConnection := connection.(*tls.Conn)
	certs := tlsConnection.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return "", fmt.Errorf("ISE HTTPS endpoint supplied no certificate")
	}
	hash := sha256.Sum256(certs[0].Raw)
	return hex.EncodeToString(hash[:]), nil
}
func delay(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
func (c *client) wait(ctx context.Context, settle bool, check func(context.Context) (bool, error)) error {
	if settle {
		if err := delay(ctx, c.settle); err != nil {
			return fmt.Errorf("ISE recovery timed out or was cancelled")
		}
	}
	stable := 0
	for {
		ok, err := check(ctx)
		if err == nil && ok {
			stable++
		} else {
			stable = 0
		}
		if stable >= 3 {
			return nil
		}
		if err := delay(ctx, c.poll); err != nil {
			return fmt.Errorf("ISE recovery timed out or was cancelled; inspect deployment before retrying")
		}
	}
}
