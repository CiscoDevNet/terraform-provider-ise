// Copyright 2026 Stegra.
// SPDX-License-Identifier: MPL-2.0

package systemcertificate

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net"
	"strings"
	"time"
)

type certificate struct {
	x509             *x509.Certificate
	pem, fingerprint string
}

func parseCertificates(value string) ([]*certificate, error) {
	var result []*certificate
	rest := []byte(value)
	for {
		rest = bytes.TrimSpace(rest)
		if len(rest) == 0 {
			break
		}
		if !bytes.HasPrefix(rest, []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, fmt.Errorf("expected certificate PEM blocks without other data")
		}
		block, next := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = next
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, fmt.Errorf("expected certificate PEM blocks")
		}
		parsed, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("invalid X509 certificate")
		}
		hash := sha256.Sum256(parsed.Raw)
		result = append(result, &certificate{parsed, string(pem.EncodeToMemory(block)), hex.EncodeToString(hash[:])})
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("no PEM certificates supplied")
	}
	if strings.TrimSpace(string(rest)) != "" {
		return nil, fmt.Errorf("unexpected data after certificate PEM")
	}
	return result, nil
}
func parseCertificate(value string) (*certificate, error) {
	certs, err := parseCertificates(value)
	if err != nil {
		return nil, err
	}
	if len(certs) != 1 {
		return nil, fmt.Errorf("expected exactly one leaf certificate")
	}
	return certs[0], nil
}
func verifies(cert, root *certificate, chain []*certificate) bool {
	roots, intermediates := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(root.x509)
	for _, ca := range chain {
		intermediates.AddCert(ca.x509)
	}
	_, err := cert.x509.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	return err == nil
}
func identitiesMatch(installed, desired *certificate) bool {
	if !bytes.Equal(installed.x509.RawSubject, desired.x509.RawSubject) {
		return false
	}
	dns := map[string]bool{}
	for _, name := range installed.x509.DNSNames {
		dns[strings.ToLower(name)] = true
	}
	for _, name := range desired.x509.DNSNames {
		if !dns[strings.ToLower(name)] {
			return false
		}
	}
	for _, wanted := range desired.x509.IPAddresses {
		found := false
		for _, address := range installed.x509.IPAddresses {
			if address.Equal(wanted) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	// Include the less common SAN types instead of silently dropping identities.
	for _, wanted := range desired.x509.EmailAddresses {
		found := false
		for _, email := range installed.x509.EmailAddresses {
			if email == wanted {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	for _, wanted := range desired.x509.URIs {
		found := false
		for _, uri := range installed.x509.URIs {
			if uri.String() == wanted.String() {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	return true
}
func preferred(installed, desired, root *certificate, chain []*certificate) (bool, error) {
	if installed.fingerprint == desired.fingerprint {
		return verifies(installed, root, chain), nil
	}
	sameIssuer := false
	for _, issuer := range append(append([]*certificate{}, chain...), root) {
		if installed.x509.CheckSignatureFrom(issuer.x509) == nil && desired.x509.CheckSignatureFrom(issuer.x509) == nil {
			sameIssuer = true
		}
	}
	if bytes.Equal(installed.x509.RawIssuer, desired.x509.RawIssuer) && sameIssuer && verifies(installed, root, chain) && !installed.x509.NotAfter.Before(desired.x509.NotAfter) {
		if !identitiesMatch(installed, desired) {
			return false, fmt.Errorf("newer managed certificate lacks the requested subject/SANs; refusing to overwrite it")
		}
		return true, nil
	}
	return false, nil
}
func parseKey(value string, cert *certificate) (*rsa.PrivateKey, error) {
	value = strings.TrimSpace(value)
	if !strings.HasPrefix(value, "-----BEGIN ") || strings.Count(value, "-----BEGIN ") != 1 {
		return nil, fmt.Errorf("expected exactly one private key PEM block")
	}
	block, rest := pem.Decode([]byte(value))
	if block == nil || strings.TrimSpace(string(rest)) != "" {
		return nil, fmt.Errorf("invalid private key PEM")
	}
	var key *rsa.PrivateKey
	if block.Type == "RSA PRIVATE KEY" {
		parsed, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("invalid RSA private key")
		}
		key = parsed
	} else if block.Type == "PRIVATE KEY" {
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("invalid PKCS8 private key")
		}
		key, _ = parsed.(*rsa.PrivateKey)
	} else {
		return nil, fmt.Errorf("only unencrypted RSA private key inputs are supported")
	}
	if key == nil || key.N.BitLen() < 2048 {
		return nil, fmt.Errorf("ISE certificate upload currently requires RSA keys")
	}
	if err := key.Validate(); err != nil {
		return nil, fmt.Errorf("invalid RSA key")
	}
	public, ok := cert.x509.PublicKey.(*rsa.PublicKey)
	if !ok || !key.PublicKey.Equal(crypto.PublicKey(public)) {
		return nil, fmt.Errorf("certificate and private key do not match")
	}
	return key, nil
}
func encryptedKey(key *rsa.PrivateKey) (string, string, error) {
	passwordBytes := make([]byte, 16)
	if _, err := rand.Read(passwordBytes); err != nil {
		return "", "", fmt.Errorf("unable to generate upload password")
	}
	password := hex.EncodeToString(passwordBytes)
	// ISE's import interface accepts password-encrypted traditional RSA PEM.
	// This legacy encoding is used only inside the HTTPS upload, never on disk.
	block, err := x509.EncryptPEMBlock(rand.Reader, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(key), []byte(password), x509.PEMCipherAES256)
	if err != nil {
		return "", "", fmt.Errorf("unable to encrypt upload key")
	}
	return string(pem.EncodeToMemory(block)), password, nil
}
func validateCA(root *certificate) error {
	if !root.x509.IsCA || !root.x509.BasicConstraintsValid || root.x509.NotAfter.Before(time.Now()) || root.x509.NotBefore.After(time.Now()) {
		return fmt.Errorf("managed CA must be a currently valid CA certificate")
	}
	return nil
}
func validateNodeIdentity(n node) error {
	if net.ParseIP(n.address) == nil || n.hostname == "" || strings.ContainsAny(n.hostname, " /:\\") {
		return fmt.Errorf("each node needs a valid IP address and hostname")
	}
	if n.admin == nil {
		return nil
	}
	if err := n.admin.x509.VerifyHostname(n.hostname); err != nil {
		return fmt.Errorf("%s: Admin certificate does not cover the node hostname", n.hostname)
	}
	if err := n.admin.x509.VerifyHostname(n.address); err != nil {
		return fmt.Errorf("%s: Admin certificate does not cover the node IP", n.hostname)
	}
	return nil
}
