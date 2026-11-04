// Copyright © 2023 Cisco Systems, Inc. and its affiliates.
// All rights reserved.
//
// Licensed under the Mozilla Public License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://mozilla.org/MPL/2.0/
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: MPL-2.0

package helpers

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

// CertificatePEMType compares PEM-encoded certificates by DER identity, so line
// endings and surrounding whitespace do not create certificate replacements.
var (
	_ basetypes.StringTypable                    = CertificatePEMType{}
	_ basetypes.StringValuableWithSemanticEquals = CertificatePEMValue{}
)

type CertificatePEMType struct {
	basetypes.StringType
}

func (t CertificatePEMType) Equal(o attr.Type) bool {
	other, ok := o.(CertificatePEMType)
	if !ok {
		return false
	}
	return t.StringType.Equal(other.StringType)
}

func (t CertificatePEMType) String() string {
	return "helpers.CertificatePEMType"
}

func (t CertificatePEMType) ValueFromString(ctx context.Context, in basetypes.StringValue) (basetypes.StringValuable, diag.Diagnostics) {
	return CertificatePEMValue{StringValue: in}, nil
}

func (t CertificatePEMType) ValueFromTerraform(ctx context.Context, in tftypes.Value) (attr.Value, error) {
	attrValue, err := t.StringType.ValueFromTerraform(ctx, in)
	if err != nil {
		return nil, err
	}
	stringValue, ok := attrValue.(basetypes.StringValue)
	if !ok {
		return nil, fmt.Errorf("unexpected value type of %T", attrValue)
	}
	stringValuable, diags := t.ValueFromString(ctx, stringValue)
	if diags.HasError() {
		return nil, fmt.Errorf("unexpected error converting StringValue to StringValuable: %v", diags)
	}
	return stringValuable, nil
}

func (t CertificatePEMType) ValueType(ctx context.Context) attr.Value {
	return CertificatePEMValue{}
}

// CertificatePEMValue is the value type produced by CertificatePEMType.
type CertificatePEMValue struct {
	basetypes.StringValue
}

func (v CertificatePEMValue) Equal(o attr.Value) bool {
	other, ok := o.(CertificatePEMValue)
	if !ok {
		return false
	}
	return v.StringValue.Equal(other.StringValue)
}

func (v CertificatePEMValue) Type(ctx context.Context) attr.Type {
	return CertificatePEMType{}
}

// StringSemanticEquals compares the parsed certificate DER rather than PEM formatting.
func (v CertificatePEMValue) StringSemanticEquals(ctx context.Context, newValuable basetypes.StringValuable) (bool, diag.Diagnostics) {
	var diags diag.Diagnostics
	newValue, ok := newValuable.(CertificatePEMValue)
	if !ok {
		diags.AddError(
			"Semantic Equality Check Error",
			fmt.Sprintf("expected value type of helpers.CertificatePEMValue but got %T", newValuable),
		)
		return false, diags
	}
	if v.IsNull() || v.IsUnknown() || newValue.IsNull() || newValue.IsUnknown() {
		return v.StringValue.Equal(newValue.StringValue), diags
	}
	left, err := ParseCertificatePEM(v.ValueString())
	if err != nil {
		return false, diags
	}
	right, err := ParseCertificatePEM(newValue.ValueString())
	if err != nil {
		return false, diags
	}
	return bytes.Equal(left.Raw, right.Raw), diags
}

// NewCertificatePEMNull returns a null CertificatePEMValue.
func NewCertificatePEMNull() CertificatePEMValue {
	return CertificatePEMValue{StringValue: basetypes.NewStringNull()}
}

// NewCertificatePEMValue returns a known CertificatePEMValue holding v.
func NewCertificatePEMValue(v string) CertificatePEMValue {
	return CertificatePEMValue{StringValue: basetypes.NewStringValue(v)}
}

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
