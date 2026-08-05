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
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

// OperatorType is a custom string type for policy condition operator attributes.
// ISE canonicalizes IP-typed operators server-side (e.g. it stores `ipEquals`
// for an attribute written as `equals`, and vice versa). OperatorType folds those
// aliases together via semantic equality so a config written with either spelling
// converges to a clean plan. See NormalizeOperator for the alias mapping.
var (
	_ basetypes.StringTypable                    = OperatorType{}
	_ basetypes.StringValuableWithSemanticEquals = OperatorValue{}
)

type OperatorType struct {
	basetypes.StringType
}

func (t OperatorType) Equal(o attr.Type) bool {
	other, ok := o.(OperatorType)
	if !ok {
		return false
	}
	return t.StringType.Equal(other.StringType)
}

func (t OperatorType) String() string {
	return "helpers.OperatorType"
}

func (t OperatorType) ValueFromString(ctx context.Context, in basetypes.StringValue) (basetypes.StringValuable, diag.Diagnostics) {
	return OperatorValue{StringValue: in}, nil
}

func (t OperatorType) ValueFromTerraform(ctx context.Context, in tftypes.Value) (attr.Value, error) {
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

func (t OperatorType) ValueType(ctx context.Context) attr.Value {
	return OperatorValue{}
}

// OperatorValue is the value type produced by OperatorType.
type OperatorValue struct {
	basetypes.StringValue
}

func (v OperatorValue) Equal(o attr.Value) bool {
	other, ok := o.(OperatorValue)
	if !ok {
		return false
	}
	return v.StringValue.Equal(other.StringValue)
}

func (v OperatorValue) Type(ctx context.Context) attr.Type {
	return OperatorType{}
}

// StringSemanticEquals reports two operator values as equal when their
// NormalizeOperator forms match, folding ISE's ip*-alias spellings together.
func (v OperatorValue) StringSemanticEquals(ctx context.Context, newValuable basetypes.StringValuable) (bool, diag.Diagnostics) {
	var diags diag.Diagnostics
	newValue, ok := newValuable.(OperatorValue)
	if !ok {
		diags.AddError(
			"Semantic Equality Check Error",
			fmt.Sprintf("expected value type of helpers.OperatorValue but got %T", newValuable),
		)
		return false, diags
	}
	if v.IsNull() || v.IsUnknown() || newValue.IsNull() || newValue.IsUnknown() {
		return v.StringValue.Equal(newValue.StringValue), diags
	}
	return NormalizeOperator(v.ValueString()) == NormalizeOperator(newValue.ValueString()), diags
}

// NewOperatorNull returns a null OperatorValue.
func NewOperatorNull() OperatorValue {
	return OperatorValue{StringValue: basetypes.NewStringNull()}
}

// NewOperatorValue returns a known OperatorValue holding v.
func NewOperatorValue(v string) OperatorValue {
	return OperatorValue{StringValue: basetypes.NewStringValue(v)}
}
