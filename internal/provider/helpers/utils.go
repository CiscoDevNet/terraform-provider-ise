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
	"encoding/json"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/tidwall/gjson"
)

func Contains(s []string, str string) bool {
	for _, v := range s {
		if v == str {
			return true
		}
	}
	return false
}

func GetStringMap(result map[string]gjson.Result) types.Map {
	v := make(map[string]attr.Value)
	for key, value := range result {
		v[key] = types.StringValue(value.String())
	}
	return types.MapValueMust(types.StringType, v)
}

// GetStringMapNonEmpty is used for ISE map attributes where the API returns
// globally-defined-but-unassigned keys as empty strings (e.g. endpoint custom
// attributes), and "" semantically means unset. Empty-string entries are dropped.
// When all entries are empty the result is an empty (non-null) map.
func GetStringMapNonEmpty(result map[string]gjson.Result) types.Map {
	v := make(map[string]attr.Value)
	for key, value := range result {
		if value.String() != "" {
			v[key] = types.StringValue(value.String())
		}
	}
	// No entries: treat as unset (null) rather than an empty map, so an Optional map
	// imported/read from a server that returns {} does not drift against a null config.
	if len(v) == 0 {
		return types.MapNull(types.StringType)
	}
	return types.MapValueMust(types.StringType, v)
}

// GetStringMapNonEmptyOrNull is like GetStringMapNonEmpty but returns null when
// all entries are empty strings — preventing drift when a config that omits the
// attribute is compared to an ISE response where all custom attribute values are "".
func GetStringMapNonEmptyOrNull(result map[string]gjson.Result) types.Map {
	v := make(map[string]attr.Value)
	for key, value := range result {
		if value.String() != "" {
			v[key] = types.StringValue(value.String())
		}
	}
	if len(v) == 0 {
		return types.MapNull(types.StringType)
	}
	return types.MapValueMust(types.StringType, v)
}

// GetStringMapFiltered returns only the keys already present in stateMap (with
// live values from apiResult), suppressing server-injected keys that were never
// declared in configuration. When stateMap is null or unknown (import), all
// apiResult keys are accepted.
func GetStringMapFiltered(apiResult map[string]gjson.Result, stateMap types.Map) types.Map {
	if stateMap.IsNull() || stateMap.IsUnknown() {
		return GetStringMap(apiResult)
	}
	v := make(map[string]attr.Value)
	for key := range stateMap.Elements() {
		if val, ok := apiResult[key]; ok {
			v[key] = types.StringValue(val.String())
		} else {
			v[key] = types.StringValue("")
		}
	}
	return types.MapValueMust(types.StringType, v)
}

// CompactJson normalizes a raw JSON string to compact form (no extra whitespace).
// This prevents perpetual drift when an API returns pretty-printed JSON while
// Terraform config uses jsonencode, which always produces compact JSON.
// If the input is not valid JSON it is returned unchanged.
func CompactJson(s string) string {
	var buf bytes.Buffer
	if err := json.Compact(&buf, []byte(s)); err != nil {
		return s
	}
	return buf.String()
}

// NormalizeOperator maps ISE IP-specific operator variants to their standard
// equivalents so that conditions written with "equals" are not perpetually
// re-applied just because ISE stores and returns the same condition as "ipEquals".
// Any operator not in the map is returned unchanged.
func NormalizeOperator(op string) string {
	switch op {
	case "ipEquals":
		return "equals"
	case "ipNotEquals":
		return "notEquals"
	case "ipGreaterThan":
		return "greaterThan"
	case "ipLessThan":
		return "lessThan"
	}
	return op
}

// MatchKey compares an API-returned key value against the desired key value for
// keyed-list matching. When normalize is true (the key attribute carries
// normalize_operator), both sides are run through NormalizeOperator so that an
// ISE "ipEquals" matches a configured "equals". When normalize is false the
// comparison is verbatim, so a literal value such as a TACACS argument of
// "ipEquals" is never coerced.
func MatchKey(apiValue, keyValue string, normalize bool) bool {
	if normalize {
		return NormalizeOperator(apiValue) == NormalizeOperator(keyValue)
	}
	return apiValue == keyValue
}

func GetStringList(result []gjson.Result) types.List {
	v := make([]attr.Value, len(result))
	for r := range result {
		v[r] = types.StringValue(result[r].String())
	}
	return types.ListValueMust(types.StringType, v)
}

func GetInt64List(result []gjson.Result) types.List {
	v := make([]attr.Value, len(result))
	for r := range result {
		v[r] = types.Int64Value(result[r].Int())
	}
	return types.ListValueMust(types.Int64Type, v)
}

func GetStringSet(result []gjson.Result) types.Set {
	v := make([]attr.Value, len(result))
	for r := range result {
		v[r] = types.StringValue(result[r].String())
	}
	return types.SetValueMust(types.StringType, v)
}

func GetInt64Set(result []gjson.Result) types.Set {
	v := make([]attr.Value, len(result))
	for r := range result {
		v[r] = types.Int64Value(result[r].Int())
	}
	return types.SetValueMust(types.Int64Type, v)
}
