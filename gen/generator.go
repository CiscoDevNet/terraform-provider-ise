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

//go:build ignore

package main

import (
	"bufio"
	"bytes"
	"fmt"
	"log"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"text/template"
	"unicode"

	"gopkg.in/yaml.v3"
)

const (
	definitionsPath   = "./gen/definitions/"
	providerTemplate  = "./gen/templates/provider.go"
	providerLocation  = "./internal/provider/provider.go"
	changelogTemplate = "./gen/templates/changelog.md.tmpl"
	changelogLocation = "./templates/guides/changelog.md.tmpl"
	changelogOriginal = "./CHANGELOG.md"
)

type t struct {
	path   string
	prefix string
	suffix string
}

var templates = []t{
	{
		path:   "./gen/templates/model.go",
		prefix: "./internal/provider/model_ise_",
		suffix: ".go",
	},
	{
		path:   "./gen/templates/data_source.go",
		prefix: "./internal/provider/data_source_ise_",
		suffix: ".go",
	},
	{
		path:   "./gen/templates/data_source_test.go",
		prefix: "./internal/provider/data_source_ise_",
		suffix: "_test.go",
	},
	{
		path:   "./gen/templates/resource.go",
		prefix: "./internal/provider/resource_ise_",
		suffix: ".go",
	},
	{
		path:   "./gen/templates/resource_test.go",
		prefix: "./internal/provider/resource_ise_",
		suffix: "_test.go",
	},
	{
		path:   "./gen/templates/data-source.tf",
		prefix: "./examples/data-sources/ise_",
		suffix: "/data-source.tf",
	},
	{
		path:   "./gen/templates/resource.tf",
		prefix: "./examples/resources/ise_",
		suffix: "/resource.tf",
	},
	{
		path:   "./gen/templates/import.sh",
		prefix: "./examples/resources/ise_",
		suffix: "/import.sh",
	},
}

type YamlConfig struct {
	Name                string                `yaml:"name"`
	RestEndpoint        string                `yaml:"rest_endpoint"`
	DeleteRestEndpoint  string                `yaml:"delete_rest_endpoint"`
	GetNoId             bool                  `yaml:"get_no_id"`
	NoDataSource        bool                  `yaml:"no_data_source"`
	NoResource          bool                  `yaml:"no_resource"`
	NoDelete            bool                  `yaml:"no_delete"`
	NoImport            bool                  `yaml:"no_import"`
	PostUpdate          bool                  `yaml:"post_update"`
	PutCreate           bool                  `yaml:"put_create"`
	PutIdQueryPath      bool                  `yaml:"put_id_query_path"`
	PutNoId             bool                  `yaml:"put_no_id"`
	PutDelete           bool                  `yaml:"put_delete"`
	PutRead             bool                  `yaml:"put_read"`
	NoRead              bool                  `yaml:"no_read"`
	NoUpdate            bool                  `yaml:"no_update"`
	UpdateDefault       bool                  `yaml:"update_default"`
	RootList            bool                  `yaml:"root_list"`
	NoReadPrefix        bool                  `yaml:"no_read_prefix"`
	NoId                bool                  `yaml:"no_id"`
	IdPath              string                `yaml:"id_path"`
	IdExample           string                `yaml:"id_example"`
	PutIdIncludePath    string                `yaml:"put_id_include_path"`
	DataSourceNameQuery bool                  `yaml:"data_source_name_query"`
	UseCache            bool                  `yaml:"use_cache"`
	CacheRestEndpoint   string                `yaml:"cache_rest_endpoint"`
	CachePageSize       int                   `yaml:"cache_page_size"`
	CacheRewrites       []YamlCacheRewrite    `yaml:"cache_rewrites"`
	MinimumVersion      string                `yaml:"minimum_version"`
	DsDescription       string                `yaml:"ds_description"`
	ResDescription      string                `yaml:"res_description"`
	DocCategory         string                `yaml:"doc_category"`
	ExcludeTest         bool                  `yaml:"exclude_test"`
	SkipMinimumTest     bool                  `yaml:"skip_minimum_test"`
	IgnoreDeleteError   string                `yaml:"ignore_delete_error"`
	Attributes          []YamlConfigAttribute `yaml:"attributes"`
	TestTags            []string              `yaml:"test_tags"`
	TestPrerequisites   string                `yaml:"test_prerequisites"`
}

// YamlCacheRewrite declares a single re-nesting of a field returned by a
// use_cache resource's bulk (modern API) endpoint, so its shape lines up with the
// path this resource's ERS-shaped model mapper (fromBody/updateFromBody/toBody)
// expects. Both paths are relative to the object as wrapped under the resource's
// cache data_path (see CacheDataPath).
type YamlCacheRewrite struct {
	From string `yaml:"from"`
	To   string `yaml:"to"`
}

type YamlConfigAttribute struct {
	ModelName              string                `yaml:"model_name"`
	TfName                 string                `yaml:"tf_name"`
	Type                   string                `yaml:"type"`
	ElementType            string                `yaml:"element_type"`
	DataPath               []string              `yaml:"data_path"`
	Id                     bool                  `yaml:"id"`
	Reference              bool                  `yaml:"reference"`
	DataSourceQuery        bool                  `yaml:"data_source_query"`
	ResponseDataPath       string                `yaml:"response_data_path"`
	ResponseValueRegex     string                `yaml:"response_value_regex"`
	Mandatory              bool                  `yaml:"mandatory"`
	Computed               bool                  `yaml:"computed"`
	ComputedWhen           string                `yaml:"computed_when"`
	Immutable              bool                  `yaml:"immutable"`
	WriteOnly              bool                  `yaml:"write_only"`
	WriteOnlyTF            bool                  `yaml:"write_only_tf"`
	WoVersion              bool                  `yaml:"-"` // Internal: marks a generated "<attr>_wo_version" companion attribute (state-only rotation trigger)
	CoexistingSecret       bool                  `yaml:"-"` // Internal: marks the legacy state-storing twin of a "<attr>_wo" write-only attribute
	WoBaseName             string                `yaml:"-"` // Internal: on a "<attr>_wo" attribute, the name of its legacy twin
	MutualExclusivityNote  string                `yaml:"-"` // Internal: documentation note carried by both halves of a write_only_tf pair
	WoPairMandatory        bool                  `yaml:"-"` // Internal: on a legacy twin, whether the pair must supply the secret through one of its halves
	WoPairHasVersion       bool                  `yaml:"-"` // Internal: on a legacy twin, whether a "_wo_version" companion was generated
	CoexistenceNote        string                `yaml:"coexistence_note"`
	NormalizeEmptyJson     bool                  `yaml:"normalize_empty_json"`
	NormalizeEmptyString   bool                  `yaml:"normalize_empty_string"`
	PreserveEmptyString    bool                  `yaml:"preserve_empty_string"`
	NormalizeOperator      bool                  `yaml:"normalize_operator"`
	SortCommaSeparated     bool                  `yaml:"sort_comma_separated"`
	WriteChangesOnly       bool                  `yaml:"write_changes_only"`
	ExcludeUpdate          bool                  `yaml:"exclude_update"`
	ExcludeTest            bool                  `yaml:"exclude_test"`
	RequiresReplace        bool                  `yaml:"requires_replace"`
	ExcludeExample         bool                  `yaml:"exclude_example"`
	Description            string                `yaml:"description"`
	Example                string                `yaml:"example"`
	EnumValues             []string              `yaml:"enum_values"`
	MinList                int64                 `yaml:"min_list"`
	MaxList                int64                 `yaml:"max_list"`
	MinInt                 int64                 `yaml:"min_int"`
	MaxInt                 int64                 `yaml:"max_int"`
	ZeroAllowed            bool                  `yaml:"zero_allowed"`
	ZeroAllowedDescription string                `yaml:"zero_allowed_description"`
	MinFloat               float64               `yaml:"min_float"`
	MaxFloat               float64               `yaml:"max_float"`
	StringPatterns         []string              `yaml:"string_patterns"`
	StringMinLength        int64                 `yaml:"string_min_length"`
	StringMaxLength        int64                 `yaml:"string_max_length"`
	DefaultValue           *string               `yaml:"default_value"`
	Value                  string                `yaml:"value"`
	TestValue              string                `yaml:"test_value"`
	MinimumTestValue       string                `yaml:"minimum_test_value"`
	TestTags               []string              `yaml:"test_tags"`
	Attributes             []YamlConfigAttribute `yaml:"attributes"`
	FilterEmptyValues      bool                  `yaml:"filter_empty_values"`
	CaseInsensitive        bool                  `yaml:"case_insensitive"`
	NotInCache             bool                  `yaml:"not_in_cache"`
}

// Templating helper function to convert TF name to GO name
func ToGoName(s string) string {
	var g []string

	p := strings.Split(s, "_")

	for _, value := range p {
		g = append(g, strings.Title(value))
	}
	s = strings.Join(g, "")
	return s
}

// Templating helper function to convert string to camel case
func CamelCase(s string) string {
	var g []string

	s = strings.ReplaceAll(s, "-", " ")
	p := strings.Fields(s)

	for _, value := range p {
		g = append(g, strings.Title(value))
	}
	return strings.Join(g, "")
}

// Templating helper function to convert string to snake case
func SnakeCase(s string) string {
	var g []string

	s = strings.ReplaceAll(s, "-", " ")
	p := strings.Fields(s)

	for _, value := range p {
		g = append(g, strings.ToLower(value))
	}
	return strings.Join(g, "_")
}

// Templating helper function to build a SJSON path
func BuildPath(s []string) string {
	return strings.Join(s, ".")
}

func contains(s []string, str string) bool {
	for _, v := range s {
		if v == str {
			return true
		}
	}
	return false
}

// Templating helper function to return the ID attribute
func GetId(attributes []YamlConfigAttribute) YamlConfigAttribute {
	for _, attr := range attributes {
		if attr.Id {
			return attr
		}
	}
	return YamlConfigAttribute{}
}

// Templating helper function to return true if id included in attributes
func HasId(attributes []YamlConfigAttribute) bool {
	for _, attr := range attributes {
		if attr.Id {
			return true
		}
	}
	return false
}

// ComputedWhenAttr returns the attribute name from a "<attr>=<bool>" expression.
func ComputedWhenAttr(expr string) string {
	parts := strings.SplitN(expr, "=", 2)
	return strings.TrimSpace(parts[0])
}

// ComputedWhenValue returns the bool literal from a "<attr>=<bool>" expression (default "false").
func ComputedWhenValue(expr string) string {
	parts := strings.SplitN(expr, "=", 2)
	if len(parts) < 2 || strings.TrimSpace(parts[1]) == "" {
		return "false"
	}
	return strings.TrimSpace(parts[1])
}

func HasComputedWhen(attributes []YamlConfigAttribute) bool {
	for _, attr := range attributes {
		if attr.ComputedWhen != "" {
			return true
		}
	}
	return false
}

// ComputedWhenModelName returns the ISE model (JSON) name of the sibling attribute in a
// "<tf_name>=<bool>" computed_when expression, e.g. "static_group_assignment" ->
// "staticGroupAssignment" (lower camelCase, matching ERS field naming).
func ComputedWhenModelName(expr string) string {
	parts := strings.Split(ComputedWhenAttr(expr), "_")
	for i, p := range parts {
		if i > 0 {
			parts[i] = strings.Title(p)
		}
	}
	return strings.Join(parts, "")
}

// Templating helper function to return true if reference included in attributes
func HasReference(attributes []YamlConfigAttribute) bool {
	for _, attr := range attributes {
		if attr.Reference {
			return true
		}
	}
	return false
}

// Templating helper function to return number of import parts
func ImportParts(attributes []YamlConfigAttribute) int {
	parts := 1
	for _, attr := range attributes {
		if attr.Reference {
			parts += 1
		} else if attr.Id {
			parts += 1
		}
	}
	return parts
}

// Templating helper function to subtract one number from another
func Subtract(a, b int) int {
	return a - b
}

// HasWriteOnlyTFChildren reports whether a list/set attribute has at least one direct
// child flagged write_only_tf (after augmentation, these children are the renamed "_wo"
// leaves — detectable via the still-set WriteOnlyTF flag, which augmentWriteOnlyTF
// preserves on the renamed attribute). Used by resource.go to decide whether to emit the
// "read the whole parent list from config" block for nested write-only secrets.
func HasWriteOnlyTFChildren(attr YamlConfigAttribute) bool {
	for _, child := range attr.Attributes {
		if child.WriteOnlyTF {
			return true
		}
	}
	return false
}

// WriteOnlyTFChildren returns the direct children of a list/set attribute that are flagged
// write_only_tf (the renamed "_wo" leaves). Used to copy each write-only leaf from the
// config-read temp back into the plan element in the generated nested config-read block.
func WriteOnlyTFChildren(attr YamlConfigAttribute) []YamlConfigAttribute {
	r := []YamlConfigAttribute{}
	for _, child := range attr.Attributes {
		if child.WriteOnlyTF {
			r = append(r, child)
		}
	}
	return r
}

// CoexistingSecretAttributes returns the top-level legacy twins of write-only
// secrets, i.e. the attributes kept for backwards compatibility when their "_wo" variant
// was generated. Nested secrets are not included: they would need a per-element walk of
// the enclosing list, and this coexistence note is currently only surfaced in the
// documentation.
func CoexistingSecretAttributes(config YamlConfig) []YamlConfigAttribute {
	r := []YamlConfigAttribute{}
	for _, attr := range config.Attributes {
		if attr.CoexistingSecret {
			r = append(r, attr)
		}
	}
	return r
}

// CoexistingSecretChildren returns the legacy twins of write-only secrets nested
// directly inside a list/set attribute. ValidateConfig applies the same pair checks to
// them, once per list element.
func CoexistingSecretChildren(attr YamlConfigAttribute) []YamlConfigAttribute {
	r := []YamlConfigAttribute{}
	for _, child := range attr.Attributes {
		if child.CoexistingSecret {
			r = append(r, child)
		}
	}
	return r
}

// CoexistingSecretParentLists returns the top-level list/set attributes holding at least
// one legacy twin of a write-only secret. ValidateConfig reads each such list from the
// configuration once and walks its elements.
func CoexistingSecretParentLists(config YamlConfig) []YamlConfigAttribute {
	r := []YamlConfigAttribute{}
	for _, attr := range config.Attributes {
		if len(CoexistingSecretChildren(attr)) > 0 {
			r = append(r, attr)
		}
	}
	return r
}

// WriteOnlyTFParentLists returns the top-level list/set attributes that contain at least
// one write_only_tf child. Emitted once per parent list in the Create/Update config-read
// codegen.
func WriteOnlyTFParentLists(config YamlConfig) []YamlConfigAttribute {
	r := []YamlConfigAttribute{}
	for _, attr := range config.Attributes {
		if HasWriteOnlyTFChildren(attr) {
			r = append(r, attr)
		}
	}
	return r
}

// Templating helper function to return true if ERS API endpoint
func IsErs(endpoint string) bool {
	if strings.HasPrefix(endpoint, "/ers") {
		return true
	}
	return false
}

// Templating helper function to remove first path element
func RemoveFirstPathElement(path string) string {
	elements := strings.Split(path, ".")
	return strings.Join(elements[1:], ".")
}

// Templating helper function to return true if type is a list or set without nested elements
func IsListSet(attribute YamlConfigAttribute) bool {
	if (attribute.Type == "List" || attribute.Type == "Set") && attribute.ElementType != "" {
		return true
	}
	return false
}

// Templating helper function to return true if type is a list without nested elements
func IsList(attribute YamlConfigAttribute) bool {
	if attribute.Type == "List" && attribute.ElementType != "" {
		return true
	}
	return false
}

// Templating helper function to return true if type is a set without nested elements
func IsSet(attribute YamlConfigAttribute) bool {
	if attribute.Type == "Set" && attribute.ElementType != "" {
		return true
	}
	return false
}

// Templating helper function to return true if type is a list or set of strings without nested elements
func IsStringListSet(attribute YamlConfigAttribute) bool {
	if (attribute.Type == "List" || attribute.Type == "Set") && attribute.ElementType == "String" {
		return true
	}
	return false
}

// Templating helper function to return true if type is a list or set of integers without nested elements
func IsInt64ListSet(attribute YamlConfigAttribute) bool {
	if (attribute.Type == "List" || attribute.Type == "Set") && attribute.ElementType == "Int64" {
		return true
	}
	return false
}

// Templating helper function to return true if type is a list or set with nested elements
func IsNestedListSet(attribute YamlConfigAttribute) bool {
	if (attribute.Type == "List" || attribute.Type == "Set") && attribute.ElementType == "" {
		return true
	}
	return false
}

// Templating helper function to return true if type is a list with nested elements
func IsNestedList(attribute YamlConfigAttribute) bool {
	if attribute.Type == "List" && attribute.ElementType == "" {
		return true
	}
	return false
}

// Templating helper function to return true if type is a set with nested elements
func IsNestedSet(attribute YamlConfigAttribute) bool {
	if attribute.Type == "Set" && attribute.ElementType == "" {
		return true
	}
	return false
}

// Templating helper function to return true if resource has specific attribute
func HasAttribute(attributes []YamlConfigAttribute, attrName string) bool {
	for _, attr := range attributes {
		if attr.TfName == attrName {
			return true
		}
	}
	return false
}

// CacheDataPath returns the common top-level response wrapper used by a resource.
// Cached modern API objects must be adapted to the resource's existing response
// shape before the normal model mapper consumes them.
func CacheDataPath(attributes []YamlConfigAttribute) string {
	for _, attr := range attributes {
		if len(attr.DataPath) > 0 {
			return attr.DataPath[0]
		}
	}
	return ""
}

// NotInCacheAttributes returns the top-level attributes flagged not_in_cache, i.e.
// attributes that are absent entirely from a use_cache resource's bulk endpoint
// payload. ReadCache re-injects each one's current state value into the cached
// response before the model mapper runs, so the cache never reports them as drift.
func NotInCacheAttributes(attributes []YamlConfigAttribute) []YamlConfigAttribute {
	var result []YamlConfigAttribute
	for _, attr := range attributes {
		if attr.NotInCache {
			result = append(result, attr)
		}
	}
	return result
}

// HasNotInCacheAttribute returns true if any top-level attribute is flagged
// not_in_cache. Resources with such attributes must bypass the cache entirely on
// import (state entirely null), since re-injecting a state value is not possible
// when there is no prior state to read it from.
func HasNotInCacheAttribute(attributes []YamlConfigAttribute) bool {
	return len(NotInCacheAttributes(attributes)) > 0
}

// Map of templating functions
var functions = template.FuncMap{
	"toGoName":                    ToGoName,
	"camelCase":                   CamelCase,
	"strContains":                 strings.Contains,
	"strReplace":                  strings.Replace,
	"snakeCase":                   SnakeCase,
	"sprintf":                     fmt.Sprintf,
	"toLower":                     strings.ToLower,
	"path":                        BuildPath,
	"hasId":                       HasId,
	"getId":                       GetId,
	"computedWhenAttr":            ComputedWhenAttr,
	"computedWhenValue":           ComputedWhenValue,
	"computedWhenModelName":       ComputedWhenModelName,
	"hasComputedWhen":             HasComputedWhen,
	"hasReference":                HasReference,
	"importParts":                 ImportParts,
	"subtract":                    Subtract,
	"isErs":                       IsErs,
	"removeFirstPathElement":      RemoveFirstPathElement,
	"isListSet":                   IsListSet,
	"isList":                      IsList,
	"isSet":                       IsSet,
	"isStringListSet":             IsStringListSet,
	"isInt64ListSet":              IsInt64ListSet,
	"isNestedListSet":             IsNestedListSet,
	"isNestedList":                IsNestedList,
	"isNestedSet":                 IsNestedSet,
	"hasAttribute":                HasAttribute,
	"cacheDataPath":               CacheDataPath,
	"notInCacheAttributes":        NotInCacheAttributes,
	"hasNotInCacheAttribute":      HasNotInCacheAttribute,
	"goValueType":                 GoValueType,
	"goValueCtor":                 GoValueCtor,
	"goNullCtor":                  GoNullCtor,
	"hasWriteOnlyTFChildren":      HasWriteOnlyTFChildren,
	"writeOnlyTFChildren":         WriteOnlyTFChildren,
	"writeOnlyTFParentLists":      WriteOnlyTFParentLists,
	"coexistingSecretAttributes":  CoexistingSecretAttributes,
	"coexistingSecretChildren":    CoexistingSecretChildren,
	"coexistingSecretParentLists": CoexistingSecretParentLists,
}

// GoValueType returns the Go type for an attribute's model struct field.
// String attributes flagged normalize_operator use the custom helpers.OperatorValue
// type so the framework folds ISE's ip*-alias operator spellings via semantic equality.
// String attributes flagged case_insensitive use the custom
// helpers.CaseInsensitiveStringValue type so the framework treats a case-only
// difference as no change via semantic equality, instead of a plan modifier (which
// cannot legally rewrite a Required/non-Computed attribute's planned value). Currently
// only wired up for top-level (non-nested) attributes — see fromBody/updateFromBody in
// gen/templates/model.go.
func GoValueType(attr YamlConfigAttribute) string {
	if attr.Type == "String" && attr.NormalizeOperator {
		return "helpers.OperatorValue"
	}
	if attr.Type == "String" && attr.CaseInsensitive {
		return "helpers.CaseInsensitiveStringValue"
	}
	return "types." + attr.Type
}

// GoValueCtor returns the constructor call (including the argument) that builds a
// known value for an attribute, honoring the custom operator/case-insensitive types.
func GoValueCtor(attr YamlConfigAttribute, arg string) string {
	if attr.Type == "String" && attr.NormalizeOperator {
		return "helpers.NewOperatorValue(" + arg + ")"
	}
	if attr.Type == "String" && attr.CaseInsensitive {
		return "helpers.NewCaseInsensitiveStringValue(" + arg + ")"
	}
	return "types." + attr.Type + "Value(" + arg + ")"
}

// GoNullCtor returns the constructor call that builds a null value for an attribute,
// honoring the custom operator/case-insensitive types.
func GoNullCtor(attr YamlConfigAttribute) string {
	if attr.Type == "String" && attr.NormalizeOperator {
		return "helpers.NewOperatorNull()"
	}
	if attr.Type == "String" && attr.CaseInsensitive {
		return "helpers.NewCaseInsensitiveStringNull()"
	}
	return "types." + attr.Type + "Null()"
}

func augmentAttribute(attr *YamlConfigAttribute) {
	if attr.TfName == "" {
		var words []string
		l := 0
		for s := attr.ModelName; s != ""; s = s[l:] {
			l = strings.IndexFunc(s[1:], unicode.IsUpper) + 1
			if l <= 0 {
				l = len(s)
			}
			words = append(words, strings.ToLower(s[:l]))
		}
		attr.TfName = strings.Join(words, "_")
	}
	if attr.Type == "List" || attr.Type == "Set" {
		for a := range attr.Attributes {
			augmentAttribute(&attr.Attributes[a])
		}
	}
}

// validateCacheRewrites hard-fails code generation when a resource's
// cache_rewrites (gen/schema/schema.yaml's cache_rewrite) would produce generated
// code that silently loses data at runtime. Both shapes below were confirmed unsafe
// by hand-testing gjson.Get/sjson.Delete/sjson.SetRaw against reference payloads in
// a standalone harness, not by reading their docs:
//
//   - "to" is an ancestor of its own "from" (e.g. from: a.b.c, to: a.b): sjson.SetRaw
//     replaces the *entire* node at "to", so a sibling of "from" living under "to"
//     (e.g. a.b.d) is silently destroyed. The reverse direction ("to" is a
//     descendant of "from", e.g. endpoint's customAttributes ->
//     customAttributes.customAttributes) is safe: "from" is deleted in full before
//     "to" is written, so nothing of value is left behind at the old location.
//   - two rewrite entries overlap: one entry's "to" equals another entry's "from"
//     (the value moved into "to" is consumed away by the other rewrite's own
//     Delete/SetRaw before it can be read back out), or two entries share the same
//     "to" (the second SetRaw silently discards the first entry's write).
//
// cache_rewrites is also rejected outright when use_cache is not set, since it has
// no effect anywhere else.
func validateCacheRewrites(config *YamlConfig) {
	if len(config.CacheRewrites) == 0 {
		return
	}
	if !config.UseCache {
		log.Fatalf("%s: cache_rewrites is set but use_cache is not true; cache_rewrites only has any effect on a use_cache resource's generated ReadCache", config.Name)
	}
	segments := func(p string) []string { return strings.Split(p, ".") }
	// isAncestor reports whether `ancestor` is a strict, proper prefix of `descendant`
	// (i.e. `descendant` is nested under `ancestor`, not equal to it).
	isAncestor := func(ancestor, descendant []string) bool {
		if len(ancestor) >= len(descendant) {
			return false
		}
		for i, s := range ancestor {
			if descendant[i] != s {
				return false
			}
		}
		return true
	}
	for _, rw := range config.CacheRewrites {
		if isAncestor(segments(rw.To), segments(rw.From)) {
			log.Fatalf("%s: cache_rewrites entry {from: %s, to: %s} is unsafe: \"to\" is an ancestor of its own \"from\"; re-writing \"to\" would silently discard any sibling data living under it that isn't part of this rewrite", config.Name, rw.From, rw.To)
		}
	}
	for i, a := range config.CacheRewrites {
		for j, b := range config.CacheRewrites {
			if i == j {
				continue
			}
			if a.To == b.From {
				log.Fatalf("%s: cache_rewrites entries {from: %s, to: %s} and {from: %s, to: %s} overlap: the first entry's \"to\" is the second entry's \"from\", so the value moved to \"to\" is deleted/overwritten by the other rewrite before it can be read back out of there", config.Name, a.From, a.To, b.From, b.To)
			}
			if i < j && a.To == b.To {
				log.Fatalf("%s: cache_rewrites entries {from: %s, to: %s} and {from: %s, to: %s} overlap: both write to the same \"to\", so the second SetRaw silently discards the first entry's write", config.Name, a.From, a.To, b.From, b.To)
			}
		}
	}
}

// validateNotInCache hard-fails code generation for two not_in_cache misuses on a
// top-level attribute (mirroring NotInCacheAttributes' scope, which likewise only
// looks at top-level attributes):
//
//   - not_in_cache set without use_cache: true, since it has no effect anywhere else.
//   - not_in_cache set on a mandatory attribute: a mandatory attribute is always
//     supplied by config/plan, so re-injecting the prior state value into a cached
//     Read can only ever mask real drift on that attribute, never legitimately fill
//     in a value config didn't provide.
func validateNotInCache(config *YamlConfig) {
	for _, attr := range config.Attributes {
		if !attr.NotInCache {
			continue
		}
		if !config.UseCache {
			log.Fatalf("%s: attribute %q sets not_in_cache but use_cache is not true; not_in_cache only has any effect on a use_cache resource's generated ReadCache", config.Name, attr.ModelName)
		}
		if attr.Mandatory {
			log.Fatalf("%s: attribute %q sets not_in_cache but is also mandatory; a mandatory attribute is always supplied by config/plan, so re-injecting the prior state value on a cached Read can only mask real drift on it, never legitimately fill in a value", config.Name, attr.ModelName)
		}
	}
}

func augmentConfig(config *YamlConfig) {
	// use_cache pages through cache_rest_endpoint by comparing the page length against
	// cache_page_size; yamale cannot express "cache_page_size is required whenever
	// use_cache is true", so a missing or non-positive value is caught here instead. Left
	// unchecked, `len(values.Array()) < 0` in the generated ReadCache loop is never true,
	// so the loop never terminates and hammers the API with an unbounded number of
	// requests.
	if config.UseCache && config.CachePageSize <= 0 {
		log.Fatalf("%s: use_cache is true but cache_page_size is missing or <= 0; set cache_page_size (e.g. 100) or the generated cache loader will page forever", config.Name)
	}
	validateCacheRewrites(config)
	validateNotInCache(config)
	for ia := range config.Attributes {
		augmentAttribute(&config.Attributes[ia])
	}
	// For each top-level attribute marked write_only_tf, rename it to "<tf_name>_wo"
	// (the Terraform-core write-only attribute) and inject a companion
	// "<tf_name>_wo_version" (Int64, Optional) that IS stored in state and drives
	// rotation. The base name (before "_wo") is derived once, since augmentAttribute
	// has already populated TfName.
	augmentWriteOnlyTF(config)
	if config.DsDescription == "" {
		config.DsDescription = fmt.Sprintf("This data source can read the %s.", config.Name)
	}
	if config.ResDescription == "" {
		name := strings.ToLower(config.Name)
		if strings.HasPrefix(name, "a") || strings.HasPrefix(name, "e") || strings.HasPrefix(name, "i") || strings.HasPrefix(name, "o") || strings.HasPrefix(name, "u") {
			config.ResDescription = fmt.Sprintf("This resource can manage an %s.", config.Name)
		} else {
			config.ResDescription = fmt.Sprintf("This resource can manage a %s.", config.Name)
		}
	}
}

// augmentWriteOnlyTF expands every attribute flagged write_only_tf into three
// coexisting attributes, so that adding write-only support is backwards compatible:
//
//	<tf_name>              the original attribute, kept as-is. Still Optional
//	                       and still written to the same API path, so existing
//	                       configurations keep working. The secret remains in state.
//	<tf_name>_wo           the Terraform-core write-only variant. Same ModelName /
//	                       DataPath / PutDataPath, so the secret reaches the same API
//	                       field, but it is never persisted to plan or state.
//	<tf_name>_wo_version   Int64, Optional, stored in state, never sent to the API.
//	                       The rotation trigger for the write-only variant.
//
// The legacy attribute and the "_wo" variant are mutually exclusive; the schema
// template emits ExactlyOneOf when the secret is mandatory and ConflictsWith when it
// is optional. Because both carry the same ModelName, toBody writes whichever of the
// two is non-null to the same JSON path, and the validators guarantee they are never
// both set.
func augmentWriteOnlyTF(config *YamlConfig) {
	config.Attributes = rewriteWriteOnlyTF(config.Attributes)
}

// rewriteWriteOnlyTF walks a single attribute list. For each attribute it first
// recurses into any nested children (list-of-objects), so a write-only secret nested
// arbitrarily deep is expanded too. Then, if the attribute itself is flagged
// write_only_tf, it is replaced by the legacy/"_wo"/"_wo_version" triple described on
// augmentWriteOnlyTF. Nested secrets get a per-element version companion, matching the
// per-element rotation granularity of the enclosing list.
func rewriteWriteOnlyTF(attrs []YamlConfigAttribute) []YamlConfigAttribute {
	newAttrs := make([]YamlConfigAttribute, 0, len(attrs))
	for _, attr := range attrs {
		if len(attr.Attributes) > 0 {
			attr.Attributes = rewriteWriteOnlyTF(attr.Attributes)
		}
		if !attr.WriteOnlyTF {
			newAttrs = append(newAttrs, attr)
			continue
		}
		// The generated "_wo" schema entry emits []validator.String, so a non-String
		// secret would not compile. Fail here rather than at build time, with a message
		// that names the offending attribute.
		if attr.Type != "String" {
			panic(fmt.Sprintf("write_only_tf is only supported on String attributes, but %q has type %q", attr.TfName, attr.Type))
		}
		// write_only_tf relies on write_only to keep the secret out of the read path.
		// fromBody and updateFromBody skip attributes on .WriteOnly alone, so a secret
		// flagged write_only_tf without it would have the API response written back into
		// its "_wo" field on every read. The framework nulls write-only attributes before
		// they reach state, so that is currently dead work rather than a leak, but it
		// leaves the guarantee resting entirely on framework behaviour. Require the flags
		// together instead.
		if !attr.WriteOnly {
			panic(fmt.Sprintf("write_only_tf requires write_only to be set as well, but %q sets only write_only_tf", attr.TfName))
		}
		baseName := attr.TfName

		// Both halves of the pair document the constraint the validators enforce.
		// tfplugindocs derives Required/Optional from the schema booleans alone, so a
		// mandatory secret reachable through either spelling would otherwise be listed as
		// merely Optional twice, with nothing saying one of them has to be supplied.
		// Computed from the original attribute, before Mandatory is cleared below.
		// A mandatory secret leads with "**Required**" because the pair is listed under
		// the documentation's Optional heading: neither half can carry the schema's
		// Required flag without making that spelling the only usable one, so the word has
		// to come from the description instead.
		exclusivity := fmt.Sprintf("Only one of `%s` and `%s_wo` can be set.", baseName, baseName)
		if attr.Mandatory {
			exclusivity = fmt.Sprintf("**Required**: exactly one of `%s` and `%s_wo` must be set.", baseName, baseName)
		}

		// The legacy attribute keeps its name and its place in the schema so existing
		// configurations are untouched. It is no longer Mandatory on its own, because the
		// "_wo" variant is an equally valid way to supply the secret; ExactlyOneOf carries
		// that requirement instead. It is excluded from the generated acceptance tests so
		// the test configurations exercise the write-only path and do not trip the
		// mutual-exclusion validator by setting both spellings.
		legacy := attr
		legacy.WriteOnlyTF = false
		legacy.CoexistingSecret = true
		legacy.Mandatory = false
		legacy.ExcludeTest = true
		legacy.ExcludeExample = true
		// MinimumTestValue has to be cleared as well, not just ExcludeTest: the minimum
		// test configuration selects attributes on MinimumTestValue without consulting
		// ExcludeTest, so a secret carrying one would otherwise be emitted alongside its
		// "_wo" twin and trip the mutual-exclusion validator.
		legacy.MinimumTestValue = ""
		legacy.CoexistenceNote = fmt.Sprintf("This attribute stores the secret in Terraform state. Prefer `%s_wo` together with `%s_wo_version`, which keeps it out of state.", baseName, baseName)
		legacy.MutualExclusivityNote = exclusivity
		legacy.WoPairMandatory = attr.Mandatory
		legacy.WoPairHasVersion = !attr.RequiresReplace
		newAttrs = append(newAttrs, legacy)

		// The write-only variant is always Optional in the schema, because the legacy
		// attribute is an equally valid way to supply the secret. Mandatory is kept so the
		// template can pick ExactlyOneOf (the secret must come from one of the two) over
		// ConflictsWith (at most one of the two) for the mutual-exclusion validator.
		wo := attr
		wo.TfName = baseName + "_wo"
		wo.WoBaseName = baseName
		wo.MutualExclusivityNote = exclusivity
		newAttrs = append(newAttrs, wo)

		// requires_replace secrets rotate by recreate, so a state-stored version int
		// (which can only drive an in-place update) is meaningless. Convert to write-only
		// but drop the version companion.
		if attr.RequiresReplace {
			continue
		}

		version := YamlConfigAttribute{
			TfName:      baseName + "_wo_version",
			Type:        "Int64",
			WoVersion:   true,
			Description: fmt.Sprintf("Rotation trigger for `%s_wo`. Increment this integer whenever the write-only value changes so Terraform sends the new secret. The value is stored in state; the secret is not.", baseName),
			Example:     "1",
			ExcludeTest: attr.ExcludeTest,
		}
		// The version belongs in the minimum test configuration exactly when its "_wo"
		// secret does, since the schema requires the pair together. The minimum template
		// selects on Mandatory/MinimumTestValue and does not consult ExcludeTest, so both
		// conditions have to be mirrored here or the version would be emitted alone.
		if !attr.ExcludeTest && (attr.Mandatory || attr.MinimumTestValue != "") {
			version.MinimumTestValue = "1"
		}
		newAttrs = append(newAttrs, version)
	}
	return newAttrs
}

func getTemplateSection(content, name string) string {
	scanner := bufio.NewScanner(strings.NewReader(content))
	result := ""
	foundSection := false
	beginRegex := regexp.MustCompile(`\/\/template:begin\s` + name + `$`)
	endRegex := regexp.MustCompile(`\/\/template:end\s` + name + `$`)
	for scanner.Scan() {
		line := scanner.Text()
		if !foundSection {
			match := beginRegex.MatchString(line)
			if match {
				foundSection = true
				result += line + "\n"
			}
		} else {
			result += line + "\n"
			match := endRegex.MatchString(line)
			if match {
				foundSection = false
			}
		}
	}
	return result
}

func renderTemplate(templatePath, outputPath string, config interface{}) {
	file, err := os.Open(templatePath)
	if err != nil {
		log.Fatalf("Error opening template: %v", err)
	}
	defer file.Close()

	// skip first line with 'build-ignore' directive for go files
	scanner := bufio.NewScanner(file)
	if strings.HasSuffix(templatePath, ".go") {
		scanner.Scan()
	}
	var temp string
	for scanner.Scan() {
		temp = temp + scanner.Text() + "\n"
	}

	template, err := template.New(path.Base(templatePath)).Funcs(functions).Parse(temp)
	if err != nil {
		log.Fatalf("Error parsing template: %v", err)
	}

	output := new(bytes.Buffer)
	err = template.Execute(output, config)
	if err != nil {
		log.Fatalf("Error executing template: %v", err)
	}

	outputFile := filepath.Join(outputPath)
	existingFile, err := os.Open(outputPath)
	if err != nil {
		os.MkdirAll(filepath.Dir(outputFile), 0755)
	} else if strings.HasSuffix(templatePath, ".go") {
		existingScanner := bufio.NewScanner(existingFile)
		var newContent string
		currentSectionName := ""
		beginRegex := regexp.MustCompile(`\/\/template:begin\s(.*?)$`)
		endRegex := regexp.MustCompile(`\/\/template:end\s(.*?)$`)
		for existingScanner.Scan() {
			line := existingScanner.Text()
			if currentSectionName == "" {
				matches := beginRegex.FindStringSubmatch(line)
				if len(matches) > 1 && matches[1] != "" {
					currentSectionName = matches[1]
				} else {
					newContent += line + "\n"
				}
			} else {
				matches := endRegex.FindStringSubmatch(line)
				if len(matches) > 1 && matches[1] == currentSectionName {
					currentSectionName = ""
					newSection := getTemplateSection(string(output.Bytes()), matches[1])
					newContent += newSection
				}
			}
		}
		output = bytes.NewBufferString(newContent)
	}
	// write to output file
	f, err := os.Create(outputFile)
	if err != nil {
		log.Fatalf("Error creating output file: %v", err)
	}
	f.Write(output.Bytes())
}

func main() {
	files, _ := os.ReadDir(definitionsPath)
	configs := make([]YamlConfig, len(files))

	// Load configs
	for i, filename := range files {
		yamlFile, err := os.ReadFile(filepath.Join(definitionsPath, filename.Name()))
		if err != nil {
			log.Fatalf("Error reading file: %v", err)
		}

		config := YamlConfig{}
		err = yaml.Unmarshal(yamlFile, &config)
		if err != nil {
			log.Fatalf("Error parsing yaml: %v", err)
		}
		configs[i] = config
	}

	for i := range configs {
		// Augment config
		augmentConfig(&configs[i])

		// Iterate over templates and render files
		for _, t := range templates {
			if (configs[i].NoImport && t.path == "./gen/templates/import.sh") ||
				(configs[i].NoDataSource && t.path == "./gen/templates/data_source.go") ||
				(configs[i].NoDataSource && t.path == "./gen/templates/data_source_test.go") ||
				(configs[i].NoDataSource && t.path == "./gen/templates/data-source.tf") ||
				(configs[i].NoResource && t.path == "./gen/templates/resource.go") ||
				(configs[i].NoResource && t.path == "./gen/templates/resource_test.go") ||
				(configs[i].NoResource && t.path == "./gen/templates/resource.tf") ||
				(configs[i].NoResource && t.path == "./gen/templates/import.sh") {
				continue
			}
			renderTemplate(t.path, t.prefix+SnakeCase(configs[i].Name)+t.suffix, configs[i])
		}
	}

	// render provider.go
	renderTemplate(providerTemplate, providerLocation, configs)

	changelog, err := os.ReadFile(changelogOriginal)
	if err != nil {
		log.Fatalf("Error reading changelog: %v", err)
	}
	renderTemplate(changelogTemplate, changelogLocation, string(changelog))
}
