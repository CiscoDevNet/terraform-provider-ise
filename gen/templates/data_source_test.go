//go:build ignore
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

// Code generated by "gen/generator.go"; DO NOT EDIT.

package provider

//template:begin imports
import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)
//template:end imports

//template:begin testAccDataSource
func TestAccDataSourceIse{{camelCase .Name}}(t *testing.T) {
	{{- if len .TestTags}}
	if {{range $i, $e := .TestTags}}{{if $i}} && {{end}}os.Getenv("{{$e}}") == ""{{end}} {
        t.Skip("skipping test, set environment variable {{range $i, $e := .TestTags}}{{if $i}} or {{end}}{{$e}}{{end}}")
	}
	{{- end}}
	var checks []resource.TestCheckFunc
	{{- $name := .Name }}
	{{- range  .Attributes}}
	{{- if and (not .WriteOnly) (not .ExcludeTest) (not .TfOnly) (not .Value) (not .TestValue)}}
	{{- if or (eq .Type "List") (eq .Type "Set")}}
	{{- $list := .TfName }}
	{{- if len .TestTags}}
	if {{range $i, $e := .TestTags}}{{if $i}} || {{end}}os.Getenv("{{$e}}") != ""{{end}} {
	{{- end}}
	{{- range  .Attributes}}
	{{- if and (not .WriteOnly) (not .ExcludeTest) (not .TfOnly) (not .Value) (not .TestValue)}}
	{{- if or (eq .Type "List") (eq .Type "Set")}}
	{{- $clist := .TfName }}
	{{- if len .TestTags}}
	if {{range $i, $e := .TestTags}}{{if $i}} || {{end}}os.Getenv("{{$e}}") != ""{{end}} {
	{{- end}}
	{{- range  .Attributes}}
	{{- if and (not .WriteOnly) (not .ExcludeTest) (not .TfOnly) (not .Value) (not .TestValue)}}
	{{- if or (eq .Type "List") (eq .Type "Set")}}
	{{- $cclist := .TfName }}
	{{- if len .TestTags}}
	if {{range $i, $e := .TestTags}}{{if $i}} || {{end}}os.Getenv("{{$e}}") != ""{{end}} {
	{{- end}}
	{{- range  .Attributes}}
	{{- if and (not .WriteOnly) (not .ExcludeTest) (not .TfOnly) (not .Value) (not .TestValue)}}
	{{- if len .TestTags}}
	if {{range $i, $e := .TestTags}}{{if $i}} || {{end}}os.Getenv("{{$e}}") != ""{{end}} {
		checks = append(checks, resource.TestCheckResourceAttr("data.ise_{{snakeCase $name}}.test", "{{$list}}.0.{{$clist}}.0.{{$cclist}}.0.{{.TfName}}{{if eq .Type "StringList"}}.0{{end}}", "{{.Example}}"))
	}
	{{- else}}
	checks = append(checks, resource.TestCheckResourceAttr("data.ise_{{snakeCase $name}}.test", "{{$list}}.0.{{$clist}}.0.{{$cclist}}.0.{{.TfName}}{{if eq .Type "StringList"}}.0{{end}}", "{{.Example}}"))
	{{- end}}
	{{- end}}
	{{- end}}
	{{- if len .TestTags}}
	}
	{{- end}}
	{{- else}}
	{{- if len .TestTags}}
	if {{range $i, $e := .TestTags}}{{if $i}} || {{end}}os.Getenv("{{$e}}") != ""{{end}} {
		checks = append(checks, resource.TestCheckResourceAttr("data.ise_{{snakeCase $name}}.test", "{{$list}}.0.{{$clist}}.0.{{.TfName}}{{if eq .Type "StringList"}}.0{{end}}", "{{.Example}}"))
	}
	{{- else}}
	checks = append(checks, resource.TestCheckResourceAttr("data.ise_{{snakeCase $name}}.test", "{{$list}}.0.{{$clist}}.0.{{.TfName}}{{if eq .Type "StringList"}}.0{{end}}", "{{.Example}}"))
	{{- end}}
	{{- end}}
	{{- end}}
	{{- end}}
	{{- if len .TestTags}}
	}
	{{- end}}
	{{- else}}
	{{- if len .TestTags}}
	if {{range $i, $e := .TestTags}}{{if $i}} || {{end}}os.Getenv("{{$e}}") != ""{{end}} {
		checks = append(checks, resource.TestCheckResourceAttr("data.ise_{{snakeCase $name}}.test", "{{$list}}.0.{{.TfName}}{{if eq .Type "StringList"}}.0{{end}}", "{{.Example}}"))
	}
	{{- else}}
	checks = append(checks, resource.TestCheckResourceAttr("data.ise_{{snakeCase $name}}.test", "{{$list}}.0.{{.TfName}}{{if eq .Type "StringList"}}.0{{end}}", "{{.Example}}"))
	{{- end}}
	{{- end}}
	{{- end}}
	{{- end}}
	{{- if len .TestTags}}
	}
	{{- end}}
	{{- else}}
	{{- if len .TestTags}}
	if {{range $i, $e := .TestTags}}{{if $i}} || {{end}}os.Getenv("{{$e}}") != ""{{end}} {
		checks = append(checks, resource.TestCheckResourceAttr("data.ise_{{snakeCase $name}}.test", "{{.TfName}}{{if eq .Type "StringList"}}.0{{end}}", "{{.Example}}"))
	}
	{{- else}}
	checks = append(checks, resource.TestCheckResourceAttr("data.ise_{{snakeCase $name}}.test", "{{.TfName}}{{if eq .Type "StringList"}}.0{{end}}", "{{.Example}}"))
	{{- end}}
	{{- end}}
	{{- end}}
	{{- end}}
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: {{if .TestPrerequisites}}testAccDataSourceIse{{camelCase .Name}}PrerequisitesConfig+{{end}}testAccDataSourceIse{{camelCase .Name}}Config(),
				Check: resource.ComposeTestCheckFunc(checks...),
			},
		},
	})
}
//template:end testAccDataSource

//template:begin testPrerequisites
{{- if .TestPrerequisites}}
const testAccDataSourceIse{{camelCase .Name}}PrerequisitesConfig = `
{{.TestPrerequisites}}
`
{{- end}}
//template:end testPrerequisites

//template:begin testAccDataSourceConfig
func testAccDataSourceIse{{camelCase .Name}}Config() string {
	config := `resource "ise_{{snakeCase $name}}" "test" {` + "\n"
	{{- range  .Attributes}}
	{{- if and (not .ExcludeTest) (not .TfOnly) (not .Value)}}
	{{- if or (eq .Type "List") (eq .Type "Set")}}
	{{- if len .TestTags}}
	if {{range $i, $e := .TestTags}}{{if $i}} || {{end}}os.Getenv("{{$e}}") != ""{{end}} {
	{{- end}}
	config += `	{{.TfName}} = [{` + "\n"
		{{- range  .Attributes}}
		{{- if and (not .ExcludeTest) (not .TfOnly) (not .Value)}}
		{{- if or (eq .Type "List") (eq .Type "Set")}}
		{{- if len .TestTags}}
	if {{range $i, $e := .TestTags}}{{if $i}} || {{end}}os.Getenv("{{$e}}") != ""{{end}} {
		{{- end}}
	config += `	  {{.TfName}} = [{` + "\n"
			{{- range  .Attributes}}
			{{- if and (not .ExcludeTest) (not .TfOnly) (not .Value)}}
			{{- if or (eq .Type "List") (eq .Type "Set")}}
			{{- if len .TestTags}}
	if {{range $i, $e := .TestTags}}{{if $i}} || {{end}}os.Getenv("{{$e}}") != ""{{end}} {
			{{- end}}
	config += `      {{.TfName}} = [{` + "\n"
				{{- range  .Attributes}}
				{{- if and (not .ExcludeTest) (not .TfOnly) (not .Value)}}
				{{- if len .TestTags}}
	if {{range $i, $e := .TestTags}}{{if $i}} || {{end}}os.Getenv("{{$e}}") != ""{{end}} {
		config += `			{{.TfName}} = {{if .TestValue}}{{.TestValue}}{{else}}{{if eq .Type "String"}}"{{.Example}}"{{else if eq .Type "StringList"}}["{{.Example}}"]{{else}}{{.Example}}{{end}}{{end}}` + "\n"
	}
				{{- else}}
	config += `			{{.TfName}} = {{if .TestValue}}{{.TestValue}}{{else}}{{if eq .Type "String"}}"{{.Example}}"{{else if eq .Type "StringList"}}["{{.Example}}"]{{else}}{{.Example}}{{end}}{{end}}` + "\n"
				{{- end}}
				{{- end}}
				{{- end}}
	config += `		}]` + "\n"
			{{- if len .TestTags}}
	}
			{{- end}}
			{{- else}}
			{{- if len .TestTags}}
	if {{range $i, $e := .TestTags}}{{if $i}} || {{end}}os.Getenv("{{$e}}") != ""{{end}} {
		config += `		{{.TfName}} = {{if .TestValue}}{{.TestValue}}{{else}}{{if eq .Type "String"}}"{{.Example}}"{{else if eq .Type "StringList"}}["{{.Example}}"]{{else}}{{.Example}}{{end}}{{end}}` + "\n"
	}
			{{- else}}
	config += `		{{.TfName}} = {{if .TestValue}}{{.TestValue}}{{else}}{{if eq .Type "String"}}"{{.Example}}"{{else if eq .Type "StringList"}}["{{.Example}}"]{{else}}{{.Example}}{{end}}{{end}}` + "\n"
			{{- end}}
			{{- end}}
			{{- end}}
			{{- end}}
	config += `	}]` + "\n"
		{{- if len .TestTags}}
	}
		{{- end}}
		{{- else}}
		{{- if len .TestTags}}
	if {{range $i, $e := .TestTags}}{{if $i}} || {{end}}os.Getenv("{{$e}}") != ""{{end}} {
		config += `	  {{.TfName}} = {{if .TestValue}}{{.TestValue}}{{else}}{{if eq .Type "String"}}"{{.Example}}"{{else if eq .Type "StringList"}}["{{.Example}}"]{{else}}{{.Example}}{{end}}{{end}}` + "\n"
	}
			{{- else}}
	config += `	  {{.TfName}} = {{if .TestValue}}{{.TestValue}}{{else}}{{if eq .Type "String"}}"{{.Example}}"{{else if eq .Type "StringList"}}["{{.Example}}"]{{else}}{{.Example}}{{end}}{{end}}` + "\n"
		{{- end}}
		{{- end}}
		{{- end}}
		{{- end}}
	config += `	}]` + "\n"
		{{- if len .TestTags}}
	}
		{{- end}}
	{{- else}}
	{{- if len .TestTags}}
	if {{range $i, $e := .TestTags}}{{if $i}} || {{end}}os.Getenv("{{$e}}") != ""{{end}} {
		config += `	{{.TfName}} = {{if .TestValue}}{{.TestValue}}{{else}}{{if eq .Type "String"}}"{{.Example}}"{{else if eq .Type "StringList"}}["{{.Example}}"]{{else}}{{.Example}}{{end}}{{end}}` + "\n"
	}
	{{- else}}
	config += `	{{.TfName}} = {{if .TestValue}}{{.TestValue}}{{else}}{{if eq .Type "String"}}"{{.Example}}"{{else if eq .Type "StringList"}}["{{.Example}}"]{{else}}{{.Example}}{{end}}{{end}}` + "\n"
	{{- end}}
	{{- end}}
	{{- end}}
	{{- end}}
	config += `}` + "\n"
	
	config += `
		data "ise_{{snakeCase .Name}}" "test" {
			id = ise_{{snakeCase $name}}.test.id
			{{- range  .Attributes}}
			{{- if .Reference}}
			{{.TfName}} = {{if .TestValue}}{{.TestValue}}{{else}}{{if eq .Type "String"}}"{{.Example}}"{{else if eq .Type "StringList"}}["{{.Example}}"]{{else}}{{.Example}}{{end}}{{end}}
			{{- end}}
			{{- end}}
		}
	`
	return config
}
//template:end testAccDataSourceConfig
