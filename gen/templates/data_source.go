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
	"context"
	"fmt"
	"net/url"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/netascode/go-ise"
	"github.com/CiscoDevNet/terraform-provider-ise/internal/provider/helpers"
)
//template:end imports

//template:begin header

// Ensure the implementation satisfies the expected interfaces.
var (
	_ datasource.DataSource              = &{{camelCase .Name}}DataSource{}
	_ datasource.DataSourceWithConfigure = &{{camelCase .Name}}DataSource{}
)

func New{{camelCase .Name}}DataSource() datasource.DataSource {
	return &{{camelCase .Name}}DataSource{}
}

type {{camelCase .Name}}DataSource struct {
	client *ise.Client
}

func (d *{{camelCase .Name}}DataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_{{snakeCase .Name}}"
}
//template:end header

{{- $nameQuery := .DataSourceNameQuery}}
{{- $openApi := false}}{{if not (isErs .RestEndpoint)}}{{$openApi = true}}{{end}}

//template:begin model
func (d *{{camelCase .Name}}DataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		// This description is used by the documentation generator and the language server.
		MarkdownDescription: "{{.DsDescription}}",

		Attributes: map[string]schema.Attribute{
			{{- if not .NoId}}
			"id": schema.StringAttribute{
				MarkdownDescription: "The id of the object",
				{{- if not .DataSourceNameQuery}}
				Required:            true,
				{{- else}}
				Optional:            true,
				Computed:            true,
				{{- end}}
			},
			{{- end}}
			{{- range  .Attributes}}
			{{- if not .Value}}
			"{{.TfName}}": schema.{{if isNestedListSet .}}{{.Type}}Nested{{else if isList .}}List{{else if isSet .}}Set{{else if eq .Type "Versions"}}List{{else if eq .Type "Version"}}Int64{{else}}{{.Type}}{{end}}Attribute{
				MarkdownDescription: "{{.Description}}",
				{{- if isListSet .}}
				ElementType:         types.{{.ElementType}}Type,
				{{- end}}
				{{- if .Reference}}
				Required:            true,
				{{- else if and (eq .ModelName "name") ($nameQuery)}}
				Optional:            true,
				Computed:            true,
				{{- else if .DataSourceQuery}}
					{{- if .Mandatory}}
				Required:            true,
					{{- else}}
				Optional:            true,
					{{- end}}
				{{- else}}
				Computed:            true,
				{{- end}}
				{{- if isNestedListSet .}}
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						{{- range  .Attributes}}
						{{- if not .Value}}
						"{{.TfName}}": schema.{{if isNestedListSet .}}{{.Type}}Nested{{else if isList .}}List{{else if isSet .}}Set{{else if eq .Type "Versions"}}List{{else if eq .Type "Version"}}Int64{{else}}{{.Type}}{{end}}Attribute{
							MarkdownDescription: "{{.Description}}",
							{{- if isListSet .}}
							ElementType:         types.{{.ElementType}}Type,
							{{- end}}
							Computed:            true,
							{{- if isNestedListSet .}}
							NestedObject: schema.NestedAttributeObject{
								Attributes: map[string]schema.Attribute{
									{{- range  .Attributes}}
									{{- if not .Value}}
									"{{.TfName}}": schema.{{if isNestedListSet .}}{{.Type}}Nested{{else if isList .}}List{{else if isSet .}}Set{{else if eq .Type "Versions"}}List{{else if eq .Type "Version"}}Int64{{else}}{{.Type}}{{end}}Attribute{
										MarkdownDescription: "{{.Description}}",
										{{- if isListSet .}}
										ElementType:         types.{{.ElementType}}Type,
										{{- end}}
										Computed:            true,
										{{- if isNestedListSet .}}
										NestedObject: schema.NestedAttributeObject{
											Attributes: map[string]schema.Attribute{
												{{- range  .Attributes}}
												{{- if not .Value}}
												"{{.TfName}}": schema.{{if isNestedListSet .}}{{.Type}}Nested{{else if isList .}}List{{else if isSet .}}Set{{else if eq .Type "Versions"}}List{{else if eq .Type "Version"}}Int64{{else}}{{.Type}}{{end}}Attribute{
													MarkdownDescription: "{{.Description}}",
													{{- if isListSet .}}
													ElementType:         types.{{.ElementType}}Type,
													{{- end}}
													Computed:            true,
												},
												{{- end}}
												{{- end}}
											},
										},
										{{- end}}
									},
									{{- end}}
									{{- end}}
								},
							},
							{{- end}}
						},
						{{- end}}
						{{- end}}
					},
				},
				{{- end}}
			},
			{{- end}}
			{{- end}}
		},
	}
}
//template:end model

//template:begin configValidators
{{- if .DataSourceNameQuery}}
func (d *{{camelCase .Name}}DataSource) ConfigValidators(ctx context.Context) []datasource.ConfigValidator {
    return []datasource.ConfigValidator{
        datasourcevalidator.ExactlyOneOf(
            path.MatchRoot("id"),
            path.MatchRoot("name"),
        ),
    }
}
{{- end}}
//template:end configValidators

//template:end configure
func (d *{{camelCase .Name}}DataSource) Configure(_ context.Context, req datasource.ConfigureRequest, _ *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	d.client = req.ProviderData.(*IseProviderData).Client
}
//template:end configure

//template:begin read
func (d *{{camelCase .Name}}DataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config {{camelCase .Name}}

	// Read config
	diags := req.Config.Get(ctx, &config)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, fmt.Sprintf("%s: Beginning Read", {{if not .NoId}}config.Id.ValueString(){{else}}""{{end}}))

	{{- if .DataSourceNameQuery}}
	if config.Id.IsNull() && !config.Name.IsNull() {
		for page := 1; ; page++ {
			res, err := d.client.Get({{if $openApi}}config.getPath(){{else}}fmt.Sprintf("%s?size=100&page=%v", config.getPath(), page){{end}})
			if err != nil {
				resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Failed to retrieve objects, got error: %s", err))
				return
			}
			if value := res.Get({{if $openApi}}"response"{{else}}"SearchResult.resources"{{end}}); len(value.Array()) > 0 {
				value.ForEach(func(k, v gjson.Result) bool {
					if config.Name.ValueString() == v.Get("{{if $openApi}}{{range .Attributes}}{{if eq .TfName "name"}}{{range .DataPath}}{{.}}.{{end}}{{end}}{{end}}{{end}}name").String() {
						config.Id = types.StringValue(v.Get("{{if .IdPath}}{{removeFirstPathElement .IdPath}}{{else}}id{{end}}").String())
						tflog.Debug(ctx, fmt.Sprintf("%s: Found object with name '%v', id: %v", config.Id.String(), config.Name.ValueString(), config.Id.String()))
						return false
					}
					return true
				})
			}
			if !config.Id.IsNull() || !res.Get("SearchResult.nextPage").Exists() {
				break
			}
		}

		if config.Id.IsNull() {
			resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Failed to find object with name: %s", config.Name.ValueString()))
			return
		}
	}
	{{- end}}

	res, err := d.client.Get(config.getPath(){{if not .GetNoId}} + "/" + url.QueryEscape(config.Id.ValueString()){{end}})
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Failed to retrieve object, got error: %s", err))
		return
	}

	config.fromBody(ctx, res)

	tflog.Debug(ctx, fmt.Sprintf("%s: Read finished successfully", {{if not .NoId}}config.Id.ValueString(){{else}}""{{end}}))

	diags = resp.State.Set(ctx, &config)
	resp.Diagnostics.Append(diags...)
}
//template:end read
