resource "ise_{{snakeCase .Name}}" "example" {
{{- range  .Attributes}}
{{- if and (not .ExcludeTest) (not .ExcludeExample) (not .ComputedOnly) (not .Value)}}
{{- if isNestedListSet .}}
  {{.TfName}} = [
    {
      {{- range  .Attributes}}
      {{- if and (not .ExcludeTest) (not .ExcludeExample) (not .ComputedOnly) (not .Value)}}
      {{- if isNestedListSet .}}
        {{.TfName}} = [
          {
          {{- range  .Attributes}}
          {{- if and (not .ExcludeTest) (not .ExcludeExample) (not .ComputedOnly) (not .Value)}}
          {{- if isNestedListSet .}}
            {{.TfName}} = [
              {
                {{- range  .Attributes}}
                {{- if and (not .ExcludeTest) (not .ExcludeExample) (not .ComputedOnly) (not .Value)}}
                {{.TfName}} = {{if .ExampleExpression}}{{.ExampleExpression}}{{else if eq .Type "String"}}"{{.Example}}"{{else if isStringListSet .}}["{{.Example}}"]{{else if isInt64ListSet .}}[{{.Example}}]{{else}}{{.Example}}{{end}}
                {{- end}}
                {{- end}}
              }
            ]
          {{- else}}
          {{.TfName}} = {{if .ExampleExpression}}{{.ExampleExpression}}{{else if eq .Type "String"}}"{{.Example}}"{{else if isStringListSet .}}["{{.Example}}"]{{else if isInt64ListSet .}}[{{.Example}}]{{else}}{{.Example}}{{end}}
          {{- end}}
          {{- end}}
          {{- end}}
          }
        ]
      {{- else}}
      {{.TfName}} = {{if .ExampleExpression}}{{.ExampleExpression}}{{else if eq .Type "String"}}"{{.Example}}"{{else if isStringListSet .}}["{{.Example}}"]{{else if isInt64ListSet .}}[{{.Example}}]{{else}}{{.Example}}{{end}}
      {{- end}}
      {{- end}}
      {{- end}}
    }
  ]
{{- else}}
  {{.TfName}} = {{if .ExampleExpression}}{{.ExampleExpression}}{{else if eq .Type "String"}}"{{.Example}}"{{else if isStringListSet .}}["{{.Example}}"]{{else if isInt64ListSet .}}[{{.Example}}]{{else}}{{.Example}}{{end}}
{{- end}}
{{- end}}
{{- end}}
}
