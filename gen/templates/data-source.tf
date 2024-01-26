data "ise_{{snakeCase .Name}}" "example" {
  {{- if not .NoId}}
  id = "{{$id := false}}{{range .Attributes}}{{if .Id}}{{$id = true}}{{.Example}}{{end}}{{end}}{{if not $id}}76d24097-41c4-4558-a4d0-a8c07ac08470{{end}}"
  {{- end}}
  {{- range  .Attributes}}
  {{- if or .Reference .DataSourceQuery}}
  {{.TfName}} = {{if eq .Type "String"}}"{{.Example}}"{{else if eq .Type "StringList"}}["{{.Example}}"]{{else}}{{.Example}}{{end}}
  {{- end}}
  {{- end}}
}
