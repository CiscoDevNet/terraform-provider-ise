resource "ise_network_access_dictionary_attribute" "example" {
  dictionary_name = "CustomDict"
  name            = "Custom-Attr"
  description     = "My custom dictionary attribute"
  data_type       = "STRING"
  direction_type  = "BOTH"
  internal_name   = "Custom-Attr"
  allowed_values = [
    {
      key   = "key1"
      value = "value1"
    }
  ]
}
