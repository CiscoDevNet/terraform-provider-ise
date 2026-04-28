resource "ise_network_access_dictionary_attribute" "example" {
  dictionary_name = "Opnet"
  name            = "Network_Physics-Attribute"
  description     = "Network Physics Attribute for ARX appliances"
  data_type       = "STRING"
  direction_type  = "BOTH"
  internal_name   = "Network_Physics-Attribute"
  allowed_values = [
    {
      key   = "key1"
      value = "value1"
    }
  ]
}
