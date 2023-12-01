resource "ise_device_admin_condition" "example" {
  name            = "Cond1"
  description     = "My description"
  condition_type  = "LibraryConditionAttributes"
  is_negate       = false
  attribute_name  = "EapAuthentication"
  attribute_value = "EAP-TLS"
  dictionary_name = "Network Access"
  operator        = "equals"
}
