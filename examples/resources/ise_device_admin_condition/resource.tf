resource "ise_device_admin_condition" "example" {
  name            = "Cond1"
  description     = "My description"
  condition_type  = "LibraryConditionAttributes"
  is_negate       = false
  attribute_name  = "User"
  attribute_value = "User1"
  dictionary_name = "TACACS"
  operator        = "equals"
}
