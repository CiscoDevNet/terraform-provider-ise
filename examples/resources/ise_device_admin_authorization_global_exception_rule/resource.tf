resource "ise_device_admin_authorization_global_exception_rule" "example" {
  name                      = "Rule1"
  rank                      = 0
  state                     = "enabled"
  condition_type            = "ConditionAttributes"
  condition_is_negate       = false
  condition_attribute_name  = "Location"
  condition_attribute_value = "All Locations"
  condition_dictionary_name = "DEVICE"
  condition_operator        = "equals"
  command_sets              = ["DenyAllCommands"]
  profile                   = "Default Shell Profile"
}
