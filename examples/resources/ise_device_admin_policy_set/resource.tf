resource "ise_device_admin_policy_set" "example" {
  name                      = "PolicySet1"
  description               = "My description"
  is_proxy                  = false
  rank                      = 0
  service_name              = "Default Network Access"
  state                     = "enabled"
  condition_type            = "ConditionAttributes"
  condition_is_negate       = false
  condition_attribute_name  = "Location"
  condition_attribute_value = "All Locations"
  condition_dictionary_name = "DEVICE"
  condition_operator        = "equals"
}
