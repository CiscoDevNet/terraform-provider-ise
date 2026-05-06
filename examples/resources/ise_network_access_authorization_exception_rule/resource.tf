resource "ise_network_access_authorization_exception_rule" "example" {
  policy_set_id             = "d82952cb-b901-4b09-b363-5ebf39bdbaf9"
  name                      = "Rule1"
  default                   = false
  rank                      = 0
  state                     = "enabled"
  condition_type            = "ConditionAttributes"
  condition_is_negate       = false
  condition_attribute_name  = "Location"
  condition_attribute_value = "All Locations"
  condition_dictionary_name = "DEVICE"
  condition_operator        = "equals"
  profiles                  = ["PermitAccess"]
  security_group            = "BYOD"
}
