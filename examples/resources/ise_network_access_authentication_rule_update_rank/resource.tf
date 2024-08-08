resource "ise_network_access_authentication_rule_update_rank" "example" {
  auth_rule_id              = "9b3680da-0165-44f6-9cff-88e778d98020"
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
  identity_source_name      = "Internal Endpoints"
  if_auth_fail              = "REJECT"
  if_process_fail           = "DROP"
  if_user_not_found         = "REJECT"
}
