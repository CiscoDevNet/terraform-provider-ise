resource "ise_network_device_group" "new_york" {
  name       = "Location#All Locations#New York"
  root_group = "Location"
}

resource "ise_trustsec_security_group" "sgt_new_york_devices" {
  name        = "New_York_Devices"
  description = "Security Group for New York Devices"
  value       = 1300
}

resource "ise_network_access_policy_set" "policy_set_1" {
  name                      = "PolicySet1"
  description               = "My first policy set"
  rank                      = 0
  service_name              = "Default Network Access"
  condition_type            = "ConditionAttributes"
  condition_attribute_name  = "Location"
  condition_attribute_value = "All Locations#New York"
  condition_dictionary_name = "DEVICE"
  condition_operator        = "equals"
}

resource "ise_network_access_authentication_rule" "authn_rule_default" {
  policy_set_id        = ise_network_access_policy_set.policy_set_1.id
  name                 = "Default"
  default              = true
  rank                 = 0
  identity_source_name = "Internal Endpoints"
  if_auth_fail         = "REJECT"
  if_process_fail      = "DROP"
  if_user_not_found    = "REJECT"
}

resource "ise_network_access_authorization_rule" "authz_rule_default" {
  policy_set_id  = ise_network_access_policy_set.policy_set_1.id
  name           = "Default"
  default        = true
  rank           = 0
  profiles       = ["PermitAccess"]
  security_group = ise_trustsec_security_group.sgt_new_york_devices.name
}