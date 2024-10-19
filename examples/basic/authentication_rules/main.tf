resource "ise_network_access_policy_set" "policy_set_1" {
  name                      = "PolicySet1"
  description               = "My first policy set"
  rank                      = 0
  service_name              = "Default Network Access"
  condition_type            = "ConditionAttributes"
  condition_attribute_name  = "Location"
  condition_attribute_value = "All Locations"
  condition_dictionary_name = "DEVICE"
  condition_operator        = "equals"
}

locals {
  rules = [
    { name = "rule_0" },
    { name = "rule_1" },
    { name = "rule_2" },
    { name = "rule_3" },
    { name = "rule_4" },
    { name = "rule_5" }
  ]
}

locals {
  rules_with_ranks = [
    for idx, rule in local.rules : merge(rule, {
      rank = idx
    })
  ]
}

resource "ise_network_access_authentication_rule" "auth_rule" {
  for_each                  = { for rule in local.rules_with_ranks : rule.name => rule }
  policy_set_id             = ise_network_access_policy_set.policy_set_1.id
  name                      = each.value.name
  default                   = false
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

resource "ise_network_access_authentication_rule_update_rank" "example_with_rank" {
  for_each      = { for rule in local.rules_with_ranks : rule.name => rule }
  policy_set_id = ise_network_access_policy_set.policy_set_1.id
  rule_id       = ise_network_access_authentication_rule.auth_rule[each.value.name].id
  rank          = each.value.rank
}