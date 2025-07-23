---
subcategory: "Guides"
page_title: "Authentication Rules"
description: |-
    Authentication Rules
---

# Authentication Rules

This example demonstrates how the provider can be used to configure a network access authentication rules. The full example can be found here: [https://github.com/CiscoDevNet/terraform-provider-ise/tree/main/examples/basic/authentication_rules](https://github.com/CiscoDevNet/terraform-provider-ise/tree/main/examples/basic/authentication_rules)

First of all we need to add the necessary provider configuration to the Terraform configuration file:

```hcl
terraform {
  required_providers {
    ise = {
      source = "CiscoDevNet/ise"
    }
  }
}

provider "ise" {
  username = "admin"
  password = "password"
  url      = "https://10.1.1.1"
}
```

Next we add the configuration for a network access policy set, under which we will later configure authentication rules.

```hcl
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
```

Next we add the configuration for the authentication rules. We make use of `network_access_authentication_rule` and `network_access_authentication_rule_update_rank` resources. The first resource manages all fields except for the rank, while the second resource specifically updates the rank field. This is a workaround for the ISE API/Backend limitation that enforces strictly incremental rank assignments. By using both resources, you can bypass this limitation. The network_access_authentication_rule_update_rank resource performs a PUT operation to update the rank and only tracks that field. When destroyed, it is simply removed from the state without affecting the ISE configuration. This ensures the correct sequence of resource configuration.

```hcl
locals {
  rules = [
    { name = "rule_0" },
    { name = "rule_1" },
    { name = "rule_2" },
    { name = "rule_3" },
    { name = "rule_4" },
    { name = "rule_5" },
    { name = "rule_6" },
    { name = "rule_7" },
    { name = "rule_8" },
    { name = "rule_9" }
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

resource "ise_network_access_authentication_rule_update_ranks" "example_with_ranks" {
  policy_set_id = ise_network_access_policy_set.policy_set_1.id
  rules = [for rule in local.rules_with_ranks :
    {
      id   = ise_network_access_authentication_rule.auth_rule[rule.name].id
      rank = rule.rank
    }
  ]
}
```
