---
subcategory: "Guides"
page_title: "Getting Started"
description: |-
    Getting Started
---

# Getting Started

This example demonstrates how the provider can be used to configure a network access policy set. The full example can be found here: [https://github.com/CiscoDevNet/terraform-provider-ise/tree/main/examples/basic/getting_started](https://github.com/CiscoDevNet/terraform-provider-ise/tree/main/examples/basic/getting_started)

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

Next we add the configuration for a network device group and a security group which we will later use in our policy.

```hcl
resource "ise_network_device_group" "new_york" {
  name       = "Location#All Locations#New York"
  root_group = "Location"
}

resource "ise_trustsec_security_group" "sgt_new_york_devices" {
  name        = "New_York_Devices"
  description = "Security Group for New York Devices"
  value       = 1300
}
```

Next we add the configuration for the policy set and update the default authentication and authorization rules. We make use of implicit dependencies to ensure resources are being configured in the right sequence.

```hcl
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
```
