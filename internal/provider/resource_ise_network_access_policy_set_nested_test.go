// Copyright © 2023 Cisco Systems, Inc. and its affiliates.
// All rights reserved.
//
// Licensed under the Mozilla Public License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://mozilla.org/MPL/2.0/
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// TestAccIseNetworkAccessPolicySet_DeepNesting tests deeply nested conditions up to 6 levels
func TestAccIseNetworkAccessPolicySet_DeepNesting(t *testing.T) {
	var checks []resource.TestCheckFunc
	checks = append(checks, resource.TestCheckResourceAttr("ise_network_access_policy_set.test_nested", "name", "NetworkAccess_7Level_Policy"))
	checks = append(checks, resource.TestCheckResourceAttr("ise_network_access_policy_set.test_nested", "description", "Multi-level Network Access authorization"))
	checks = append(checks, resource.TestCheckResourceAttr("ise_network_access_policy_set.test_nested", "state", "enabled"))
	checks = append(checks, resource.TestCheckResourceAttr("ise_network_access_policy_set.test_nested", "condition_type", "ConditionAndBlock"))
	checks = append(checks, resource.TestCheckResourceAttr("ise_network_access_policy_set.test_nested", "condition_is_negate", "false"))

	// Check level 1 children exist
	checks = append(checks, resource.TestCheckResourceAttr("ise_network_access_policy_set.test_nested", "children.#", "2"))
	checks = append(checks, resource.TestCheckResourceAttr("ise_network_access_policy_set.test_nested", "children.0.condition_type", "ConditionOrBlock"))
	checks = append(checks, resource.TestCheckResourceAttr("ise_network_access_policy_set.test_nested", "children.1.condition_type", "ConditionAttributes"))

	// Check level 2 children
	checks = append(checks, resource.TestCheckResourceAttr("ise_network_access_policy_set.test_nested", "children.0.children.#", "2"))
	checks = append(checks, resource.TestCheckResourceAttr("ise_network_access_policy_set.test_nested", "children.0.children.0.condition_type", "ConditionAndBlock"))

	// Check level 3 children
	checks = append(checks, resource.TestCheckResourceAttr("ise_network_access_policy_set.test_nested", "children.0.children.0.children.#", "2"))
	checks = append(checks, resource.TestCheckResourceAttr("ise_network_access_policy_set.test_nested", "children.0.children.0.children.0.condition_type", "ConditionOrBlock"))

	// Check level 4 children
	checks = append(checks, resource.TestCheckResourceAttr("ise_network_access_policy_set.test_nested", "children.0.children.0.children.0.children.#", "2"))
	checks = append(checks, resource.TestCheckResourceAttr("ise_network_access_policy_set.test_nested", "children.0.children.0.children.0.children.0.condition_type", "ConditionAndBlock"))

	// Check level 5 children
	checks = append(checks, resource.TestCheckResourceAttr("ise_network_access_policy_set.test_nested", "children.0.children.0.children.0.children.0.children.#", "2"))
	checks = append(checks, resource.TestCheckResourceAttr("ise_network_access_policy_set.test_nested", "children.0.children.0.children.0.children.0.children.0.condition_type", "ConditionOrBlock"))

	// Check level 6 children (deepest - leaf nodes only)
	checks = append(checks, resource.TestCheckResourceAttr("ise_network_access_policy_set.test_nested", "children.0.children.0.children.0.children.0.children.0.children.#", "2"))
	checks = append(checks, resource.TestCheckResourceAttr("ise_network_access_policy_set.test_nested", "children.0.children.0.children.0.children.0.children.0.children.0.condition_type", "ConditionAttributes"))
	checks = append(checks, resource.TestCheckResourceAttr("ise_network_access_policy_set.test_nested", "children.0.children.0.children.0.children.0.children.0.children.0.dictionary_name", "RADIUS"))
	checks = append(checks, resource.TestCheckResourceAttr("ise_network_access_policy_set.test_nested", "children.0.children.0.children.0.children.0.children.0.children.0.attribute_name", "User-Name"))
	checks = append(checks, resource.TestCheckResourceAttr("ise_network_access_policy_set.test_nested", "children.0.children.0.children.0.children.0.children.0.children.0.operator", "contains"))
	checks = append(checks, resource.TestCheckResourceAttr("ise_network_access_policy_set.test_nested", "children.0.children.0.children.0.children.0.children.0.children.0.attribute_value", "admin"))

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccIseNetworkAccessPolicySetConfig_deepNested(),
				Check:  resource.ComposeTestCheckFunc(checks...),
			},
			{
				ResourceName:      "ise_network_access_policy_set.test_nested",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

// TestAccIseNetworkAccessPolicySet_Level3Nesting tests 3-level nesting (common case)
func TestAccIseNetworkAccessPolicySet_Level3Nesting(t *testing.T) {
	var checks []resource.TestCheckFunc
	checks = append(checks, resource.TestCheckResourceAttr("ise_network_access_policy_set.test_level3", "name", "NetworkAccess_3Level_Policy"))
	checks = append(checks, resource.TestCheckResourceAttr("ise_network_access_policy_set.test_level3", "state", "enabled"))
	checks = append(checks, resource.TestCheckResourceAttr("ise_network_access_policy_set.test_level3", "condition_type", "ConditionAndBlock"))
	checks = append(checks, resource.TestCheckResourceAttr("ise_network_access_policy_set.test_level3", "children.#", "2"))
	checks = append(checks, resource.TestCheckResourceAttr("ise_network_access_policy_set.test_level3", "children.0.children.#", "2"))
	checks = append(checks, resource.TestCheckResourceAttr("ise_network_access_policy_set.test_level3", "children.0.children.0.children.#", "2"))

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccIseNetworkAccessPolicySetConfig_level3(),
				Check:  resource.ComposeTestCheckFunc(checks...),
			},
			{
				ResourceName:      "ise_network_access_policy_set.test_level3",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

// TestAccIseNetworkAccessPolicySet_MacOperators tests MAC address operators
func TestAccIseNetworkAccessPolicySet_MacOperators(t *testing.T) {
	var checks []resource.TestCheckFunc
	checks = append(checks, resource.TestCheckResourceAttr("ise_network_access_policy_set.test_mac", "name", "NetworkAccess_MAC_Policy"))
	checks = append(checks, resource.TestCheckResourceAttr("ise_network_access_policy_set.test_mac", "condition_type", "ConditionAndBlock"))
	checks = append(checks, resource.TestCheckResourceAttr("ise_network_access_policy_set.test_mac", "children.0.operator", "macEquals"))
	checks = append(checks, resource.TestCheckResourceAttr("ise_network_access_policy_set.test_mac", "children.1.operator", "macContains"))

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccIseNetworkAccessPolicySetConfig_macOperators(),
				Check:  resource.ComposeTestCheckFunc(checks...),
			},
			{
				ResourceName:      "ise_network_access_policy_set.test_mac",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

// Deep nested configuration with 7 levels (1 root + 6 children levels)
func testAccIseNetworkAccessPolicySetConfig_deepNested() string {
	return `
resource "ise_network_access_policy_set" "test_nested" {
  name        = "NetworkAccess_7Level_Policy"
  description = "Multi-level Network Access authorization"
  state       = "enabled"
  service_name = "Default Network Access"
  
  condition_type = "ConditionAndBlock"
  condition_is_negate = false
  
  children = [
    {
      condition_type = "ConditionOrBlock"
      children = [
        {
          condition_type = "ConditionAndBlock"
          children = [
            {
              condition_type = "ConditionOrBlock"
              children = [
                {
                  condition_type = "ConditionAndBlock"
                  children = [
                    {
                      condition_type = "ConditionOrBlock"
                      children = [
                        {
                          condition_type  = "ConditionAttributes"
                          dictionary_name = "RADIUS"
                          attribute_name  = "User-Name"
                          operator        = "contains"
                          attribute_value = "admin"
                        },
                        {
                          condition_type  = "ConditionAttributes"
                          dictionary_name = "RADIUS"
                          attribute_name  = "User-Name"
                          operator        = "contains"
                          attribute_value = "network-ops"
                        }
                      ]
                    },
                    {
                      condition_type  = "ConditionAttributes"
                      dictionary_name = "DEVICE"
                      attribute_name  = "Device Type"
                      operator        = "equals"
                      attribute_value = "All Device Types#Switches"
                    }
                  ]
                },
                {
                  condition_type  = "ConditionAttributes"
                  dictionary_name = "RADIUS"
                  attribute_name  = "NAS-Port-Type"
                  operator        = "equals"
                  attribute_value = "Ethernet"
                }
              ]
            },
            {
              condition_type  = "ConditionAttributes"
              dictionary_name = "DEVICE"
              attribute_name  = "Location"
              operator        = "equals"
              attribute_value = "All Locations#HQ"
            }
          ]
        },
        {
          condition_type  = "ConditionAttributes"
          dictionary_name = "RADIUS"
          attribute_name  = "Service-Type"
          operator        = "equals"
          attribute_value = "Login-User"
        }
      ]
    },
    {
      condition_type  = "ConditionAttributes"
      dictionary_name = "RADIUS"
      attribute_name  = "Framed-Protocol"
      operator        = "equals"
      attribute_value = "PPP"
    }
  ]
}
`
}

// 3-level nested configuration (common case)
func testAccIseNetworkAccessPolicySetConfig_level3() string {
	return `
resource "ise_network_access_policy_set" "test_level3" {
  name         = "NetworkAccess_3Level_Policy"
  description  = "Three-level nested conditions"
  state        = "enabled"
  service_name = "Default Network Access"
  
  condition_type = "ConditionAndBlock"
  condition_is_negate = false
  
  children = [
    {
      condition_type = "ConditionOrBlock"
      children = [
        {
          condition_type = "ConditionAndBlock"
          children = [
            {
              condition_type  = "ConditionAttributes"
              dictionary_name = "RADIUS"
              attribute_name  = "User-Name"
              operator        = "equals"
              attribute_value = "testuser"
            },
            {
              condition_type  = "ConditionAttributes"
              dictionary_name = "DEVICE"
              attribute_name  = "Location"
              operator        = "equals"
              attribute_value = "All Locations"
            }
          ]
        },
        {
          condition_type  = "ConditionAttributes"
          dictionary_name = "RADIUS"
          attribute_name  = "NAS-Port-Type"
          operator        = "equals"
          attribute_value = "Wireless - IEEE 802.11"
        }
      ]
    },
    {
      condition_type  = "ConditionAttributes"
      dictionary_name = "RADIUS"
      attribute_name  = "Service-Type"
      operator        = "equals"
      attribute_value = "Framed-User"
    }
  ]
}
`
}

// Configuration testing MAC operators
func testAccIseNetworkAccessPolicySetConfig_macOperators() string {
	return `
resource "ise_network_access_policy_set" "test_mac" {
  name         = "NetworkAccess_MAC_Policy"
  description  = "Testing MAC address operators"
  state        = "enabled"
  service_name = "Default Network Access"
  
  condition_type = "ConditionAndBlock"
  condition_is_negate = false
  
  children = [
    {
      condition_type  = "ConditionAttributes"
      dictionary_name = "RADIUS"
      attribute_name  = "Calling-Station-ID"
      operator        = "macEquals"
      attribute_value = "00:11:22:33:44:55"
    },
    {
      condition_type  = "ConditionAttributes"
      dictionary_name = "RADIUS"
      attribute_name  = "Calling-Station-ID"
      operator        = "macContains"
      attribute_value = "AA:BB:CC"
    }
  ]
}
`
}
