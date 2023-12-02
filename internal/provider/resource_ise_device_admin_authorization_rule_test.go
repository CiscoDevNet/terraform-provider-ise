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

// Code generated by "gen/generator.go"; DO NOT EDIT.

package provider

//template:begin imports
import (
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

//template:end imports

//template:begin testAcc
func TestAccIseDeviceAdminAuthorizationRule(t *testing.T) {
	var checks []resource.TestCheckFunc
	checks = append(checks, resource.TestCheckResourceAttr("ise_device_admin_authorization_rule.test", "name", "Rule1"))
	checks = append(checks, resource.TestCheckResourceAttr("ise_device_admin_authorization_rule.test", "default", "false"))
	checks = append(checks, resource.TestCheckResourceAttr("ise_device_admin_authorization_rule.test", "rank", "0"))
	checks = append(checks, resource.TestCheckResourceAttr("ise_device_admin_authorization_rule.test", "state", "enabled"))
	checks = append(checks, resource.TestCheckResourceAttr("ise_device_admin_authorization_rule.test", "condition_type", "ConditionAttributes"))
	checks = append(checks, resource.TestCheckResourceAttr("ise_device_admin_authorization_rule.test", "condition_is_negate", "false"))
	checks = append(checks, resource.TestCheckResourceAttr("ise_device_admin_authorization_rule.test", "condition_attribute_name", "Location"))
	checks = append(checks, resource.TestCheckResourceAttr("ise_device_admin_authorization_rule.test", "condition_attribute_value", "All Locations"))
	checks = append(checks, resource.TestCheckResourceAttr("ise_device_admin_authorization_rule.test", "condition_dictionary_name", "DEVICE"))
	checks = append(checks, resource.TestCheckResourceAttr("ise_device_admin_authorization_rule.test", "condition_operator", "equals"))
	checks = append(checks, resource.TestCheckResourceAttr("ise_device_admin_authorization_rule.test", "command_sets.0", "DenyAllCommands"))
	checks = append(checks, resource.TestCheckResourceAttr("ise_device_admin_authorization_rule.test", "profile", "Default Shell Profile"))

	var steps []resource.TestStep
	if os.Getenv("SKIP_MINIMUM_TEST") == "" {
		steps = append(steps, resource.TestStep{
			Config: testAccIseDeviceAdminAuthorizationRulePrerequisitesConfig + testAccIseDeviceAdminAuthorizationRuleConfig_minimum(),
		})
	}
	steps = append(steps, resource.TestStep{
		Config: testAccIseDeviceAdminAuthorizationRulePrerequisitesConfig + testAccIseDeviceAdminAuthorizationRuleConfig_all(),
		Check:  resource.ComposeTestCheckFunc(checks...),
	})

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps:                    steps,
	})
}

//template:end testAcc

//template:begin testPrerequisites
const testAccIseDeviceAdminAuthorizationRulePrerequisitesConfig = `
resource "ise_device_admin_policy_set" "test" {
  name                      = "PolicySet1"
  service_name              = "Default Device Admin"
  condition_type            = "ConditionAttributes"
  condition_is_negate       = false
  condition_attribute_name  = "Location"
  condition_attribute_value = "All Locations"
  condition_dictionary_name = "DEVICE"
  condition_operator        = "equals"
}
resource "ise_device_admin_condition" "test" {
  name            = "Cond1"
  condition_type  = "LibraryConditionAttributes"
  attribute_name  = "User"
  attribute_value = "User1"
  dictionary_name = "TACACS"
  operator        = "equals"
}

`

//template:end testPrerequisites

//template:begin testAccConfigMinimal
func testAccIseDeviceAdminAuthorizationRuleConfig_minimum() string {
	config := `resource "ise_device_admin_authorization_rule" "test" {` + "\n"
	config += `	policy_set_id = ise_device_admin_policy_set.test.id` + "\n"
	config += `	name = "Rule1"` + "\n"
	config += `	condition_type = "ConditionReference"` + "\n"
	config += `	condition_id = ise_device_admin_condition.test.id` + "\n"
	config += `	command_sets = ["DenyAllCommands"]` + "\n"
	config += `}` + "\n"
	return config
}

//template:end testAccConfigMinimal

//template:begin testAccConfigAll
func testAccIseDeviceAdminAuthorizationRuleConfig_all() string {
	config := `resource "ise_device_admin_authorization_rule" "test" {` + "\n"
	config += `	policy_set_id = ise_device_admin_policy_set.test.id` + "\n"
	config += `	name = "Rule1"` + "\n"
	config += `	default = false` + "\n"
	config += `	rank = 0` + "\n"
	config += `	state = "enabled"` + "\n"
	config += `	condition_type = "ConditionAttributes"` + "\n"
	config += `	condition_is_negate = false` + "\n"
	config += `	condition_attribute_name = "Location"` + "\n"
	config += `	condition_attribute_value = "All Locations"` + "\n"
	config += `	condition_dictionary_name = "DEVICE"` + "\n"
	config += `	condition_operator = "equals"` + "\n"
	config += `	command_sets = ["DenyAllCommands"]` + "\n"
	config += `	profile = "Default Shell Profile"` + "\n"
	config += `}` + "\n"
	return config
}

//template:end testAccConfigAll