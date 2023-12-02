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
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

//template:end imports

//template:begin testAccDataSource
func TestAccDataSourceIseDeviceAdminAuthorizationGlobalExceptionRule(t *testing.T) {
	var checks []resource.TestCheckFunc
	checks = append(checks, resource.TestCheckResourceAttr("data.ise_device_admin_authorization_global_exception_rule.test", "name", "Rule1"))
	checks = append(checks, resource.TestCheckResourceAttr("data.ise_device_admin_authorization_global_exception_rule.test", "default", "false"))
	checks = append(checks, resource.TestCheckResourceAttr("data.ise_device_admin_authorization_global_exception_rule.test", "rank", "0"))
	checks = append(checks, resource.TestCheckResourceAttr("data.ise_device_admin_authorization_global_exception_rule.test", "state", "enabled"))
	checks = append(checks, resource.TestCheckResourceAttr("data.ise_device_admin_authorization_global_exception_rule.test", "condition_type", "ConditionAttributes"))
	checks = append(checks, resource.TestCheckResourceAttr("data.ise_device_admin_authorization_global_exception_rule.test", "condition_is_negate", "false"))
	checks = append(checks, resource.TestCheckResourceAttr("data.ise_device_admin_authorization_global_exception_rule.test", "condition_attribute_name", "Location"))
	checks = append(checks, resource.TestCheckResourceAttr("data.ise_device_admin_authorization_global_exception_rule.test", "condition_attribute_value", "All Locations"))
	checks = append(checks, resource.TestCheckResourceAttr("data.ise_device_admin_authorization_global_exception_rule.test", "condition_dictionary_name", "DEVICE"))
	checks = append(checks, resource.TestCheckResourceAttr("data.ise_device_admin_authorization_global_exception_rule.test", "condition_operator", "equals"))
	checks = append(checks, resource.TestCheckResourceAttr("data.ise_device_admin_authorization_global_exception_rule.test", "command_sets.0", "DenyAllCommands"))
	checks = append(checks, resource.TestCheckResourceAttr("data.ise_device_admin_authorization_global_exception_rule.test", "profile", "Default Shell Profile"))
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccDataSourceIseDeviceAdminAuthorizationGlobalExceptionRulePrerequisitesConfig + testAccDataSourceIseDeviceAdminAuthorizationGlobalExceptionRuleConfig(),
				Check:  resource.ComposeTestCheckFunc(checks...),
			},
		},
	})
}

//template:end testAccDataSource

//template:begin testPrerequisites
const testAccDataSourceIseDeviceAdminAuthorizationGlobalExceptionRulePrerequisitesConfig = `
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

//template:begin testAccDataSourceConfig
func testAccDataSourceIseDeviceAdminAuthorizationGlobalExceptionRuleConfig() string {
	config := `resource "ise_device_admin_authorization_global_exception_rule" "test" {` + "\n"
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

	config += `
		data "ise_device_admin_authorization_global_exception_rule" "test" {
			id = ise_device_admin_authorization_global_exception_rule.test.id
		}
	`
	return config
}

//template:end testAccDataSourceConfig