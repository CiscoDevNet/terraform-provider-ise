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
func TestAccIseDeviceAdminTimeAndDateCondition(t *testing.T) {
	var checks []resource.TestCheckFunc
	checks = append(checks, resource.TestCheckResourceAttr("ise_device_admin_time_and_date_condition.test", "name", "Cond1"))
	checks = append(checks, resource.TestCheckResourceAttr("ise_device_admin_time_and_date_condition.test", "description", "My description"))
	checks = append(checks, resource.TestCheckResourceAttr("ise_device_admin_time_and_date_condition.test", "is_negate", "false"))
	checks = append(checks, resource.TestCheckResourceAttr("ise_device_admin_time_and_date_condition.test", "start_date", "2022-05-06"))
	checks = append(checks, resource.TestCheckResourceAttr("ise_device_admin_time_and_date_condition.test", "end_date", "2022-05-10"))
	checks = append(checks, resource.TestCheckResourceAttr("ise_device_admin_time_and_date_condition.test", "exception_start_date", "2022-06-06"))
	checks = append(checks, resource.TestCheckResourceAttr("ise_device_admin_time_and_date_condition.test", "exception_end_date", "2022-06-10"))
	checks = append(checks, resource.TestCheckResourceAttr("ise_device_admin_time_and_date_condition.test", "start_time", "08:00"))
	checks = append(checks, resource.TestCheckResourceAttr("ise_device_admin_time_and_date_condition.test", "end_time", "15:00"))
	checks = append(checks, resource.TestCheckResourceAttr("ise_device_admin_time_and_date_condition.test", "exception_start_time", "20:00"))
	checks = append(checks, resource.TestCheckResourceAttr("ise_device_admin_time_and_date_condition.test", "exception_end_time", "22:00"))

	var steps []resource.TestStep
	if os.Getenv("SKIP_MINIMUM_TEST") == "" {
		steps = append(steps, resource.TestStep{
			Config: testAccIseDeviceAdminTimeAndDateConditionConfig_minimum(),
		})
	}
	steps = append(steps, resource.TestStep{
		Config: testAccIseDeviceAdminTimeAndDateConditionConfig_all(),
		Check:  resource.ComposeTestCheckFunc(checks...),
	})
	steps = append(steps, resource.TestStep{
		ResourceName: "ise_device_admin_time_and_date_condition.test",
		ImportState:  true,
	})

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps:                    steps,
	})
}

//template:end testAcc

//template:begin testPrerequisites
//template:end testPrerequisites

//template:begin testAccConfigMinimal
func testAccIseDeviceAdminTimeAndDateConditionConfig_minimum() string {
	config := `resource "ise_device_admin_time_and_date_condition" "test" {` + "\n"
	config += `	name = "Cond1"` + "\n"
	config += `	description = "My description"` + "\n"
	config += `}` + "\n"
	return config
}

//template:end testAccConfigMinimal

//template:begin testAccConfigAll
func testAccIseDeviceAdminTimeAndDateConditionConfig_all() string {
	config := `resource "ise_device_admin_time_and_date_condition" "test" {` + "\n"
	config += `	name = "Cond1"` + "\n"
	config += `	description = "My description"` + "\n"
	config += `	is_negate = false` + "\n"
	config += `	week_days = ["Monday"]` + "\n"
	config += `	week_days_exception = ["Tuesday"]` + "\n"
	config += `	start_date = "2022-05-06"` + "\n"
	config += `	end_date = "2022-05-10"` + "\n"
	config += `	exception_start_date = "2022-06-06"` + "\n"
	config += `	exception_end_date = "2022-06-10"` + "\n"
	config += `	start_time = "08:00"` + "\n"
	config += `	end_time = "15:00"` + "\n"
	config += `	exception_start_time = "20:00"` + "\n"
	config += `	exception_end_time = "22:00"` + "\n"
	config += `}` + "\n"
	return config
}

//template:end testAccConfigAll
