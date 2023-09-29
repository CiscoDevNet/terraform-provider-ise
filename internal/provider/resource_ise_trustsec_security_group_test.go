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

import (
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccIseTrustSecSecurityGroup(t *testing.T) {
	var checks []resource.TestCheckFunc
	checks = append(checks, resource.TestCheckResourceAttr("ise_trustsec_security_group.test", "name", "SGT1234"))
	checks = append(checks, resource.TestCheckResourceAttr("ise_trustsec_security_group.test", "description", "My SGT"))
	checks = append(checks, resource.TestCheckResourceAttr("ise_trustsec_security_group.test", "value", "1234"))
	checks = append(checks, resource.TestCheckResourceAttr("ise_trustsec_security_group.test", "propogate_to_apic", "true"))

	var steps []resource.TestStep
	if os.Getenv("SKIP_MINIMUM_TEST") == "" {
		steps = append(steps, resource.TestStep{
			Config: testAccIseTrustSecSecurityGroupConfig_minimum(),
		})
	}
	steps = append(steps, resource.TestStep{
		Config: testAccIseTrustSecSecurityGroupConfig_all(),
		Check:  resource.ComposeTestCheckFunc(checks...),
	})
	steps = append(steps, resource.TestStep{
		ResourceName: "ise_trustsec_security_group.test",
		ImportState:  true,
	})

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps:                    steps,
	})
}

func testAccIseTrustSecSecurityGroupConfig_minimum() string {
	config := `resource "ise_trustsec_security_group" "test" {` + "\n"
	config += `	name = "SGT1234"` + "\n"
	config += `	value = 1234` + "\n"
	config += `}` + "\n"
	return config
}

func testAccIseTrustSecSecurityGroupConfig_all() string {
	config := `resource "ise_trustsec_security_group" "test" {` + "\n"
	config += `	name = "SGT1234"` + "\n"
	config += `	description = "My SGT"` + "\n"
	config += `	value = 1234` + "\n"
	config += `	propogate_to_apic = true` + "\n"
	config += `	is_read_only = false` + "\n"
	config += `}` + "\n"
	return config
}
