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
func TestAccIseTrustSecIPToSGTMapping(t *testing.T) {
	var checks []resource.TestCheckFunc
	checks = append(checks, resource.TestCheckResourceAttr("ise_trustsec_ip_to_sgt_mapping.test", "name", "10.0.0.1/32"))
	checks = append(checks, resource.TestCheckResourceAttr("ise_trustsec_ip_to_sgt_mapping.test", "deploy_type", "ALL"))
	checks = append(checks, resource.TestCheckResourceAttr("ise_trustsec_ip_to_sgt_mapping.test", "host_ip", "10.0.0.1/32"))

	var steps []resource.TestStep
	if os.Getenv("SKIP_MINIMUM_TEST") == "" {
		steps = append(steps, resource.TestStep{
			Config: testAccIseTrustSecIPToSGTMappingPrerequisitesConfig + testAccIseTrustSecIPToSGTMappingConfig_minimum(),
		})
	}
	steps = append(steps, resource.TestStep{
		Config: testAccIseTrustSecIPToSGTMappingPrerequisitesConfig + testAccIseTrustSecIPToSGTMappingConfig_all(),
		Check:  resource.ComposeTestCheckFunc(checks...),
	})
	steps = append(steps, resource.TestStep{
		ResourceName: "ise_trustsec_ip_to_sgt_mapping.test",
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
const testAccIseTrustSecIPToSGTMappingPrerequisitesConfig = `
resource "ise_trustsec_security_group" "test" {
  name              = "SGT1234"
  description       = "My SGT"
  value             = 1234
  propogate_to_apic = true
  is_read_only      = false
}

`

//template:end testPrerequisites

//template:begin testAccConfigMinimal
func testAccIseTrustSecIPToSGTMappingConfig_minimum() string {
	config := `resource "ise_trustsec_ip_to_sgt_mapping" "test" {` + "\n"
	config += `	name = "10.0.0.1/32"` + "\n"
	config += `	deploy_type = "ALL"` + "\n"
	config += `	host_ip = "10.0.0.1/32"` + "\n"
	config += `	sgt = ise_trustsec_security_group.test.id` + "\n"
	config += `}` + "\n"
	return config
}

//template:end testAccConfigMinimal

//template:begin testAccConfigAll
func testAccIseTrustSecIPToSGTMappingConfig_all() string {
	config := `resource "ise_trustsec_ip_to_sgt_mapping" "test" {` + "\n"
	config += `	name = "10.0.0.1/32"` + "\n"
	config += `	deploy_type = "ALL"` + "\n"
	config += `	host_ip = "10.0.0.1/32"` + "\n"
	config += `	sgt = ise_trustsec_security_group.test.id` + "\n"
	config += `}` + "\n"
	return config
}

//template:end testAccConfigAll
