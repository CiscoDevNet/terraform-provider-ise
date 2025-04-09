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
func TestAccDataSourceIseNetworkDevice(t *testing.T) {
	var checks []resource.TestCheckFunc
	checks = append(checks, resource.TestCheckResourceAttr("data.ise_network_device.test", "name", "Device1"))
	checks = append(checks, resource.TestCheckResourceAttr("data.ise_network_device.test", "description", "My device"))
	checks = append(checks, resource.TestCheckResourceAttr("data.ise_network_device.test", "authentication_enable_key_wrap", "true"))
	checks = append(checks, resource.TestCheckResourceAttr("data.ise_network_device.test", "authentication_encryption_key", "cisco123cisco123"))
	checks = append(checks, resource.TestCheckResourceAttr("data.ise_network_device.test", "authentication_encryption_key_format", "ASCII"))
	checks = append(checks, resource.TestCheckResourceAttr("data.ise_network_device.test", "authentication_message_authenticator_code_key", "cisco123cisco1235678"))
	checks = append(checks, resource.TestCheckResourceAttr("data.ise_network_device.test", "authentication_network_protocol", "RADIUS"))
	checks = append(checks, resource.TestCheckResourceAttr("data.ise_network_device.test", "authentication_radius_shared_secret", "cisco123"))
	checks = append(checks, resource.TestCheckResourceAttr("data.ise_network_device.test", "authentication_enable_multi_secret", "true"))
	checks = append(checks, resource.TestCheckResourceAttr("data.ise_network_device.test", "authentication_second_radius_shared_secret", "cisco12345"))
	checks = append(checks, resource.TestCheckResourceAttr("data.ise_network_device.test", "authentication_dtls_required", "true"))
	checks = append(checks, resource.TestCheckResourceAttr("data.ise_network_device.test", "coa_port", "12345"))
	checks = append(checks, resource.TestCheckResourceAttr("data.ise_network_device.test", "dtls_dns_name", "cisco.com"))
	checks = append(checks, resource.TestCheckResourceAttr("data.ise_network_device.test", "ips.0.ipaddress", "2.3.4.5"))
	checks = append(checks, resource.TestCheckResourceAttr("data.ise_network_device.test", "ips.0.mask", "32"))
	checks = append(checks, resource.TestCheckResourceAttr("data.ise_network_device.test", "model_name", "Unknown"))
	checks = append(checks, resource.TestCheckResourceAttr("data.ise_network_device.test", "software_version", "Unknown"))
	checks = append(checks, resource.TestCheckResourceAttr("data.ise_network_device.test", "profile_name", "Cisco"))
	checks = append(checks, resource.TestCheckResourceAttr("data.ise_network_device.test", "snmp_link_trap_query", "true"))
	checks = append(checks, resource.TestCheckResourceAttr("data.ise_network_device.test", "snmp_mac_trap_query", "true"))
	checks = append(checks, resource.TestCheckResourceAttr("data.ise_network_device.test", "snmp_polling_interval", "1200"))
	checks = append(checks, resource.TestCheckResourceAttr("data.ise_network_device.test", "snmp_ro_community", "rocom"))
	checks = append(checks, resource.TestCheckResourceAttr("data.ise_network_device.test", "snmp_version", "TWO_C"))
	checks = append(checks, resource.TestCheckResourceAttr("data.ise_network_device.test", "tacacs_connect_mode_options", "OFF"))
	checks = append(checks, resource.TestCheckResourceAttr("data.ise_network_device.test", "tacacs_shared_secret", "cisco123"))
	checks = append(checks, resource.TestCheckResourceAttr("data.ise_network_device.test", "trustsec_device_id", "device123"))
	checks = append(checks, resource.TestCheckResourceAttr("data.ise_network_device.test", "trustsec_device_password", "cisco123"))
	checks = append(checks, resource.TestCheckResourceAttr("data.ise_network_device.test", "trustsec_rest_api_username", "user123"))
	checks = append(checks, resource.TestCheckResourceAttr("data.ise_network_device.test", "trustsec_enable_mode_password", "cisco123"))
	checks = append(checks, resource.TestCheckResourceAttr("data.ise_network_device.test", "trustsec_exec_mode_password", "cisco123"))
	checks = append(checks, resource.TestCheckResourceAttr("data.ise_network_device.test", "trustsec_exec_mode_username", "user456"))
	checks = append(checks, resource.TestCheckResourceAttr("data.ise_network_device.test", "trustsec_include_when_deploying_sgt_updates", "true"))
	checks = append(checks, resource.TestCheckResourceAttr("data.ise_network_device.test", "trustsec_download_environment_data_every_x_seconds", "1000"))
	checks = append(checks, resource.TestCheckResourceAttr("data.ise_network_device.test", "trustsec_download_peer_authorization_policy_every_x_seconds", "1000"))
	checks = append(checks, resource.TestCheckResourceAttr("data.ise_network_device.test", "trustsec_download_sgacl_lists_every_x_seconds", "1000"))
	checks = append(checks, resource.TestCheckResourceAttr("data.ise_network_device.test", "trustsec_other_sga_devices_to_trust_this_device", "true"))
	checks = append(checks, resource.TestCheckResourceAttr("data.ise_network_device.test", "trustsec_re_authentication_every_x_seconds", "1000"))
	checks = append(checks, resource.TestCheckResourceAttr("data.ise_network_device.test", "trustsec_send_configuration_to_device", "true"))
	checks = append(checks, resource.TestCheckResourceAttr("data.ise_network_device.test", "trustsec_send_configuration_to_device_using", "ENABLE_USING_COA"))
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccDataSourceIseNetworkDeviceConfig(),
				Check:  resource.ComposeTestCheckFunc(checks...),
			},
		},
	})
}

//template:end testAccDataSource

//template:begin testPrerequisites
//template:end testPrerequisites

//template:begin testAccDataSourceConfig
func testAccDataSourceIseNetworkDeviceConfig() string {
	config := `resource "ise_network_device" "test" {` + "\n"
	config += `	name = "Device1"` + "\n"
	config += `	description = "My device"` + "\n"
	config += `	authentication_enable_key_wrap = true` + "\n"
	config += `	authentication_encryption_key = "cisco123cisco123"` + "\n"
	config += `	authentication_encryption_key_format = "ASCII"` + "\n"
	config += `	authentication_message_authenticator_code_key = "cisco123cisco1235678"` + "\n"
	config += `	authentication_network_protocol = "RADIUS"` + "\n"
	config += `	authentication_radius_shared_secret = "cisco123"` + "\n"
	config += `	authentication_enable_multi_secret = true` + "\n"
	config += `	authentication_second_radius_shared_secret = "cisco12345"` + "\n"
	config += `	authentication_dtls_required = true` + "\n"
	config += `	coa_port = 12345` + "\n"
	config += `	dtls_dns_name = "cisco.com"` + "\n"
	config += `	ips = [{` + "\n"
	config += `	  ipaddress = "2.3.4.5"` + "\n"
	config += `	  mask = "32"` + "\n"
	config += `	}]` + "\n"
	config += `	model_name = "Unknown"` + "\n"
	config += `	software_version = "Unknown"` + "\n"
	config += `	profile_name = "Cisco"` + "\n"
	config += `	snmp_link_trap_query = true` + "\n"
	config += `	snmp_mac_trap_query = true` + "\n"
	config += `	snmp_polling_interval = 1200` + "\n"
	config += `	snmp_ro_community = "rocom"` + "\n"
	config += `	snmp_version = "TWO_C"` + "\n"
	config += `	tacacs_connect_mode_options = "OFF"` + "\n"
	config += `	tacacs_shared_secret = "cisco123"` + "\n"
	config += `	trustsec_device_id = "device123"` + "\n"
	config += `	trustsec_device_password = "cisco123"` + "\n"
	config += `	trustsec_rest_api_username = "user123"` + "\n"
	config += `	trustsec_rest_api_password = "Cisco123"` + "\n"
	config += `	trustsec_enable_mode_password = "cisco123"` + "\n"
	config += `	trustsec_exec_mode_password = "cisco123"` + "\n"
	config += `	trustsec_exec_mode_username = "user456"` + "\n"
	config += `	trustsec_include_when_deploying_sgt_updates = true` + "\n"
	config += `	trustsec_download_environment_data_every_x_seconds = 1000` + "\n"
	config += `	trustsec_download_peer_authorization_policy_every_x_seconds = 1000` + "\n"
	config += `	trustsec_download_sgacl_lists_every_x_seconds = 1000` + "\n"
	config += `	trustsec_other_sga_devices_to_trust_this_device = true` + "\n"
	config += `	trustsec_re_authentication_every_x_seconds = 1000` + "\n"
	config += `	trustsec_send_configuration_to_device = true` + "\n"
	config += `	trustsec_send_configuration_to_device_using = "ENABLE_USING_COA"` + "\n"
	config += `}` + "\n"

	config += `
		data "ise_network_device" "test" {
			id = ise_network_device.test.id
		}
	`
	return config
}

//template:end testAccDataSourceConfig
