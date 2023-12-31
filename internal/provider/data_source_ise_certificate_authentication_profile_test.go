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

//template:begin testAccDataSource
func TestAccDataSourceIseCertificateAuthenticationProfile(t *testing.T) {
	if os.Getenv("CERT_PROFILE") == "" {
		t.Skip("skipping test, set environment variable CERT_PROFILE")
	}
	var checks []resource.TestCheckFunc
	checks = append(checks, resource.TestCheckResourceAttr("data.ise_certificate_authentication_profile.test", "name", "CertProf1"))
	checks = append(checks, resource.TestCheckResourceAttr("data.ise_certificate_authentication_profile.test", "description", "My cert profile"))
	checks = append(checks, resource.TestCheckResourceAttr("data.ise_certificate_authentication_profile.test", "allowed_as_user_name", "false"))
	checks = append(checks, resource.TestCheckResourceAttr("data.ise_certificate_authentication_profile.test", "external_identity_store_name", "[not applicable]"))
	checks = append(checks, resource.TestCheckResourceAttr("data.ise_certificate_authentication_profile.test", "certificate_attribute_name", "SUBJECT_COMMON_NAME"))
	checks = append(checks, resource.TestCheckResourceAttr("data.ise_certificate_authentication_profile.test", "match_mode", "NEVER"))
	checks = append(checks, resource.TestCheckResourceAttr("data.ise_certificate_authentication_profile.test", "username_from", "CERTIFICATE"))
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccDataSourceIseCertificateAuthenticationProfileConfig(),
				Check:  resource.ComposeTestCheckFunc(checks...),
			},
		},
	})
}

//template:end testAccDataSource

//template:begin testPrerequisites
//template:end testPrerequisites

//template:begin testAccDataSourceConfig
func testAccDataSourceIseCertificateAuthenticationProfileConfig() string {
	config := `resource "ise_certificate_authentication_profile" "test" {` + "\n"
	config += `	name = "CertProf1"` + "\n"
	config += `	description = "My cert profile"` + "\n"
	config += `	allowed_as_user_name = false` + "\n"
	config += `	external_identity_store_name = "[not applicable]"` + "\n"
	config += `	certificate_attribute_name = "SUBJECT_COMMON_NAME"` + "\n"
	config += `	match_mode = "NEVER"` + "\n"
	config += `	username_from = "CERTIFICATE"` + "\n"
	config += `}` + "\n"

	config += `
		data "ise_certificate_authentication_profile" "test" {
			id = ise_certificate_authentication_profile.test.id
		}
	`
	return config
}

//template:end testAccDataSourceConfig
