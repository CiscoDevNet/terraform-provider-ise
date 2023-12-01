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
func TestAccDataSourceIseDownloadableACL(t *testing.T) {
	var checks []resource.TestCheckFunc
	checks = append(checks, resource.TestCheckResourceAttr("data.ise_downloadable_acl.test", "name", "MyACL"))
	checks = append(checks, resource.TestCheckResourceAttr("data.ise_downloadable_acl.test", "description", "My first downloadable ACL"))
	checks = append(checks, resource.TestCheckResourceAttr("data.ise_downloadable_acl.test", "dacl", "permit ip any any"))
	checks = append(checks, resource.TestCheckResourceAttr("data.ise_downloadable_acl.test", "dacl_type", "IPV4"))
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccDataSourceIseDownloadableACLConfig(),
				Check:  resource.ComposeTestCheckFunc(checks...),
			},
		},
	})
}

//template:end testAccDataSource

//template:begin testPrerequisites
//template:end testPrerequisites

//template:begin testAccDataSourceConfig
func testAccDataSourceIseDownloadableACLConfig() string {
	config := `resource "ise_downloadable_acl" "test" {` + "\n"
	config += `	name = "MyACL"` + "\n"
	config += `	description = "My first downloadable ACL"` + "\n"
	config += `	dacl = "permit ip any any"` + "\n"
	config += `	dacl_type = "IPV4"` + "\n"
	config += `}` + "\n"

	config += `
		data "ise_downloadable_acl" "test" {
			id = ise_downloadable_acl.test.id
		}
	`
	return config
}

//template:end testAccDataSourceConfig