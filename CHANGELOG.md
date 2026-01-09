## Unreleased

- Add Software Bill of Materials (SBOM) generation in SPDX and CycloneDX formats during releases

## 0.2.14

- Add `ise_trustsec_egress_push_matrix` resource to enable deploying the full matrix to TrustSec devices
- Add destroy support for `ise_certificate_authentication_profile` (requires ISE 3.4 or later)

## 0.2.13

- Add SNMPv3 support to `ise_network_device` resource and data source

## 0.2.12

- Enhancement: The `ise_endpoint` resource now performs a PUT update if the endpoint already exists during creation, instead of returning an error

## 0.2.11

- Add new condition operators to relevant resources: `macContains`, `macEndsWith`, `macEquals`, `macIn`, `macNotContains`, `macNotEndsWith`, `macNotEquals`, `macNotIn`, `macNotStartsWith`, `macStartsWith`

## 0.2.10

- Fix issue with children blocks not working properly with List and Set, [link](https://github.com/CiscoDevNet/terraform-provider-ise/issues/138)

## 0.2.9

- Change `children` attribute type from `Attributes Set` to `Attributes List` on all relevant resources

## 0.2.8

- Add `ise_endpoint_custom_attribute` resource and data source

## 0.2.7

- BREAKING CHANGE: Rename `trustsec_download_enviroment_data_every_x_seconds` attribute of `ise_network_device` resource to `trustsec_download_environment_data_every_x_seconds`
- Fix issue with updating `ise_network_device` with existing TrustSec config, [link](https://github.com/CiscoDevNet/terraform-provider-ise/issues/60)
- Add `network_access_*_update_ranks` and `device_admin_*_update_ranks` resources to enable bulk updates of ranks across (Policy Sets, Authentication Rules, Authorization Rules, Authorization Global Exception Rules and Authorization Exception Rules) under Network Access and Device Administration, bypassing an API limitation that restricts rank assignments to a strictly incremental sequence. More detailed information is available [here](https://registry.terraform.io/providers/CiscoDevNet/ise/latest/docs/guides/authentication_rules).
- Fix issue with adding new groups to existing `ise_active_directory_add_groups` resource, [link](https://github.com/CiscoDevNet/terraform-provider-ise/issues/113)

## 0.2.6

- Add `ise_trustsec_egress_matrix_cell_default` resource to support default egress policy matrix rule modifications

## 0.2.5

- Remove default_value from `systemDefined` attribute in `ise_endpoint_identity_group`
- Remove `default` from `ise_device_admin_authorization_global_exception_rule` and `ise_network_access_authorization_global_exception_rule`
- Remove default_value from `isReadOnly` and `readOnly` attributes in `ise_trustsec_security_group` and `ise_trustsec_security_group_acl`
- Add `ise_sxp_domain_filter` resource and data source

## 0.2.4

- Fix managing `Default` network access and device administration resources

## 0.2.3

- Add `network_access_*_update_rank` and `device_admin_*_update_rank` resources to update rank under network access and device admin policy sets to bypass API limitation which restricts rank assignments to a strictly incremental sequence. More detailed information is available [here](https://registry.terraform.io/providers/CiscoDevNet/ise/latest/docs/guides/authentication_rules).

## 0.2.2

- Fix issue with `ise_repository` triggers in-place upgrade when no changes are made #59

## 0.2.1

- Make `groupId` attribute of `ise_endpoint` resource optional

## 0.2.0

- Add `ise_endpoint` resource and data source
- Add support for ISE version 3.3.0

## 0.1.14

- Use `set` type for list attributes with primitive values
- Implement workaround for API issue when creating multiple network device groups at once

## 0.1.13

- Add `default` attribute to `ise_network_access_policy_set` resource
- Add `default` attribute to `ise_device_admin_policy_set` resource
- Allow updating default policy sets and rules

## 0.1.12

- Ignore error messages when attempting to delete default policy sets or rules
- Add `ise_active_directory_add_groups` resource
- Add `ise_active_directory_join_domain_with_all_nodes` resource
- Add `ise_active_directory_groups_by_domain` data source

## 0.1.11

- Fix import operation of nested resources (e.g. `ise_network_access_authentication_rule`)
- Fix name-based queries for `device_admin` and `network_access` data sources
- Add `ise_active_directory_join_point` resource and data source

## 0.1.10

- Retry on 400 and 500 HTTP errors when creating or updating objects
- Fix import operation of resources

## 0.1.9

- Fix issue with `ise_network_device_group` resource and ISE versions >= 3.2.0 Patch1. Due to a breaking change in the API, this resource is now only supported with ISE version >= 3.2.0 Patch1.
- Add `ise_identity_source_sequence` resource and data source

## 0.1.8

- Fix default value of `ip_version` attribute of `ise_trustsec_security_group_acl` resource
- Fix idempotency issue with `ise_network_access_condition` and `ise_device_admin_condition` resources

## 0.1.7

- BREAKING CHANGE: Refactor `advanced_attributes` of `ise_authorization_profile` resource and data source
- Add `ise_allowed_protocols_tacacs` resource and data source

## 0.1.6

- Add `ise_downloadable_acl` resource and data source
- Add `ise_tacacs_command_set` resource and data source
- Add `ise_tacacs_profile` resource and data source
- Add `ise_device_admin_condition` resource and data source
- Add `ise_device_admin_policy_set` resource and data source
- Add `ise_device_admin_time_and_date_condition` resource and data source
- Add `ise_device_admin_authentication_rule` resource and data source
- Add `ise_device_admin_authorization_rule` resource and data source
- Add `ise_device_admin_authorization_exception_rule` resource and data source
- Add `ise_device_admin_authorization_global_exception_rule` resource and data source
- BREAKING CHANGE: Rename `profile` attribute to `profiles` of `ise_network_access_authorization_rule` resource and data source
- Add `ise_network_access_authorization_exception_rule` resource and data source
- Add `ise_network_access_authorization_global_exception_rule` resource and data source

## 0.1.5

- Make `sgacls` attribute of `ise_trustsec_egress_matrix_cell` resource optional

## 0.1.4

- Add `ise_trustsec_ip_to_sgt_mapping` resource and data source
- Add `ise_trustsec_ip_to_sgt_mapping_group` resource and data source

## 0.1.3

- Add support for nested conditions to `ise_network_access_authentication_rule` resource and data source
- Add support for nested conditions to `ise_network_access_authorization_rule` resource and data source
- BREAKING CHANGE: Remove `condition_` prefix from nested attributes of `ise_network_access_policy_set` resource and data source
- Instead of specifying an `id` when querying an object using a data source, `name` can also be used

## 0.1.2

- Fix issue with reading nested conditions using `ise_network_access_condition` resource
- Add support for nested conditions to `ise_network_access_policy_set` resource and data source
- Add `agentless_posture` attribute to `ise_authorization_profile` resource and data source
- Add `identity_groups` and `custom_attributes` attributes to `ise_internal_user` resource and data source
- Add support for nested conditions to `ise_network_access_authentication_rule` resource and data source
- Add support for nested conditions to `ise_network_access_authorization_rule` resource and data source
- Add `ise_trustsec_egress_matrix_cell` resource and data source
- Add `ise_trustsec_security_group_acl` resource and data source

## 0.1.1

- Fix issue with nested conditions using `ise_network_access_condition` resource

## 0.1.0

- Initial Release
