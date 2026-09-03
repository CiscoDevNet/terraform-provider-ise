## 0.4.1 (unreleased)

- Add `rsa_pss` (ISE 3.4+) and `display_additional_tls_params` (ISE 3.5+) attributes to the `ise_allowed_protocols` resource and data source
- Fix perpetual drift in the `identity_groups` attribute of the `ise_internal_user` resource, where ISE returns the comma-separated UUID list in an internal order that varies across ISE instances and versions, causing Terraform to report changes on every plan even when no groups were added or removed. The provider now sorts the value on read so that state always reflects a canonical ascending order, matching the sort applied by the module on write.
- Add `ise_sxp_connection`, `ise_sxp_vpn` and `ise_sxp_local_binding` resources and data sources
- Fix `snmp_polling_interval` on the `ise_network_device` resource rejecting `0`, which is a valid ISE value meaning "SNMP polling disabled". The validator now accepts `0` (disabled) or `600`-`86400` (enabled), matching ISE's actual constraint. The generator was also extended with a `zero_allowed` field for other attributes that follow this "sentinel or range" pattern.
- Fix perpetual `coa_port = 0 -> 1700` drift on the `ise_network_device` resource for TACACS-only devices. The `coa_port` attribute had a provider-level `Default(1700)` and `Computed: true` that resolved a null config value to `1700` at plan time, causing drift whenever ISE reported `coaPort: 0` (no CoA configured). Removing the schema default makes `coa_port` behave like all other optional RADIUS attributes on this resource — if not set in config, ISE retains its current value and no plan diff is generated.
- Fix destroy/recreate of `ise_active_directory_join_point` during brownfield import, where ISE returns existing `groups` and `rewrite_rules` in the GET response but these attributes were not marked as `Computed`, causing Terraform to plan a destroy and recreate of the resource to reconcile the difference

## 0.4.0

- Change the `custom_attributes` attribute of the `ise_internal_user` resource from a JSON-encoded `String` to a `Map` of strings, fixing an HTTP 400 on apply (the value was serialized as a quoted string that ISE rejected) and perpetual drift (string comparison was sensitive to whitespace and key ordering). This matches how `ise_endpoint` already models its `custom_attributes`. **Breaking change:** configurations must now supply a native map (`custom_attributes = { key = "value" }`) instead of `jsonencode({ ... })` [link](https://github.com/CiscoDevNet/terraform-provider-ise/issues/253)
- Change the `data_type` enum values in the `ise_network_access_dictionary_attribute` resource from `UNIT64`, `IPv4` and `IPv6` to `UINT64`, `IPV4` and `IPV6` to match the ISE API and avoid HTTP 400 errors
- Fix perpetual drift in the `group_id` and `profile_id` attributes of the `ise_endpoint` resource, where ISE dynamically assigns these values when `static_group_assignment` / `static_profile_assignment` are `false`, causing Terraform to report changes on every plan
- Fix perpetual drift after importing existing (brownfield) resources, where ISE returns normalized values for policy condition operators (e.g. `ipEquals` for `equals`) and empty strings for unset optional fields such as `description`, causing Terraform to report changes on every plan

## 0.3.4

- Fix perpetual drift in the `custom_attributes` attribute of the `ise_endpoint` resource, where ISE returns all globally-defined endpoint custom attributes (including unassigned ones as empty strings), causing Terraform to report changes on every plan
- Make `password` optional in the `ise_internal_user` resource to support brownfield management of existing ISE user accounts without requiring the password to be stored in configuration

## 0.3.3

- Make `certificate_authentication_profile` optional in the `ise_identity_source_sequence` resource
- Fix issue with `Map` type attributes using a nested `data_path` generating a malformed JSON key (e.g. `custom_attributes` on `ise_endpoint` produced `[ERSEndPoint customAttributes]` instead of the nested `ERSEndPoint.customAttributes` path), causing API request and read failures

## 0.3.2

- Fix issue with deeply nested policy conditions losing their children during update operations

## 0.3.1

- Add `ise_network_access_dictionary_attribute` resource and data source
- Fix issue with duplicate key matching in `updateFromBody` causing permanent idempotency failure when resource attributes share overlapping key names [link](https://github.com/CiscoDevNet/terraform-provider-ise/issues/205)

## 0.3.0

- Added `request_timeout` provider attribute (60–600 seconds, default 60) to handle ISE API latency for deeply nested condition processing. Configurable via `ISE_REQUEST_TIMEOUT` environment variable
- Change `children` attribute type from `Set` to `List` in all policy condition resources
- Extended policy condition nesting support from 3 to 7 levels (1 root + 6 nested children) for all 12 Network Access and Device Admin policy resources
- Fix issue with `trustsec_egress_matrix_cell` updates while using `DENY_IP` or `PERMIT_IP` sgacl

## 0.2.17

- Add `matrix_id` attribute to `trustsec_egress_matrix_cell` resource (requires ISE 3.4 patch 2 or later)
- Add `ise_trustsec_work_process_settings` resource
- Add `ise_trustsec_matrix` resource and data source

## 0.2.16

- Add `ise_profiler_profile` data source

## 0.2.15

- Add `ALL_SUBJECT_AND_ALTERNATIVE_NAMES` option to `certificate_attribute_name` attribute in `ise_certificate_authentication_profile` resource
- Remove default value from `certificate_attribute_name` attribute to align with ISE API behavior when using UPN authentication
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
