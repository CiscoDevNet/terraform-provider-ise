## 0.1.15 (unreleased)

- Add `ise_endpoint` resource and data source

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
