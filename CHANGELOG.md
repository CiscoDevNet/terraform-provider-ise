## 0.1.9 (unreleased)

- Fix issue with `ise_network_device_group` resource and ISE versions >= 3.2.0 Patch1. Due to a breaking change in the API, this resource is now only supported with ISE version >= 3.2.0 Patch1.

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
