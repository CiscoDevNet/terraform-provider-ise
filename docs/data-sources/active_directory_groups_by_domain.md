---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "ise_active_directory_groups_by_domain Data Source - terraform-provider-ise"
subcategory: "Identity Management"
description: |-
  This data source can read the Active Directory Groups By Domain.
---

# ise_active_directory_groups_by_domain (Data Source)

This data source can read the Active Directory Groups By Domain.

## Example Usage

```terraform
data "ise_active_directory_groups_by_domain" "example" {
  join_point_id = "73808580-b6e6-11ee-8960-de6d7692bc40"
  domain        = "cisco.com"
  filter        = "CN=ISE Admins"
  sid_filter    = "cisco.com/S-1-5-33-544"
  type_filter   = "UNIVERSAL"
}
```

<!-- schema generated by tfplugindocs -->
## Schema

### Required

- `domain` (String) The domain whose groups we want to fetch
- `join_point_id` (String) Active Directory Join Point ID

### Optional

- `filter` (String) Exact match filter on group's CN
- `sid_filter` (String) Exact match filter on group's SID, optionally specifying the domain as prefix. e.g. S-1-5-33-544 and R1.dom/S-1-5-33-544 are legal.
- `type_filter` (String) Can be exactly one of: BUILTIN, DOMAIN LOCAL, GLOBAL, UNIVERSAL.

### Read-Only

- `groups` (Attributes List) List of groups (see [below for nested schema](#nestedatt--groups))

<a id="nestedatt--groups"></a>
### Nested Schema for `groups`

Read-Only:

- `name` (String) Group name
- `sid` (String) Group SID
- `type` (String) Group type
