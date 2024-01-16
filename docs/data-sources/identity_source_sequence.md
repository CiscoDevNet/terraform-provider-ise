---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "ise_identity_source_sequence Data Source - terraform-provider-ise"
subcategory: "Identity Management"
description: |-
  This data source can read the Identity Source Sequence.
---

# ise_identity_source_sequence (Data Source)

This data source can read the Identity Source Sequence.

## Example Usage

```terraform
data "ise_identity_source_sequence" "example" {
  id = "76d24097-41c4-4558-a4d0-a8c07ac08470"
}
```

<!-- schema generated by tfplugindocs -->
## Schema

### Optional

- `id` (String) The id of the object
- `name` (String) The name of the identity source sequence

### Read-Only

- `break_on_store_fail` (Boolean) Do not access other stores in the sequence if a selected identity store cannot be accessed for authentication
- `certificate_authentication_profile` (String) Certificate Authentication Profile, empty if doesn't exist
- `description` (String) Description
- `identity_sources` (Attributes List) (see [below for nested schema](#nestedatt--identity_sources))

<a id="nestedatt--identity_sources"></a>
### Nested Schema for `identity_sources`

Read-Only:

- `name` (String) Name of the identity source
- `order` (Number) Order of the identity source in the sequence