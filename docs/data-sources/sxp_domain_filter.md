---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "ise_sxp_domain_filter Data Source - terraform-provider-ise"
subcategory: "TrustSec"
description: |-
  This data source can read the SXP Domain Filter.
---

# ise_sxp_domain_filter (Data Source)

This data source can read the SXP Domain Filter.

## Example Usage

```terraform
data "ise_sxp_domain_filter" "example" {
  id = "76d24097-41c4-4558-a4d0-a8c07ac08470"
}
```

<!-- schema generated by tfplugindocs -->
## Schema

### Optional

- `id` (String) The id of the object
- `name` (String) Resource name

### Read-Only

- `description` (String) Description
- `domains` (String) List of SXP Domains, separated with comma
- `sgt` (String) SGT name or ID. At least one of subnet or sgt or vn should be defined
- `subnet` (String) Subnet for filter policy (hostname is not supported). At least one of subnet or sgt or vn should be defined
- `vn` (String) Virtual Network. At least one of subnet or sgt or vn should be defined
