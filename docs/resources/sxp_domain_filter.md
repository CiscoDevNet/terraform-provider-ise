---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "ise_sxp_domain_filter Resource - terraform-provider-ise"
subcategory: "TrustSec"
description: |-
  This resource can manage a SXP Domain Filter.
---

# ise_sxp_domain_filter (Resource)

This resource can manage a SXP Domain Filter.

## Example Usage

```terraform
resource "ise_sxp_domain_filter" "example" {
  subnet  = "1.0.0.0/24"
  vn      = "VN1"
  domains = "default"
}
```

<!-- schema generated by tfplugindocs -->
## Schema

### Required

- `domains` (String) List of SXP Domains, separated with comma

### Optional

- `description` (String) Description
- `name` (String) Resource name
- `sgt` (String) SGT name or ID. At least one of subnet or sgt or vn should be defined
- `subnet` (String) Subnet for filter policy (hostname is not supported). At least one of subnet or sgt or vn should be defined
- `vn` (String) Virtual Network. At least one of subnet or sgt or vn should be defined

### Read-Only

- `id` (String) The id of the object

## Import

Import is supported using the following syntax:

```shell
terraform import ise_sxp_domain_filter.example "76d24097-41c4-4558-a4d0-a8c07ac08470"
```