---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "ise_trustsec_security_group_acl Data Source - terraform-provider-ise"
subcategory: "TrustSec"
description: |-
  This data source can read the TrustSec Security Group ACL.
---

# ise_trustsec_security_group_acl (Data Source)

This data source can read the TrustSec Security Group ACL.

## Example Usage

```terraform
data "ise_trustsec_security_group_acl" "example" {
  id = "76d24097-41c4-4558-a4d0-a8c07ac08470"
}
```

<!-- schema generated by tfplugindocs -->
## Schema

### Optional

- `id` (String) The id of the object
- `name` (String) The name of the security group ACL

### Read-Only

- `acl_content` (String) Content of ACL
- `description` (String) Description
- `ip_version` (String) IP Version
- `read_only` (Boolean) Read-only
