resource "ise_trustsec_security_group_acl" "example" {
  name = "ACL1"
  description = "SG ACL 1"
  acl_content = "Permit IP"
  ip_version = "IPV4"
  read_only = false
}
