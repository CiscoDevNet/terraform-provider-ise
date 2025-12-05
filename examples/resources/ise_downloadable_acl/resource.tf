resource "ise_downloadable_acl" "example" {
  name = "MyACL"
  description = "My first downloadable ACL"
  dacl = "permit ip any any"
  dacl_type = "IPV4"
}
