resource "ise_internal_user" "example" {
  name                   = "UserTF"
  password               = "Cisco123"
  change_password        = true
  email                  = "aaa@cisco.com"
  account_name_alias     = "User 1"
  enable_password        = "Cisco123"
  enabled                = true
  password_never_expires = false
  first_name             = "John"
  last_name              = "Doe"
  password_id_store      = "Internal Users"
  description            = "My first Terraform user"
}
