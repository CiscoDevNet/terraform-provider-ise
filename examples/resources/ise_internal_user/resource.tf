resource "ise_internal_user" "example" {
  name                       = "UserTF"
  password_wo                = "Cisco123"
  password_wo_version        = 1
  change_password            = true
  email                      = "aaa@cisco.com"
  account_name_alias         = "User 1"
  enable_password_wo         = "Cisco123"
  enable_password_wo_version = 1
  enabled                    = true
  password_never_expires     = false
  first_name                 = "John"
  last_name                  = "Doe"
  password_id_store          = "Internal Users"
  description                = "My first Terraform user"
}
