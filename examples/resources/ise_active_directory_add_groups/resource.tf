resource "ise_active_directory_add_groups" "example" {
  join_point_id              = "73808580-b6e6-11ee-8960-de6d7692bc40"
  name                       = "cisco.local"
  description                = "My AD join point"
  domain                     = "cisco.local"
  ad_scopes_names            = "Default_Scope"
  enable_domain_allowed_list = true
  groups = [
    {
      name = "cisco.local/operators"
      sid  = "S-1-5-32-548"
      type = "GLOBAL"
    }
  ]
}
