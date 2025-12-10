data "ise_active_directory_groups_by_domain" "example" {
  join_point_id = "73808580-b6e6-11ee-8960-de6d7692bc40"
  domain        = "cisco.com"
  filter        = "CN=ISE Admins"
  sid_filter    = "cisco.com/S-1-5-33-544"
  type_filter   = "UNIVERSAL"
}
