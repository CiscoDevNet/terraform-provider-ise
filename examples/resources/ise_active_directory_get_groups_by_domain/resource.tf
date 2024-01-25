resource "ise_active_directory_get_groups_by_domain" "example" {
  join_point_id = "73808580-b6e6-11ee-8960-de6d7692bc40"
  additional_data = [
    {
      name  = "domain"
      value = "cisco.local"
    }
  ]
}
