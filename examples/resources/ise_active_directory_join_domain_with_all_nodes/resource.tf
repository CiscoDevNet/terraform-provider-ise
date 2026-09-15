resource "ise_active_directory_join_domain_with_all_nodes" "example" {
  join_point_id = "73808580-b6e6-11ee-8960-de6d7692bc40"
  additional_data = [
    {
      name  = "username"
      value = "administrator"
    }
  ]
}
