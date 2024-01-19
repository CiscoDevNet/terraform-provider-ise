resource "ise_active_directory_join_point" "example" {
  name        = "cisco.local"
  description = "My AD join point"
  domain      = "cisco.local"
}
