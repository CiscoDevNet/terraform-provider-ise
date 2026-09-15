resource "ise_network_device_group" "example" {
  name = "Device Type#All Device Types#Group1"
  description = "My network device group"
  root_group = "Device Type"
}
