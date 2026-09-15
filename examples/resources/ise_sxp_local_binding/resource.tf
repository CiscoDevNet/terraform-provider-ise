resource "ise_sxp_local_binding" "example" {
  name               = "SXPLocalBinding1"
  ip_address_or_host = "10.0.0.1"
  sgt                = "SGT1234"
  sxp_vpn            = "default"
}
