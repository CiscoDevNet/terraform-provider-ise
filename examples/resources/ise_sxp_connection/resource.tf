resource "ise_sxp_connection" "example" {
  name        = "SXPConnection1"
  sxp_peer    = "SXPPeer1"
  sxp_vpn     = "default"
  sxp_node    = "ise1"
  ip_address  = "10.0.0.1"
  sxp_mode    = "SPEAKER"
  sxp_version = "VERSION_2"
  enabled     = true
}
