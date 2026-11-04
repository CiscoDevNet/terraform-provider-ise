resource "ise_system_certificate_deployment" "example" {
  root_certificate_pem = file("root-ca.pem")
  nodes = [
    {
      hostname              = "primary.example.test"
      address               = "192.0.2.5"
      admin_certificate_pem = file("primary.pem")
      admin_ca_pem          = file("issuing-ca.pem")
      eap                   = false
    }
  ]
  private_keys_wo         = { "primary.example.test" = file("primary.key") }
  private_keys_wo_version = 1
  timeout_seconds         = 1800
}
