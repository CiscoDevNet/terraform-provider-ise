# Supply through an ephemeral variable so keys are not saved in plan or state.
variable "private_keys" {
  type      = map(string)
  sensitive = true
  ephemeral = true
}

# Root and issuing CAs must already be trusted for Infrastructure on every node.
resource "ise_system_certificate_deployment" "example" {
  root_certificate_pem = file("root-ca.pem")
  nodes = [
    {
      hostname              = "secondary.example.test"
      address               = "192.0.2.4"
      admin_certificate_pem = file("secondary.pem")
      admin_ca_pem          = file("issuing-ca.pem")
      eap                   = false
    },
    {
      hostname              = "primary.example.test"
      address               = "192.0.2.5"
      admin_certificate_pem = file("primary.pem")
      admin_ca_pem          = file("issuing-ca.pem")
      eap                   = false
    }
  ]
  private_keys_wo         = var.private_keys
  private_keys_wo_version = 1
  timeout_seconds         = 1800
}
