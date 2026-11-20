resource "ise_trusted_certificate" "example" {
  name                                   = "Example Root CA"
  description                            = "Root CA for ISE and endpoint authentication"
  certificate_pem                        = file("ca.pem")
  trust_for_ise_auth                     = true
  trust_for_client_auth                  = true
  trust_for_certificate_based_admin_auth = false
  trust_for_cisco_services_auth          = false
  retain_on_destroy                      = true
  create_timeout_seconds                 = 120
}
