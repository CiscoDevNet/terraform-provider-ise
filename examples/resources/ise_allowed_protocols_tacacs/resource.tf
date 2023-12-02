resource "ise_allowed_protocols_tacacs" "example" {
  name             = "Protocols1"
  description      = "My allowed TACACS protocols"
  allow_pap_ascii  = true
  allow_chap       = true
  allow_ms_chap_v1 = true
}
