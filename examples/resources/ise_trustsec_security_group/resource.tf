resource "ise_trustsec_security_group" "example" {
  name = "SGT1234"
  description = "My SGT"
  value = 1234
  propogate_to_apic = true
  is_read_only = false
}
