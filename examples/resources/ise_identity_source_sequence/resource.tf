resource "ise_identity_source_sequence" "example" {
  name = "Sequence1"
  description = "My identity source sequence"
  break_on_store_fail = true
  certificate_authentication_profile = "Preloaded_Certificate_Profile"
  identity_sources = [
    {
      name = "Internal Users"
      order = 1
    }
  ]
}
