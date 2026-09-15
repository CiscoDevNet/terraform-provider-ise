resource "ise_certificate_authentication_profile" "example" {
  name = "CertProf1"
  description = "My cert profile"
  allowed_as_user_name = false
  external_identity_store_name = "[not applicable]"
  certificate_attribute_name = "SUBJECT_COMMON_NAME"
  match_mode = "NEVER"
  username_from = "CERTIFICATE"
}
