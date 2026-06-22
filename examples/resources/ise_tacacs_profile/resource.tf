resource "ise_tacacs_profile" "example" {
  name        = "Profile1"
  description = "My TACACS profile"
  session_attributes = [
    {
      type  = "MANDATORY"
      name  = "attr1"
      value = "value"
    }
  ]
}
