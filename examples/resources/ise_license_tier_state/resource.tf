resource "ise_license_tier_state" "example" {
  licenses = [
    {
      name = "ESSENTIAL"
      status = "ENABLED"
    }
  ]
}
