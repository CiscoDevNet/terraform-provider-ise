resource "ise_device_admin_authentication_rule_update_ranks" "example" {
  policy_set_id = "d82952cb-b901-4b09-b363-5ebf39bdbaf9"
  rules = [
    {
      id = "3741aca3-db08-4899-af73-2e3f65ec31e1"
      rank = 0
    }
  ]
}
