resource "ise_device_admin_policy_set_update_ranks" "example" {
  policies = [
    {
      id   = "d82952cb-b901-4b09-b363-5ebf39bdbaf9"
      rank = 0
    }
  ]
}
