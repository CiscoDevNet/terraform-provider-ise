resource "ise_repository" "example" {
  name                = "repo1"
  protocol            = "SFTP"
  path                = "/dir"
  server_name         = "server1"
  user_name           = "user9"
  password_wo         = "cisco123"
  password_wo_version = 1
  enable_pki          = false
}
