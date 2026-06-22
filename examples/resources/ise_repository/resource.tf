resource "ise_repository" "example" {
  name        = "repo1"
  protocol    = "SFTP"
  path        = "/dir"
  server_name = "server1"
  user_name   = "user9"
  password    = "cisco123"
  enable_pki  = false
}
