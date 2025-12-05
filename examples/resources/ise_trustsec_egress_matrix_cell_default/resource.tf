resource "ise_trustsec_egress_matrix_cell_default" "example" {
  description = "Default egress rule"
  default_rule = "PERMIT_IP"
  matrix_cell_status = "ENABLED"
}
