resource "ise_trustsec_egress_matrix_cell" "example" {
  description = "EgressMatrixCell Description"
  default_rule = "NONE"
  matrix_cell_status = "ENABLED"
  sgacls = ["26b76b10-66e6-11ee-9cc1-9eb2a3ecc82a, 9d64dcd0-6384-11ee-9cc1-9eb2a3ecc82a"]
  source_sgt_id = "93c66ed0-8c01-11e6-996c-525400b48521"
  destination_sgt_id = "93e1bf00-8c01-11e6-996c-525400b48521"
}
