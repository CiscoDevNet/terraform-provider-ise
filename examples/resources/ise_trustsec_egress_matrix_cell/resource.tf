resource "ise_trustsec_egress_matrix_cell" "example" {
  description        = "EgressMatrixCell Description"
  matrix_cell_status = "ENABLED"
  sgacls             = [""]
  source_sgt_id      = ""
  destination_sgt_id = ""
}
