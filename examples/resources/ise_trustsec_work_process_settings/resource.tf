resource "ise_trustsec_work_process_settings" "example" {
  matrix_mode              = "MULTIPLE_MATRICES"
  use_defcons              = false
  enable_approval_workflow = false
}
