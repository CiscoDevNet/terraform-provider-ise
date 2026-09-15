resource "ise_trustsec_matrix" "example" {
  name               = "MyMatrix"
  description        = "My TrustSec Matrix Policy"
  matrix_policy_type = "TRUSTSEC_POLICY"
}
