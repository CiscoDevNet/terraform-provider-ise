resource "ise_sxp_domain_filter" "example" {
  subnet  = "1.0.0.0/24"
  vn      = "VN1"
  domains = "default"
}
