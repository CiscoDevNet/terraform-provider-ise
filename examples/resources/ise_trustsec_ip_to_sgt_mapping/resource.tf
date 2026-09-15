resource "ise_trustsec_ip_to_sgt_mapping" "example" {
  name = "10.0.0.1/32"
  deploy_type = "ALL"
  host_ip = "10.0.0.1/32"
  sgt = "93e1bf00-8c01-11e6-996c-525400b48521"
}
