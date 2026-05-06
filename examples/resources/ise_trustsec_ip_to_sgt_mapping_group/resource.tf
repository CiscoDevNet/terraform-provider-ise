resource "ise_trustsec_ip_to_sgt_mapping_group" "example" {
  name        = "groupA"
  deploy_type = "ALL"
  sgt         = "93e1bf00-8c01-11e6-996c-525400b48521"
}
