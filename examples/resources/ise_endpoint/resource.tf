resource "ise_endpoint" "example" {
  name                              = "00:11:22:33:44:55"
  description                       = "My endpoint"
  mac                               = "00:11:22:33:44:55"
  group_id                          = "3a88eec0-8c00-11e6-996c-525400b48521"
  profile_id                        = "3a91a150-8c00-11e6-996c-525400b48521"
  static_profile_assignment         = true
  static_profile_assignment_defined = true
  static_group_assignment           = true
  static_group_assignment_defined   = true
}
