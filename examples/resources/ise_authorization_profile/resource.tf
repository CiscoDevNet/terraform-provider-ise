resource "ise_authorization_profile" "example" {
  name                                  = "AuthzProfile1"
  description                           = "My Authorization Profile"
  name_id                               = "VLAN10"
  tag_id                                = 0
  web_redirection_type                  = "CentralizedWebAuth"
  web_redirection_acl                   = "TEST_ACL"
  portal_name                           = "Sponsored Guest Portal (default)"
  display_certificates_renewal_messages = true
  access_type                           = "ACCESS_ACCEPT"
  authz_profile_type                    = "SWITCH"
  profile_name                          = "Cisco"
  asa_vpn                               = ""
  unique_identifier                     = ""
  track_movement                        = false
  service_template                      = false
  easywired_session_candidate           = false
  connectivity                          = "DEFAULT"
  timer                                 = 1
  advanced_attributes = [
    {
      attribute_1_value_type = "AdvancedDictionaryAttribute"
      dictionary_name        = "Cisco"
      attribute_name         = "cisco-av-pair"
      attribute_2_value_type = "AttributeValue"
      value                  = "set_nadprofile_vlan=true,vlan=TEST,tag=1"
    }
  ]
}
