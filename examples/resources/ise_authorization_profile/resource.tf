resource "ise_authorization_profile" "example" {
  name                                                  = "AuthzProfile1"
  description                                           = "My Authorization Profile"
  vlan_name_id                                          = "VLAN10"
  vlan_tag_id                                           = 0
  web_redirection_type                                  = "CentralizedWebAuth"
  web_redirection_acl                                   = "TEST_ACL"
  web_redirection_portal_name                           = "Sponsored Guest Portal (default)"
  web_redirection_static_ip_host_name_fqdn              = "1.2.3.4"
  web_redirection_display_certificates_renewal_messages = true
  agentless_posture                                     = false
  access_type                                           = "ACCESS_ACCEPT"
  profile_name                                          = "Cisco"
  airespace_acl                                         = "ACL1"
  acl                                                   = "ACL1"
  auto_smart_port                                       = "PROFILE1"
  interface_template                                    = "TEMP1"
  ipv6_acl_filter                                       = "ACL1"
  avc_profile                                           = "PROF1"
  asa_vpn                                               = "1"
  unique_identifier                                     = "ID1234"
  track_movement                                        = false
  service_template                                      = false
  easywired_session_candidate                           = false
  voice_domain_permission                               = false
  neat                                                  = false
  web_auth                                              = false
  mac_sec_policy                                        = "MUST_SECURE"
  reauthentication_connectivity                         = "DEFAULT"
  reauthentication_timer                                = 1
  advanced_attributes = [
    {
      attribute_left_dictionary_name = "Cisco"
      attribute_left_name            = "cisco-av-pair"
      attribute_right_value_type     = "AttributeValue"
      attribute_right_value          = "set_nadprofile_vlan=true,vlan=TEST,tag=1"
    }
  ]
  airespace_ipv6_acl = "ACL1"
}
