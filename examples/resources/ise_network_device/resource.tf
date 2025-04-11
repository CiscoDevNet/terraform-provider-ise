resource "ise_network_device" "example" {
  name                                          = "Device1"
  description                                   = "My device"
  authentication_enable_key_wrap                = true
  authentication_encryption_key                 = "cisco123cisco123"
  authentication_encryption_key_format          = "ASCII"
  authentication_message_authenticator_code_key = "cisco123cisco1235678"
  authentication_network_protocol               = "RADIUS"
  authentication_radius_shared_secret           = "cisco123"
  authentication_enable_multi_secret            = true
  authentication_second_radius_shared_secret    = "cisco12345"
  authentication_dtls_required                  = true
  coa_port                                      = 12345
  dtls_dns_name                                 = "cisco.com"
  ips = [
    {
      ipaddress = "2.3.4.5"
      mask      = "32"
    }
  ]
  model_name                                                  = "Unknown"
  software_version                                            = "Unknown"
  profile_name                                                = "Cisco"
  snmp_link_trap_query                                        = true
  snmp_mac_trap_query                                         = true
  snmp_polling_interval                                       = 1200
  snmp_ro_community                                           = "rocom"
  snmp_version                                                = "TWO_C"
  tacacs_connect_mode_options                                 = "OFF"
  tacacs_shared_secret                                        = "cisco123"
  trustsec_device_id                                          = "device123"
  trustsec_device_password                                    = "cisco123"
  trustsec_rest_api_username                                  = "user123"
  trustsec_rest_api_password                                  = "Cisco123"
  trustsec_enable_mode_password                               = "cisco123"
  trustsec_exec_mode_password                                 = "cisco123"
  trustsec_exec_mode_username                                 = "user456"
  trustsec_include_when_deploying_sgt_updates                 = true
  trustsec_download_environment_data_every_x_seconds          = 1000
  trustsec_download_peer_authorization_policy_every_x_seconds = 1000
  trustsec_download_sgacl_lists_every_x_seconds               = 1000
  trustsec_other_sga_devices_to_trust_this_device             = true
  trustsec_re_authentication_every_x_seconds                  = 1000
  trustsec_send_configuration_to_device                       = true
  trustsec_send_configuration_to_device_using                 = "ENABLE_USING_COA"
}
