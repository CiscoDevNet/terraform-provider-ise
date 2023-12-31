---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "ise_allowed_protocols Data Source - terraform-provider-ise"
subcategory: "Network Access"
description: |-
  This data source can read an allowed protocols policy element.
---

# ise_allowed_protocols (Data Source)

This data source can read an allowed protocols policy element.

## Example Usage

```terraform
data "ise_allowed_protocols" "example" {
  id = "76d24097-41c4-4558-a4d0-a8c07ac08470"
}
```

<!-- schema generated by tfplugindocs -->
## Schema

### Optional

- `id` (String) The id of the object
- `name` (String) The name of the allowed protocols

### Read-Only

- `allow_5g` (Boolean) Allow 5G. This field is only supported from ISE 3.2.
- `allow_chap` (Boolean) Allow CHAP
- `allow_eap_fast` (Boolean) Allow EAP Fast
- `allow_eap_md5` (Boolean) Allow EAP MD5
- `allow_eap_tls` (Boolean) Allow EAP TLS
- `allow_eap_ttls` (Boolean) Allow EAP TTLS
- `allow_leap` (Boolean) Allow LEAP
- `allow_ms_chap_v1` (Boolean) Allow MS CHAP v1
- `allow_ms_chap_v2` (Boolean) Allow MS CHAP v2
- `allow_pap_ascii` (Boolean) Allow PAP ASCII
- `allow_peap` (Boolean) Allow PEAP
- `allow_preferred_eap_protocol` (Boolean) Allow preferred EAP protocol
- `allow_teap` (Boolean) Allow TEAP
- `allow_weak_ciphers_for_eap` (Boolean) Allow weak ciphers for EAP
- `description` (String) Description
- `eap_fast_accept_client_cert` (Boolean) Accept client certificates. Is required only if `eap_fast_use_pacs` is `false`.
- `eap_fast_allow_machine_authentication` (Boolean) Allow machine authentication. Is required only if `eap_fast_use_pacs` is `false`.
- `eap_fast_eap_gtc` (Boolean) Allow EAP GTC
- `eap_fast_eap_gtc_pwd_change` (Boolean) Allow EAP GTC password change. Is required only if `eap_fast_eap_gtc` is `true`.
- `eap_fast_eap_gtc_pwd_change_retries` (Number) EAP GTC password change retries. Is required only if `eap_fast_eap_gtc` is `true`.
- `eap_fast_eap_ms_chap_v2` (Boolean) Allow EAP MS CHAP v2
- `eap_fast_eap_ms_chap_v2_pwd_change` (Boolean) Allow EAP MS CHAP v2 password change. Is required only if `eap_fast_eap_ms_chap_v2` is `true`.
- `eap_fast_eap_ms_chap_v2_pwd_change_retries` (Number) EAP MS CHAP v2 password change retries. Is required only if `eap_fast_eap_ms_chap_v2` is `true`.
- `eap_fast_eap_tls` (Boolean) Allow EAP TLS
- `eap_fast_eap_tls_auth_of_expired_certs` (Boolean) Allow EAP TLS authentication of expired certificates. Is required only if `eap_fast_eap_tls` is `true`.
- `eap_fast_enable_eap_chaining` (Boolean) Enable EAP chaining
- `eap_fast_pacs_allow_anonymous_provisioning` (Boolean) Allow anonymous provisioning. Is required only if `eap_fast_use_pacs` is `true`.
- `eap_fast_pacs_allow_authenticated_provisioning` (Boolean) Allow authenticated provisioning. Is required only if `eap_fast_use_pacs` is `true`.
- `eap_fast_pacs_allow_client_cert` (Boolean) Accept client certification for provisioning. Is required only if `eap_fast_pacs_allow_authenticated_provisioning` is `true`.
- `eap_fast_pacs_allow_machine_authentication` (Boolean) Allow machine authentication. Is required only if `eap_fast_use_pacs` is `true`.
- `eap_fast_pacs_authorization_pac_ttl` (Number) Authorization PAC TTL. Is required only if `eap_fast_pacs_stateless_session_resume` is `true`.
- `eap_fast_pacs_authorization_pac_ttl_unit` (String) Authorization PAC TTL unit. Is required only if `eap_fast_pacs_stateless_session_resume` is `true`.
- `eap_fast_pacs_machine_pac_ttl` (Number) Machine PAC TTL. Is required only if `eap_fast_pacs_allow_machine_authentication` is `true`.
- `eap_fast_pacs_machine_pac_ttl_unit` (String) Machine PAC TTL unit. Is required only if `eap_fast_pacs_allow_machine_authentication` is `true`.
- `eap_fast_pacs_server_returns` (Boolean) Server returns access accept after authenticated provisioning. Is required only if `eap_fast_pacs_allow_authenticated_provisioning` is `true`.
- `eap_fast_pacs_stateless_session_resume` (Boolean) Stateless session resume. Is required only if `eap_fast_use_pacs` is `true`.
- `eap_fast_pacs_tunnel_pac_ttl` (Number) PACs tunnel PAC time to live. Is required only if `eap_fast_use_pacs` is `true`.
- `eap_fast_pacs_tunnel_pac_ttl_unit` (String) PACs tunnel PAC time to live unit. Is required only if `eap_fast_use_pacs` is `true`.
- `eap_fast_pacs_use_proactive_pac_update_percentage` (Number) Use proactive pac update percentage. Is required only if `eap_fast_use_pacs` is `true`.
- `eap_fast_use_pacs` (Boolean) Use PACs
- `eap_tls_allow_auth_of_expired_certs` (Boolean) Allow authentication of expired certificates
- `eap_tls_enable_stateless_session_resume` (Boolean) Enable stateless session resume
- `eap_tls_l_bit` (Boolean) EAP TLS L-Bit
- `eap_tls_session_ticket_percentage` (Number) Session ticket percentage. Is required only if `eap_tls_enable_stateless_session_resume` is `true`.
- `eap_tls_session_ticket_ttl` (Number) Session ticket TTL. Is required only if `eap_tls_enable_stateless_session_resume` is `true`.
- `eap_tls_session_ticket_ttl_unit` (String) Session ticket TTL unit. Is required only if `eap_tls_enable_stateless_session_resume` is `true`.
- `eap_ttls_chap` (Boolean) Allow CHAP
- `eap_ttls_eap_md5` (Boolean) Allow EAP MD5
- `eap_ttls_eap_ms_chap_v2` (Boolean) Allow EAP MS CHAP v2
- `eap_ttls_eap_ms_chap_v2_pwd_change` (Boolean) Allow EAP MS CHAP v2 password change. Is required only if `eap_ttls_eap_ms_chap_v2` is `true`.
- `eap_ttls_eap_ms_chap_v2_pwd_change_retries` (Number) EAP MS CHAP v2 password change retries. Is required only if `eap_ttls_eap_ms_chap_v2` is `true`.
- `eap_ttls_ms_chap_v1` (Boolean) Allow MS CHAP v1
- `eap_ttls_ms_chap_v2` (Boolean) Allow MS CHAP v2
- `eap_ttls_pap_ascii` (Boolean) Allow PAP ASCII
- `peap_allow_peap_eap_gtc` (Boolean) Allow PEAP EAP GTC
- `peap_allow_peap_eap_gtc_pwd_change` (Boolean) Allow PEAP EAP GTC password change. Is required only if `allow_peap_eap_gtc` is `true`.
- `peap_allow_peap_eap_gtc_pwd_change_retries` (Number) PEAP EAP GTC password change retries. Is required only if `allow_peap_eap_gtc` is `true`.
- `peap_allow_peap_eap_ms_chap_v2` (Boolean) Allow PEAP EAP MS CHAP v2
- `peap_allow_peap_eap_ms_chap_v2_pwd_change` (Boolean) Allow PEAP EAP MS CHAP v2 password change. Is required only if `allow_peap_eap_ms_chap_v2` is `true`.
- `peap_allow_peap_eap_ms_chap_v2_pwd_change_retries` (Number) Allow PEAP EAP MS CHAP v2 password change retries. Is required only if `allow_peap_eap_ms_chap_v2` is `true`.
- `peap_allow_peap_eap_tls` (Boolean) Allow PEAP EAP TLS
- `peap_allow_peap_eap_tls_auth_of_expired_certs` (Boolean) Allow PEAP EAP TLS authentication of expired certificates. Is required only if `peap_allow_peap_eap_tls` is `true`.
- `peap_peap_v0` (Boolean) Allow PEAP v0
- `preferred_eap_protocol` (String) Preferred EAP protocol
- `process_host_lookup` (Boolean) Process host lookup
- `require_cryptobinding` (Boolean) Require cryptobinding
- `require_message_auth` (Boolean) Require message authentication
- `teap_downgrade_msk` (Boolean) Allow downgrade to MSK
- `teap_eap_accept_client_cert_during_tunnel_est` (Boolean) Accept client certificate during tunnel establishment
- `teap_eap_chaining` (Boolean) Allow EAP chaining
- `teap_eap_ms_chap_v2` (Boolean) Allow EAP MS CHAP v2
- `teap_eap_ms_chap_v2_pwd_change` (Boolean) Allow EAP MS CHAP v2 password change. Is required only if `teap_eap_ms_chap_v2` is `true`.
- `teap_eap_ms_chap_v2_pwd_change_retries` (Number) EAP MS CHAP v2 password change retries. Is required only if `teap_eap_ms_chap_v2` is `true`.
- `teap_eap_tls` (Boolean) Allow EAP TLS
- `teap_eap_tls_auth_of_expired_certs` (Boolean) Allow EAP TLS authentication of expired certs. Is required only if `teap_eap_tls` is `true`.
- `teap_request_basic_pwd_auth` (Boolean) Request basic password authentication
