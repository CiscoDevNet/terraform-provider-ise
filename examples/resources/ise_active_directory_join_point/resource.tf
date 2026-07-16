resource "ise_active_directory_join_point" "example" {
  name                       = "cisco.local"
  description                = "My AD join point"
  domain                     = "cisco.local"
  ad_scopes_names            = "Default_Scope"
  enable_domain_allowed_list = true
  groups = [
    {
      name = "cisco.local/operators"
      sid  = "S-1-5-32-548"
      type = "GLOBAL"
    }
  ]
  attributes = [
    {
      name          = "Attribute_1"
      type          = "STRING"
      internal_name = "internal_name"
      default_value = "default_string"
    }
  ]
  rewrite_rules = [
    {
      row_id         = "0"
      rewrite_match  = "rewrite_match"
      rewrite_result = "rewrite_result"
    }
  ]
  enable_rewrites                   = false
  enable_pass_change                = true
  enable_machine_auth               = true
  enable_machine_access             = true
  enable_dialin_permission_check    = false
  plaintext_auth                    = false
  aging_time                        = 5
  enable_callback_for_dialin_client = false
  identity_not_in_ad_behaviour      = "SEARCH_JOINED_FOREST"
  unreachable_domains_behaviour     = "PROCEED"
  schema                            = "ACTIVE_DIRECTORY"
  first_name                        = "givenName"
  department                        = "department"
  last_name                         = "sn"
  organizational_unit               = "company"
  job_title                         = "title"
  locality                          = "l"
  email                             = "mail"
  state_or_province                 = "st"
  telephone                         = "telephoneNumber"
  country                           = "co"
  street_address                    = "streetAddress"
  enable_failed_auth_protection     = false
  failed_auth_threshold             = 5
  auth_protection_type              = "WIRELESS"
}
