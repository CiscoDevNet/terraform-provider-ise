resource "ise_user_identity_group" "example" {
  name = "Group1"
  description = "My endpoint identity group"
  parent = "NAC Group:NAC:IdentityGroups:User Identity Groups"
}
