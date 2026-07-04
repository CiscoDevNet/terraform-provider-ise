resource "ise_tacacs_command_set" "example" {
  name = "CommandSet1"
  description = "My TACACS command set"
  permit_unmatched = true
  commands = [
    {
      grant = "PERMIT"
      command = "show"
      arguments = ""
    }
  ]
}
