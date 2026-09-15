terraform {
  required_version = ">= 1.11.0"

  required_providers {
    ise = {
      source = "CiscoDevNet/ise"
    }
  }
}

provider "ise" {
  // By default uses env $ISE_USERNAME $ISE_PASSWORD $ISE_URL
}
