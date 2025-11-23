terraform {
  required_version = ">= 1.6.0"
  required_providers {
    null = {
      source  = "hashicorp/null"
      version = "3.2.2"
    }
  }
}

provider "null" {}

resource "null_resource" "vps" {
  provisioner "local-exec" {
    command = "echo 'Use GUI vpr Studio for provisioning.'"
  }
}
