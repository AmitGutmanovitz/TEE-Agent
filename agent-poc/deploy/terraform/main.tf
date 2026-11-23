# Verifiable agent on Phala Cloud CVMs.
#
#   $env:PHALA_CLOUD_API_KEY = "phak_..."   (or run ..\deploy.ps1, which loads it from agent-poc\.env)
#   terraform init
#   terraform apply
#   terraform destroy
#
# The compose file (../docker-compose.cvm.yml) is the single source of truth: it pins the agent image
# by digest, its hash is measured into each CVM's RTMR3, and verify.py --expect-compose checks it.

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    phala = {
      source  = "phala-network/phala"
      version = "0.3.0-beta.5" # beta provider: pin exactly (0.2.x is rejected by the current Phala API)
    }
  }
}

provider "phala" {} # reads PHALA_CLOUD_API_KEY from the environment

resource "phala_app" "agent" {
  name           = var.name
  size           = var.size
  region         = var.region
  disk_size      = var.disk_size
  docker_compose = file("${path.module}/../docker-compose.cvm.yml")

  # Encrypted by the provider before upload; only the CVM can decrypt them.
  # NOTE: plaintext values are kept in terraform.tfstate. Keep state local and git-ignored
  # (or use an encrypted remote backend).
  env = {
    PHALA_API_KEY   = var.phala_api_key
    OPEN_AI_API_KEY = var.openai_api_key
    ADMIN_TOKEN   = var.admin_token
    CHAT_TOKEN    = var.chat_token
    DEMO_TOKEN    = var.demo_token
  }

  # Publish what verifiers need: logs, system info and the TCB info (incl. app_compose).
  public_logs    = true
  public_sysinfo = true
  public_tcbinfo = true

  wait_for_ready       = true
  wait_timeout_seconds = 900
}

# Power: `deploy.ps1 stop` sets this to "stopped" (compute billing stops; disk is still billed),
# `deploy.ps1 start` / `apply` set it back to "running".
resource "phala_cvm_power" "agent" {
  cvm_id               = phala_app.agent.primary_cvm_id
  state                = var.power_state
  wait_for_state       = true
  wait_timeout_seconds = 900
}

# Scaling: more CVMs of the same app (same app_id => same compose, same KMS-derived signing key).
# Each extra instance is its own CVM and is billed separately. (Not exercised yet in this POC.)
resource "phala_app_instance" "extra" {
  count                = var.extra_instances
  app_id               = phala_app.agent.app_id
  name                 = "agent-${count.index + 2}"
  wait_for_ready       = true
  wait_timeout_seconds = 900
}
