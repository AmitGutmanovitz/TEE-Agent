variable "name" {
  description = "App name on Phala Cloud"
  type        = string
  default     = "verifiable-agent"
}

variable "size" {
  description = "Instance type (tdx.small = 1 vCPU / 2 GB, enough per the load test)"
  type        = string
  default     = "tdx.small"
}

variable "region" {
  description = "Phala region, e.g. US-WEST-1. null lets Phala choose."
  type        = string
  default     = null
}

variable "disk_size" {
  description = "Disk in GB (billed while the CVM exists)"
  type        = number
  default     = 20
}

variable "power_state" {
  description = "running or stopped (set by deploy.ps1 start / stop)"
  type        = string
  default     = "running"
}

variable "extra_instances" {
  description = "Extra CVMs of the same app beyond the first (0 = one CVM). They share the app id and signing key."
  type        = number
  default     = 0
}

variable "phala_api_key" {
  description = "Phala Private AI key used by the agent for LLM calls"
  type        = string
  sensitive   = true
}

variable "openai_api_key" {
  description = "OpenAI key for LLM_BACKEND=openai (optional; empty if unused)"
  type        = string
  sensitive   = true
  default     = ""
}

variable "admin_token" {
  description = "Bearer token allowed to change the system prompt"
  type        = string
  sensitive   = true
}

variable "demo_token" {
  description = "Access code for the demo page (port 8080), shared with demo viewers"
  type        = string
  sensitive   = true
}

variable "chat_token" {
  description = "Bearer token allowed to chat and read proofs"
  type        = string
  sensitive   = true
}
