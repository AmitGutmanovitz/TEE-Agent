output "app_id" {
  value = phala_app.agent.app_id
}

output "endpoint" {
  description = "Primary public URL of the app"
  value       = phala_app.agent.endpoint
}

output "demo_url" {
  description = "Demo page; share it with '#code=<DEMO_TOKEN>' appended"
  value       = "https://${trimprefix(phala_app.agent.app_id, "app_")}-8080.${phala_app.agent.gateway_base_domain}/"
}

output "compose_hash" {
  description = "Must equal the compose-hash measured in the agent's RTMR3 (checked by verify.py)"
  value       = phala_app.agent.compose_hash
}

output "gateway_base_domain" {
  value = phala_app.agent.gateway_base_domain
}

output "extra_instance_endpoints" {
  value = phala_app_instance.extra[*].endpoint
}

output "cvm_ids" {
  value = phala_app.agent.cvm_ids
}

output "status" {
  value = phala_app.agent.status
}
