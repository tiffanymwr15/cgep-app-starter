######################################################################
# Outputs for GRC baseline resources (Layer 1).
# Starter outputs stay in outputs.tf; GRC outputs live here.
######################################################################

output "phi_kms_key_arn" {
  value       = aws_kms_key.phi.arn
  description = "Customer-managed KMS key for PHI encryption (S3, DynamoDB, vault)."
}

output "phi_kms_key_alias" {
  value       = aws_kms_alias.phi.name
  description = "Human-readable alias for the PHI CMK."
}

output "evidence_vault_name" {
  value       = aws_s3_bucket.evidence_vault.id
  description = "S3 bucket for signed pipeline evidence bundles (Object Lock enabled)."
}

output "evidence_vault_arn" {
  value       = aws_s3_bucket.evidence_vault.arn
  description = "ARN of the evidence vault bucket."
}

output "cloudtrail_name" {
  value       = aws_cloudtrail.mgmt.name
  description = "Multi-region management CloudTrail for HIPAA audit controls."
}

output "cloudtrail_bucket" {
  value       = aws_s3_bucket.cloudtrail.id
  description = "S3 bucket receiving CloudTrail log files."
}

output "security_alerts_topic_arn" {
  value       = aws_sns_topic.security_alerts.arn
  description = "SNS topic for HIPAA drift detection alerts (DET-01 through DET-04)."
}

output "detector_lambda_name" {
  value       = aws_lambda_function.detector.function_name
  description = "CloudTrail drift detector Lambda (classify, dedup, route)."
}

output "detection_rule_names" {
  value       = [for rule in aws_cloudwatch_event_rule.detection : rule.name]
  description = "EventBridge rules feeding the detector Lambda."
}
