######################################################################
# Variables for GRC baseline (Layer 1).
######################################################################

variable "evidence_lock_mode" {
  type        = string
  description = "COMPLIANCE for strict immutability (HIPAA audit evidence). GOVERNANCE allows bypass with special permission."
  default     = "COMPLIANCE"

  validation {
    condition     = contains(["GOVERNANCE", "COMPLIANCE"], var.evidence_lock_mode)
    error_message = "evidence_lock_mode must be GOVERNANCE or COMPLIANCE."
  }
}

variable "evidence_retention_days" {
  type        = number
  description = "Default Object Lock retention for every object in the evidence vault."
  default     = 30
}

variable "security_alert_email" {
  type        = string
  description = "Email endpoint for HIPAA drift alerts (SNS). Leave empty to create the topic without a subscription."
  default     = ""
  sensitive   = true
}

variable "alert_dedup_ttl_seconds" {
  type        = number
  description = "Suppress duplicate CloudTrail event IDs for this many seconds (noise reduction)."
  default     = 3600

  validation {
    condition     = var.alert_dedup_ttl_seconds >= 300 && var.alert_dedup_ttl_seconds <= 86400
    error_message = "alert_dedup_ttl_seconds must be between 300 and 86400."
  }
}
