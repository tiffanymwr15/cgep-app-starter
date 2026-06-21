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
