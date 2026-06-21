######################################################################
# Layer 1 — Evidence vault (S3 Object Lock)
#
# Every pipeline run uploads a signed bundle here. Object Lock +
# versioning make objects tamper-evident and non-deletable until
# retention expires. Encrypted with the PHI CMK from grc_kms.tf.
#
# Adapted from Lab 2.5; capstone upgrades: SSE-KMS + COMPLIANCE Object Lock (see WRITEUP.md).
######################################################################

locals {
  evidence_vault_name = "${local.name_prefix}-grc-evidence-vault-${local.suffix}"
}

resource "aws_s3_bucket" "evidence_vault" {
  bucket              = local.evidence_vault_name
  object_lock_enabled = true # must be set at creation; cannot be added later
}

resource "aws_s3_bucket_versioning" "evidence_vault" {
  bucket = aws_s3_bucket.evidence_vault.id

  versioning_configuration {
    status = "Enabled" # required for Object Lock
  }
}

resource "aws_s3_bucket_object_lock_configuration" "evidence_vault" {
  bucket = aws_s3_bucket.evidence_vault.id

  rule {
    default_retention {
      mode = var.evidence_lock_mode
      days = var.evidence_retention_days
    }
  }

  depends_on = [aws_s3_bucket_versioning.evidence_vault]
}

resource "aws_s3_bucket_server_side_encryption_configuration" "evidence_vault" {
  bucket = aws_s3_bucket.evidence_vault.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.phi.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "evidence_vault" {
  bucket = aws_s3_bucket.evidence_vault.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Deny bucket deletion for everyone except account root (Lab 2.5 pattern).
resource "aws_s3_bucket_policy" "evidence_vault" {
  bucket = aws_s3_bucket.evidence_vault.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyBucketDeletion"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:DeleteBucket"
        Resource  = aws_s3_bucket.evidence_vault.arn
        Condition = {
          StringNotEquals = {
            "aws:PrincipalArn" = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
          }
        }
      },
    ]
  })
}
