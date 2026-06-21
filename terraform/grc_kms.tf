######################################################################
# Layer 1 — Customer-managed KMS key (CMK)
#
# HIPAA 164.312(a)(2)(iv): PHI at rest must use encryption you control.
# The starter's S3 bucket and DynamoDB table use AWS-owned keys (GAP-01/02).
# This CMK is the single encryption root for the GRC baseline.
######################################################################

data "aws_caller_identity" "current" {}

resource "aws_kms_key" "phi" {
  description             = "Acme Health PHI customer-managed key"
  enable_key_rotation     = true
  deletion_window_in_days = 30

  # Key policy needs two principals:
  # 1. Account root — lets IAM policies in this account grant kms:Decrypt etc.
  # 2. Current caller — AWS requires the identity running terraform apply to
  #    retain PutKeyPolicy, or CreateKey fails with MalformedPolicyDocument.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EnableRootAccountAdmin"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "AllowTerraformCallerKeyAdmin"
        Effect = "Allow"
        Principal = {
          AWS = data.aws_caller_identity.current.arn
        }
        Action = [
          "kms:Create*",
          "kms:Describe*",
          "kms:Enable*",
          "kms:Disable*",
          "kms:PutKeyPolicy",
          "kms:GetKeyPolicy",
          "kms:ScheduleKeyDeletion",
          "kms:CancelKeyDeletion",
          "kms:TagResource",
          "kms:UntagResource",
        ]
        Resource = "*"
      },
      {
        Sid    = "AllowCloudTrailUse"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action = [
          "kms:GenerateDataKey*",
          "kms:DescribeKey",
        ]
        Resource = "*"
        Condition = {
          StringLike = {
            "kms:EncryptionContext:aws:cloudtrail:arn" = "arn:aws:cloudtrail:*:${data.aws_caller_identity.current.account_id}:trail/*"
          }
        }
      },
      {
        Sid    = "AllowS3Use"
        Effect = "Allow"
        Principal = {
          Service = "s3.amazonaws.com"
        }
        Action = [
          "kms:GenerateDataKey",
          "kms:Decrypt",
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "kms:CallerAccount" = data.aws_caller_identity.current.account_id
          }
        }
      },
      {
        Sid    = "AllowDynamoDBUse"
        Effect = "Allow"
        Principal = {
          Service = "dynamodb.amazonaws.com"
        }
        Action = [
          "kms:GenerateDataKey",
          "kms:Decrypt",
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "kms:CallerAccount" = data.aws_caller_identity.current.account_id
          }
        }
      },
    ]
  })

  tags = {
    Name    = "${local.name_prefix}-phi-cmk"
    Purpose = "phi-encryption"
  }
}

resource "aws_kms_alias" "phi" {
  name          = "alias/${local.name_prefix}-phi-${local.suffix}"
  target_key_id = aws_kms_key.phi.key_id
}
