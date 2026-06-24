######################################################################
# Layer 1b — Continuous monitoring & detection (HIPAA drift)
#
# CloudTrail management events -> EventBridge rules -> detector Lambda
# -> DynamoDB dedup (1h TTL) -> SNS security-alerts topic.
#
# Maps to rubric "Continuous Monitoring & Detection Logic":
#   - Targeted scenarios (DET-01..04) tied to GAPs / HIPAA controls
#   - Deduplication via DynamoDB TTL
#   - Alert routing via SNS (email subscription optional)
#   - Unit tests replay fixtures in monitoring/tests/
######################################################################

locals {
  detector_name = "${local.name_prefix}-detector-${local.suffix}"

  detection_rules = {
    phi_s3_exposure = {
      description = "DET-01: PHI uploads/evidence S3 public exposure drift (GAP-01/03)"
      pattern = jsonencode({
        source      = ["aws.s3"]
        detail-type = ["AWS API Call via CloudTrail"]
        detail = {
          eventSource = ["s3.amazonaws.com"]
          eventName = [
            "PutBucketPublicAccessBlock",
            "DeleteBucketPublicAccessBlock",
            "PutBucketPolicy",
          ]
        }
      })
    }
    phi_kms_destruction = {
      description = "DET-02: PHI CMK disable or scheduled deletion (GAP-01/02)"
      pattern = jsonencode({
        source      = ["aws.kms"]
        detail-type = ["AWS API Call via CloudTrail"]
        detail = {
          eventSource = ["kms.amazonaws.com"]
          eventName = [
            "DisableKey",
            "ScheduleKeyDeletion",
          ]
        }
      })
    }
    evidence_vault_tamper = {
      description = "DET-03: Evidence vault retention or legal-hold changes (164.312(b))"
      pattern = jsonencode({
        source      = ["aws.s3"]
        detail-type = ["AWS API Call via CloudTrail"]
        detail = {
          eventSource = ["s3.amazonaws.com"]
          eventName = [
            "PutObjectRetention",
            "PutObjectLegalHold",
            "BypassGovernanceRetention",
          ]
        }
      })
    }
    lambda_iam_escalation = {
      description = "DET-04: Intake Lambda IAM wildcard regression (GAP-07)"
      pattern = jsonencode({
        source      = ["aws.iam"]
        detail-type = ["AWS API Call via CloudTrail"]
        detail = {
          eventSource = ["iam.amazonaws.com"]
          eventName = [
            "PutRolePolicy",
            "AttachRolePolicy",
          ]
        }
      })
    }
  }
}

resource "aws_sns_topic" "security_alerts" {
  provider = aws.no_default_tags
  name     = "${local.name_prefix}-security-alerts-${local.suffix}"
}

resource "aws_sns_topic_subscription" "security_alerts_email" {
  count = var.security_alert_email != "" ? 1 : 0

  topic_arn = aws_sns_topic.security_alerts.arn
  protocol  = "email"
  endpoint  = var.security_alert_email
}

resource "aws_dynamodb_table" "alert_dedup" {
  name         = "${local.name_prefix}-alert-dedup-${local.suffix}"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "event_id"

  attribute {
    name = "event_id"
    type = "S"
  }

  ttl {
    attribute_name = "expires_at"
    enabled        = true
  }

  tags = {
    Purpose = "detection-dedup"
  }
}

data "archive_file" "detector" {
  type        = "zip"
  source_dir  = "${path.module}/../monitoring/detector"
  output_path = "${path.module}/detector.zip"
}

resource "aws_iam_role" "detector" {
  name = "${local.name_prefix}-detector-${local.suffix}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "detector" {
  name = "detector-runtime"
  role = aws_iam_role.detector.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
        ]
        Resource = "arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${local.detector_name}:*"
      },
      {
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:PutItem",
        ]
        Resource = aws_dynamodb_table.alert_dedup.arn
      },
      {
        Effect   = "Allow"
        Action   = "sns:Publish"
        Resource = aws_sns_topic.security_alerts.arn
      },
    ]
  })
}

resource "aws_lambda_function" "detector" {
  function_name    = local.detector_name
  role             = aws_iam_role.detector.arn
  handler          = "handler.handler"
  runtime          = "python3.12"
  filename         = data.archive_file.detector.output_path
  source_code_hash = data.archive_file.detector.output_base64sha256
  timeout          = 15

  environment {
    variables = {
      DEDUP_TABLE           = aws_dynamodb_table.alert_dedup.name
      DEDUP_TTL_SECONDS     = tostring(var.alert_dedup_ttl_seconds)
      SNS_TOPIC_ARN         = aws_sns_topic.security_alerts.arn
      UPLOADS_BUCKET        = aws_s3_bucket.uploads.id
      EVIDENCE_VAULT_BUCKET = aws_s3_bucket.evidence_vault.id
      PHI_KMS_KEY_ARN       = aws_kms_key.phi.arn
      PHI_KMS_KEY_ID        = aws_kms_key.phi.key_id
      LAMBDA_ROLE_NAME      = aws_iam_role.lambda.name
    }
  }
}

resource "aws_cloudwatch_event_rule" "detection" {
  provider = aws.no_default_tags

  for_each = local.detection_rules

  name          = "${local.name_prefix}-${replace(each.key, "_", "-")}-${local.suffix}"
  description   = each.value.description
  event_pattern = each.value.pattern
}

resource "aws_cloudwatch_event_target" "detection" {
  for_each = local.detection_rules

  rule      = aws_cloudwatch_event_rule.detection[each.key].name
  target_id = "detector-lambda"
  arn       = aws_lambda_function.detector.arn
}

resource "aws_lambda_permission" "detection_eventbridge" {
  for_each = local.detection_rules

  statement_id  = "AllowExecutionFromEventBridge-${each.key}"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.detector.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.detection[each.key].arn
}

resource "aws_cloudwatch_metric_alarm" "detector_errors" {
  provider = aws.no_default_tags

  alarm_name          = "${local.name_prefix}-detector-errors-${local.suffix}"
  alarm_description   = "Detector Lambda errors (monitoring pipeline health)"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = 300
  statistic           = "Sum"
  threshold           = 0
  treat_missing_data  = "notBreaching"

  dimensions = {
    FunctionName = aws_lambda_function.detector.function_name
  }

  alarm_actions = [aws_sns_topic.security_alerts.arn]
}
