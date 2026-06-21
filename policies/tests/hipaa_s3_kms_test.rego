package compliance.hipaa.s3_kms_test

import rego.v1
import data.compliance.hipaa.s3_kms

compliant := {
	"configuration": {"root_module": {"resources": [
		{"type": "aws_s3_bucket", "name": "uploads"},
		{
			"type": "aws_s3_bucket_server_side_encryption_configuration",
			"name": "uploads",
			"expressions": {"bucket": {"references": ["aws_s3_bucket.uploads"]}},
		},
	]}},
	"planned_values": {"root_module": {"resources": [{
		"address": "aws_s3_bucket_server_side_encryption_configuration.uploads",
		"values": {"rule": [{"apply_server_side_encryption_by_default": {
			"sse_algorithm": "aws:kms",
			"kms_master_key_id": "arn:aws:kms:us-east-1:123:key/abc",
		}}]},
	}]}},
}

noncompliant_aes := {
	"configuration": {"root_module": {"resources": [
		{"type": "aws_s3_bucket", "name": "uploads"},
		{
			"type": "aws_s3_bucket_server_side_encryption_configuration",
			"name": "uploads",
			"expressions": {"bucket": {"references": ["aws_s3_bucket.uploads"]}},
		},
	]}},
	"planned_values": {"root_module": {"resources": [{
		"address": "aws_s3_bucket_server_side_encryption_configuration.uploads",
		"values": {"rule": [{"apply_server_side_encryption_by_default": {"sse_algorithm": "AES256"}}]},
	}]}},
}

noncompliant_missing := {
	"configuration": {"root_module": {"resources": [
		{"type": "aws_s3_bucket", "name": "uploads"},
	]}},
	"planned_values": {"root_module": {"resources": []}},
}

test_compliant_passes if {
	count(s3_kms.deny) == 0 with input as compliant
}

test_noncompliant_aes_fails if {
	some msg in s3_kms.deny with input as noncompliant_aes
	contains(msg, "164.312(a)(2)(iv)")
	contains(msg, "GAP-01")
}

test_noncompliant_missing_fails if {
	some msg in s3_kms.deny with input as noncompliant_missing
	contains(msg, "164.312(a)(2)(iv)")
}
