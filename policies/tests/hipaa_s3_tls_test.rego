package compliance.hipaa.s3_tls_test

import rego.v1
import data.compliance.hipaa.s3_tls

tls_policy := json.marshal({
	"Version": "2012-10-17",
	"Statement": [{
		"Sid": "DenyInsecureTransport",
		"Effect": "Deny",
		"Principal": "*",
		"Action": "s3:*",
		"Resource": ["arn:aws:s3:::bucket", "arn:aws:s3:::bucket/*"],
		"Condition": {"Bool": {"aws:SecureTransport": "false"}},
	}],
})

compliant := {
	"configuration": {"root_module": {"resources": [
		{"type": "aws_s3_bucket", "name": "uploads"},
		{
			"type": "aws_s3_bucket_policy",
			"name": "uploads",
			"expressions": {"bucket": {"references": ["aws_s3_bucket.uploads"]}},
		},
	]}},
	"planned_values": {"root_module": {"resources": [{
		"address": "aws_s3_bucket_policy.uploads",
		"values": {"policy": tls_policy},
	}]}},
}

noncompliant := {
	"configuration": {"root_module": {"resources": [
		{"type": "aws_s3_bucket", "name": "uploads"},
	]}},
	"planned_values": {"root_module": {"resources": []}},
}

test_compliant_passes if {
	count(s3_tls.deny) == 0 with input as compliant
}

test_noncompliant_fails if {
	some msg in s3_tls.deny with input as noncompliant
	contains(msg, "164.312(e)(1)")
	contains(msg, "GAP-03")
}
