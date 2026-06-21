package compliance.hipaa.s3_versioning_test

import rego.v1
import data.compliance.hipaa.s3_versioning

compliant := {
	"configuration": {"root_module": {"resources": [
		{"type": "aws_s3_bucket", "name": "uploads"},
		{
			"type": "aws_s3_bucket_versioning",
			"name": "uploads",
			"expressions": {"bucket": {"references": ["aws_s3_bucket.uploads"]}},
		},
	]}},
	"planned_values": {"root_module": {"resources": [{
		"address": "aws_s3_bucket_versioning.uploads",
		"values": {"versioning_configuration": {"status": "Enabled"}},
	}]}},
}

noncompliant := {
	"configuration": {"root_module": {"resources": [
		{"type": "aws_s3_bucket", "name": "uploads"},
	]}},
	"planned_values": {"root_module": {"resources": []}},
}

test_compliant_passes if {
	count(s3_versioning.deny) == 0 with input as compliant
}

test_noncompliant_fails if {
	some msg in s3_versioning.deny with input as noncompliant
	contains(msg, "164.308(a)(7)")
	contains(msg, "GAP-04")
}
