package compliance.hipaa.dynamodb_kms_test

import rego.v1
import data.compliance.hipaa.dynamodb_kms

compliant := {
	"configuration": {"root_module": {"resources": [
		{"type": "aws_dynamodb_table", "name": "intake"},
	]}},
	"planned_values": {"root_module": {"resources": [{
		"address": "aws_dynamodb_table.intake",
		"values": {"server_side_encryption": {
			"enabled": true,
			"kms_key_arn": "arn:aws:kms:us-east-1:123:key/abc",
		}},
	}]}},
}

noncompliant := {
	"configuration": {"root_module": {"resources": [
		{"type": "aws_dynamodb_table", "name": "intake"},
	]}},
	"planned_values": {"root_module": {"resources": [{
		"address": "aws_dynamodb_table.intake",
		"values": {},
	}]}},
}

test_compliant_passes if {
	count(dynamodb_kms.deny) == 0 with input as compliant
}

test_noncompliant_fails if {
	some msg in dynamodb_kms.deny with input as noncompliant
	contains(msg, "164.312(a)(2)(iv)")
	contains(msg, "GAP-02")
}
