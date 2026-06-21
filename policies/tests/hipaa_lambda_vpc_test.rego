package compliance.hipaa.lambda_vpc_test

import rego.v1
import data.compliance.hipaa.lambda_vpc

compliant := {
	"configuration": {"root_module": {"resources": [
		{"type": "aws_lambda_function", "name": "intake"},
	]}},
	"planned_values": {"root_module": {"resources": [{
		"address": "aws_lambda_function.intake",
		"values": {"vpc_config": [{
			"subnet_ids": ["subnet-abc"],
			"security_group_ids": ["sg-123"],
		}]},
	}]}},
}

noncompliant := {
	"configuration": {"root_module": {"resources": [
		{"type": "aws_lambda_function", "name": "intake"},
	]}},
	"planned_values": {"root_module": {"resources": [{
		"address": "aws_lambda_function.intake",
		"values": {},
	}]}},
}

test_compliant_passes if {
	count(lambda_vpc.deny) == 0 with input as compliant
}

test_noncompliant_fails if {
	some msg in lambda_vpc.deny with input as noncompliant
	contains(msg, "164.312(e)(1)")
	contains(msg, "GAP-05")
}
