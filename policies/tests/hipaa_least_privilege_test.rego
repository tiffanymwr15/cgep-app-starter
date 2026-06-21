package compliance.hipaa.least_privilege_test

import rego.v1
import data.compliance.hipaa.least_privilege

scoped_policy := json.marshal({
	"Version": "2012-10-17",
	"Statement": [
		{"Effect": "Allow", "Action": ["dynamodb:PutItem"], "Resource": "*"},
		{"Effect": "Allow", "Action": ["s3:PutObject"], "Resource": "*"},
	],
})

wildcard_policy := json.marshal({
	"Version": "2012-10-17",
	"Statement": [
		{"Effect": "Allow", "Action": "dynamodb:*", "Resource": "*"},
		{"Effect": "Allow", "Action": "s3:*", "Resource": "*"},
	],
})

compliant := {
	"configuration": {"root_module": {"resources": [
		{"type": "aws_iam_role_policy", "name": "lambda_inline"},
	]}},
	"planned_values": {"root_module": {"resources": [{
		"address": "aws_iam_role_policy.lambda_inline",
		"values": {"policy": scoped_policy},
	}]}},
}

noncompliant_ddb := {
	"configuration": {"root_module": {"resources": [
		{"type": "aws_iam_role_policy", "name": "lambda_inline"},
	]}},
	"planned_values": {"root_module": {"resources": [{
		"address": "aws_iam_role_policy.lambda_inline",
		"values": {"policy": wildcard_policy},
	}]}},
}

test_compliant_passes if {
	count(least_privilege.deny) == 0 with input as compliant
}

test_noncompliant_ddb_wildcard_fails if {
	some msg in least_privilege.deny with input as noncompliant_ddb
	contains(msg, "164.312(a)(1)")
	contains(msg, "dynamodb:*")
}

test_noncompliant_s3_wildcard_fails if {
	some msg in least_privilege.deny with input as noncompliant_ddb
	contains(msg, "s3:*")
}
