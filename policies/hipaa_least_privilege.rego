# METADATA
# title: HIPAA — Lambda least privilege IAM
# description: "Lambda inline policy must not use dynamodb:* or s3:* wildcards (GAP-07)."
# custom:
#   framework: hipaa
#   controls:
#     - "164.312(a)(1)"
#   gap: GAP-07
#   severity: critical
#   remediation: "Replace dynamodb:* and s3:* with scoped actions (PutItem, GetItem, PutObject, etc.) on specific resources."
package compliance.hipaa.least_privilege

import rego.v1

deny contains msg if {
	addr := lambda_inline_policies[_]
	wildcard_action(addr, "dynamodb:*")
	msg := sprintf(
		"[164.312(a)(1)] %s: IAM policy must not grant wildcard dynamodb:* on workload resources (GAP-07). Use least-privilege actions.",
		[addr],
	)
}

deny contains msg if {
	addr := lambda_inline_policies[_]
	wildcard_action(addr, "s3:*")
	msg := sprintf(
		"[164.312(a)(1)] %s: IAM policy must not grant wildcard s3:* on workload resources (GAP-07). Use least-privilege actions.",
		[addr],
	)
}

lambda_inline_policies contains addr if {
	some r in input.configuration.root_module.resources
	r.type == "aws_iam_role_policy"
	r.name == "lambda_inline"
	addr := sprintf("aws_iam_role_policy.%s", [r.name])
}

wildcard_action(addr, action) if {
	some r in input.planned_values.root_module.resources
	r.address == addr
	policy := json.unmarshal(r.values.policy)
	some stmt in policy.Statement
	is_string(stmt.Action)
	stmt.Action == action
}

wildcard_action(addr, action) if {
	some r in input.planned_values.root_module.resources
	r.address == addr
	policy := json.unmarshal(r.values.policy)
	some stmt in policy.Statement
	some a in stmt.Action
	a == action
}
