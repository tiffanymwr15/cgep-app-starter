# METADATA
# title: HIPAA — Lambda VPC boundary
# description: "Intake Lambda must run inside the starter VPC private subnets (GAP-05)."
# custom:
#   framework: hipaa
#   controls:
#     - "164.312(e)(1)"
#   gap: GAP-05
#   severity: high
#   remediation: "Add vpc_config { subnet_ids = aws_subnet.private[*].id security_group_ids = [...] } to aws_lambda_function.intake."
package compliance.hipaa.lambda_vpc

import rego.v1

deny contains msg if {
	addr := intake_lambda_addresses[_]
	not has_vpc_config(addr)
	msg := sprintf(
		"[164.312(e)(1)] %s: intake Lambda must include vpc_config in private subnets (GAP-05).",
		[addr],
	)
}

intake_lambda_addresses contains addr if {
	some r in input.configuration.root_module.resources
	r.type == "aws_lambda_function"
	r.name == "intake"
	addr := sprintf("aws_lambda_function.%s", [r.name])
}

has_vpc_config(addr) if {
	some r in input.planned_values.root_module.resources
	r.address == addr
	count(r.values.vpc_config) > 0
	count(r.values.vpc_config[0].subnet_ids) > 0
	count(r.values.vpc_config[0].security_group_ids) > 0
}
