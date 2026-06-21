# METADATA
# title: HIPAA — DynamoDB CMK encryption
# description: "Submissions table must use a customer-managed KMS key (GAP-02)."
# custom:
#   framework: hipaa
#   controls:
#     - "164.312(a)(2)(iv)"
#   gap: GAP-02
#   severity: high
#   remediation: "Add server_side_encryption { enabled = true kms_key_arn = <your CMK> } to aws_dynamodb_table.intake."
package compliance.hipaa.dynamodb_kms

import rego.v1

deny contains msg if {
	addr := dynamodb_table_addresses[_]
	not has_cmk_encryption(addr)
	msg := sprintf(
		"[164.312(a)(2)(iv)] %s: DynamoDB table must use server_side_encryption with a customer KMS key (GAP-02).",
		[addr],
	)
}

dynamodb_table_addresses contains addr if {
	some r in input.configuration.root_module.resources
	r.type == "aws_dynamodb_table"
	addr := sprintf("aws_dynamodb_table.%s", [r.name])
}

has_cmk_encryption(addr) if {
	some r in input.planned_values.root_module.resources
	r.address == addr
	is_array(r.values.server_side_encryption)
	some sse in r.values.server_side_encryption
	sse.enabled == true
	sse.kms_key_arn != ""
}

has_cmk_encryption(addr) if {
	some r in input.planned_values.root_module.resources
	r.address == addr
	not is_array(r.values.server_side_encryption)
	r.values.server_side_encryption.enabled == true
	r.values.server_side_encryption.kms_key_arn != ""
}
