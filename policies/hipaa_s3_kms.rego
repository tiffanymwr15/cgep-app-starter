# METADATA
# title: HIPAA — SSE-KMS on PHI S3 buckets
# description: "Workload uploads bucket must use SSE-KMS with a customer-managed key (GAP-01)."
# custom:
#   framework: hipaa
#   controls:
#     - "164.312(a)(2)(iv)"
#   gap: GAP-01
#   severity: high
#   remediation: "Add aws_s3_bucket_server_side_encryption_configuration with sse_algorithm = aws:kms and kms_master_key_id set."
package compliance.hipaa.s3_kms

import rego.v1

deny contains msg if {
	bucket := phi_upload_buckets[_]
	not has_kms_encryption(bucket)
	msg := sprintf(
		"[164.312(a)(2)(iv)] %s: uploads bucket must use SSE-KMS with a customer CMK (GAP-01). Add aws_s3_bucket_server_side_encryption_configuration with sse_algorithm = aws:kms.",
		[bucket],
	)
}

# GAP-01 targets the starter uploads bucket only (not CloudTrail / evidence vault buckets).
phi_upload_buckets contains addr if {
	some r in input.configuration.root_module.resources
	r.type == "aws_s3_bucket"
	r.name == "uploads"
	addr := sprintf("aws_s3_bucket.%s", [r.name])
}

has_kms_encryption(bucket_addr) if {
	enc := encryption_for(bucket_addr)
	enc.sse_algorithm == "aws:kms"
	enc.kms_master_key_id != ""
}

encryption_for(bucket_addr) := cfg if {
	some r in input.configuration.root_module.resources
	r.type == "aws_s3_bucket_server_side_encryption_configuration"
	some ref in r.expressions.bucket.references
	references_bucket(ref, bucket_addr)
	addr := sprintf("aws_s3_bucket_server_side_encryption_configuration.%s", [r.name])
	cfg := encryption_planned_values(addr)
}

encryption_planned_values(addr) := cfg if {
	some r in input.planned_values.root_module.resources
	r.address == addr
	some rule in r.values.rule
	is_array(rule.apply_server_side_encryption_by_default)
	some sse in rule.apply_server_side_encryption_by_default
	cfg := {
		"sse_algorithm": sse.sse_algorithm,
		"kms_master_key_id": object.get(sse, "kms_master_key_id", ""),
	}
}

encryption_planned_values(addr) := cfg if {
	some r in input.planned_values.root_module.resources
	r.address == addr
	some rule in r.values.rule
	not is_array(rule.apply_server_side_encryption_by_default)
	sse := rule.apply_server_side_encryption_by_default
	cfg := {
		"sse_algorithm": sse.sse_algorithm,
		"kms_master_key_id": object.get(sse, "kms_master_key_id", ""),
	}
}

references_bucket(ref, bucket_addr) if ref == bucket_addr
references_bucket(ref, bucket_addr) if ref == sprintf("%s.id", [bucket_addr])
