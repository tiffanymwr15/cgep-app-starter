# METADATA
# title: HIPAA — S3 TLS-only access
# description: "Uploads bucket must deny requests not using HTTPS (GAP-03)."
# custom:
#   framework: hipaa
#   controls:
#     - "164.312(e)(1)"
#   gap: GAP-03
#   severity: high
#   remediation: "Add aws_s3_bucket_policy with a Deny on s3:* when aws:SecureTransport is false."
package compliance.hipaa.s3_tls

import rego.v1

deny contains msg if {
	bucket := phi_upload_buckets[_]
	not has_secure_transport_deny(bucket)
	msg := sprintf(
		"[164.312(e)(1)] %s: uploads bucket must deny non-TLS requests via aws:SecureTransport (GAP-03).",
		[bucket],
	)
}

phi_upload_buckets contains addr if {
	some r in input.configuration.root_module.resources
	r.type == "aws_s3_bucket"
	r.name == "uploads"
	addr := sprintf("aws_s3_bucket.%s", [r.name])
}

has_secure_transport_deny(bucket_addr) if {
	some r in input.configuration.root_module.resources
	r.type == "aws_s3_bucket_policy"
	some ref in r.expressions.bucket.references
	references_bucket(ref, bucket_addr)
	addr := sprintf("aws_s3_bucket_policy.%s", [r.name])
	policy_denies_insecure_transport(addr)
}

policy_denies_insecure_transport(addr) if {
	some r in input.planned_values.root_module.resources
	r.address == addr
	policy := json.unmarshal(r.values.policy)
	some stmt in policy.Statement
	stmt.Effect == "Deny"
	stmt.Condition.Bool["aws:SecureTransport"] == "false"
}

references_bucket(ref, bucket_addr) if ref == bucket_addr
references_bucket(ref, bucket_addr) if ref == sprintf("%s.id", [bucket_addr])
