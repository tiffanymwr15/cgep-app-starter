# METADATA
# title: HIPAA — S3 versioning on PHI uploads
# description: "Uploads bucket must have versioning enabled for overwrite recovery (GAP-04)."
# custom:
#   framework: hipaa
#   controls:
#     - "164.308(a)(7)"
#   gap: GAP-04
#   severity: medium
#   remediation: "Add aws_s3_bucket_versioning with status = Enabled for the uploads bucket."
package compliance.hipaa.s3_versioning

import rego.v1

deny contains msg if {
	bucket := phi_upload_buckets[_]
	not has_versioning(bucket)
	msg := sprintf(
		"[164.308(a)(7)] %s: uploads bucket must have versioning enabled (GAP-04).",
		[bucket],
	)
}

phi_upload_buckets contains addr if {
	some r in input.configuration.root_module.resources
	r.type == "aws_s3_bucket"
	r.name == "uploads"
	addr := sprintf("aws_s3_bucket.%s", [r.name])
}

has_versioning(bucket_addr) if {
	some r in input.configuration.root_module.resources
	r.type == "aws_s3_bucket_versioning"
	some ref in r.expressions.bucket.references
	references_bucket(ref, bucket_addr)
	addr := sprintf("aws_s3_bucket_versioning.%s", [r.name])
	versioning_enabled(addr)
}

versioning_enabled(addr) if {
	some r in input.planned_values.root_module.resources
	r.address == addr
	is_array(r.values.versioning_configuration)
	some vc in r.values.versioning_configuration
	vc.status == "Enabled"
}

versioning_enabled(addr) if {
	some r in input.planned_values.root_module.resources
	r.address == addr
	not is_array(r.values.versioning_configuration)
	r.values.versioning_configuration.status == "Enabled"
}

references_bucket(ref, bucket_addr) if ref == bucket_addr
references_bucket(ref, bucket_addr) if ref == sprintf("%s.id", [bucket_addr])
