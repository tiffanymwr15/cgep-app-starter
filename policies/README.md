# HIPAA Rego Policy Suite (Phase 2)

Primary framework: **HIPAA Security Rule**. Each policy maps to a starter gap from [GAPS.md](../GAPS.md) and cites the HIPAA control ID in deny messages.

## Policies

| File | Package (Conftest namespace) | Gap | HIPAA control |
|---|---|---|---|
| `hipaa_s3_kms.rego` | `compliance.hipaa.s3_kms` | GAP-01 | 164.312(a)(2)(iv) |
| `hipaa_dynamodb_kms.rego` | `compliance.hipaa.dynamodb_kms` | GAP-02 | 164.312(a)(2)(iv) |
| `hipaa_s3_tls.rego` | `compliance.hipaa.s3_tls` | GAP-03 | 164.312(e)(1) |
| `hipaa_s3_versioning.rego` | `compliance.hipaa.s3_versioning` | GAP-04 | 164.308(a)(7) |
| `hipaa_lambda_vpc.rego` | `compliance.hipaa.lambda_vpc` | GAP-05 | 164.312(e)(1) |
| `hipaa_least_privilege.rego` | `compliance.hipaa.least_privilege` | GAP-07 | 164.312(a)(1) |

Uploads-bucket policies scope to `aws_s3_bucket.uploads` (the starter PHI bucket). Lambda and IAM policies scope to `intake` / `lambda_inline`.

## Local commands

```bash
# Unit tests (pass + fail fixtures)
opa test ./policies -v

# Conftest against a saved Terraform plan
cd terraform
terraform plan -out=tfplan
terraform show -json tfplan > plan.json
conftest test --policy ../policies --namespace compliance.hipaa.s3_kms plan.json
# repeat for each namespace, or use scripts/policy-gate.sh
```

## How policies read Terraform

Conftest passes Terraform **plan JSON** as `input`. AWS policies use two sections:

- `input.configuration.root_module.resources` — what Terraform declares (types, names, references)
- `input.planned_values.root_module.resources` — resolved values after planning (encryption algorithm, policy JSON, vpc_config)

A deny rule typically: find starter resources in `configuration`, verify remediations in `planned_values`.

## Red PR demo (Phase 3)

Re-introduce one gap (e.g. remove SSE-KMS from uploads) on a branch. Conftest must fail closed with the HIPAA control ID in the message.
