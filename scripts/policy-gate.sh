#!/usr/bin/env bash
# Run Conftest against all HIPAA policy namespaces.
set -euo pipefail

POLICY_DIR="${POLICY_DIR:-policies}"
PLAN="${1:-terraform/plan.json}"
EVIDENCE_DIR="${EVIDENCE_DIR:-evidence}"

if [[ ! -f "$PLAN" ]]; then
  echo "Usage: $0 [path/to/plan.json]" >&2
  echo "Generate plan.json first: terraform plan -out=tfplan && terraform show -json tfplan > plan.json" >&2
  exit 2
fi

mkdir -p "$EVIDENCE_DIR"

NAMESPACES=(
  compliance.hipaa.s3_kms
  compliance.hipaa.dynamodb_kms
  compliance.hipaa.s3_tls
  compliance.hipaa.s3_versioning
  compliance.hipaa.lambda_vpc
  compliance.hipaa.least_privilege
)

EXIT=0
{
  echo "["
  FIRST=1
  for ns in "${NAMESPACES[@]}"; do
    [[ $FIRST -eq 1 ]] && FIRST=0 || printf ","
    conftest test --policy "$POLICY_DIR" --namespace "$ns" --output=json "$PLAN" || true
  done
  echo "]"
} > "$EVIDENCE_DIR/conftest-results.json"

python3 -c "
import json, sys
d = json.load(open('$EVIDENCE_DIR/conftest-results.json'))
fails = sum(len(r.get('failures') or []) for results in d for r in results)
print(f'conftest failures: {fails}')
sys.exit(0 if fails == 0 else 1)
" || EXIT=1

if [[ $EXIT -eq 0 ]]; then
  echo "policy-gate: PASS"
else
  echo "policy-gate: FAIL (see $EVIDENCE_DIR/conftest-results.json)"
fi
exit $EXIT
