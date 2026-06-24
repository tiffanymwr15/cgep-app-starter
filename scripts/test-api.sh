#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROFILE="${1:-${AWS_PROFILE:-default}}"

cd "$ROOT/terraform"
eval "$(aws configure export-credentials --profile "$PROFILE" --format env)"

API_URL="$(terraform output -raw api_url)"
echo "POST $API_URL"
curl -sS -X POST "$API_URL" \
  -H 'content-type: application/json' \
  -d '{"patient_id":"P-0001","fields":{"reason":"smoke-test"}}' \
  | python3 -m json.tool
