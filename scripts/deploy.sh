#!/usr/bin/env bash
# Deploy capstone stack without GNU make (Windows-friendly).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROFILE="${1:-${AWS_PROFILE:-default}}"

cd "$ROOT"

echo "Using AWS profile: $PROFILE"
eval "$(aws configure export-credentials --profile "$PROFILE" --format env)"
aws sts get-caller-identity

cd terraform
terraform init -input=false
terraform apply -auto-approve

echo ""
echo "Deploy complete. Smoke test:"
echo "  bash scripts/test-api.sh $PROFILE"
