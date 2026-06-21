#!/usr/bin/env bash
# Verify chain of custody for a pipeline evidence bundle in the vault.
# Usage: verify-evidence.sh <run_id> [--vault <bucket>] [--profile <p>]

set -euo pipefail

RUN_ID="${1:?usage: verify-evidence.sh <run_id> [--vault <bucket>] [--profile <p>]}"
shift || true

VAULT="${EVIDENCE_VAULT:-}"
PROFILE_ARG=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --vault)   VAULT="$2"; shift 2 ;;
    --profile) PROFILE_ARG="--profile $2"; shift 2 ;;
    *) echo "Unknown arg: $1" >&2; exit 2 ;;
  esac
done

[[ -z "$VAULT" ]] && {
  echo "Set --vault or EVIDENCE_VAULT" >&2
  exit 2
}

if command -v sha256sum >/dev/null 2>&1; then
  SHASUM="sha256sum"
elif command -v shasum >/dev/null 2>&1; then
  SHASUM="shasum -a 256"
else
  echo "Need sha256sum or shasum" >&2
  exit 2
fi

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"

PREFIX="runs/${RUN_ID}"

echo "=== Download from s3://${VAULT}/${PREFIX}/ ==="
aws $PROFILE_ARG s3 cp "s3://${VAULT}/${PREFIX}/" . --recursive \
  --exclude "*" --include "evidence-*.tar.gz" --include "evidence-*.tar.gz.*" --include "receipt.json"

BUNDLE=$(ls evidence-*.tar.gz 2>/dev/null | head -1 || true)
[[ -z "$BUNDLE" ]] && { echo "FAIL: no evidence-*.tar.gz found for run ${RUN_ID}"; exit 1; }

echo "=== 1. Integrity (SHA-256) ==="
EXPECTED=$(cat "${BUNDLE}.sha256")
ACTUAL=$($SHASUM "$BUNDLE" | awk '{print $1}')
[[ "$EXPECTED" == "$ACTUAL" ]] || { echo "FAIL: SHA mismatch"; exit 1; }
echo "  OK (${ACTUAL})"

echo "=== 2. Authenticity + timestamp (Cosign + Sigstore Rekor) ==="
cosign verify-blob \
  --bundle "${BUNDLE}.sig.bundle" \
  --certificate-identity-regexp '.*' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  "$BUNDLE"
echo "  OK (Cosign verified, Rekor entry exists)"

echo "=== 3. Preservation (Object Lock retention) ==="
RETAIN_UNTIL=$(aws $PROFILE_ARG s3api get-object-retention \
  --bucket "${VAULT}" --key "${PREFIX}/${BUNDLE}" \
  --query 'Retention.RetainUntilDate' --output text)
NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)
[[ "$RETAIN_UNTIL" > "$NOW" ]] || { echo "FAIL: retention expired (${RETAIN_UNTIL})"; exit 1; }
echo "  OK (retain until ${RETAIN_UNTIL})"

echo "CHAIN INTACT for run ${RUN_ID}"
