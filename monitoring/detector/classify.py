"""Classify CloudTrail management events into HIPAA-scoped security alerts."""

from __future__ import annotations

import json
from typing import Any

PAB_FIELDS = (
    "blockPublicAcls",
    "blockPublicPolicy",
    "ignorePublicAcls",
    "restrictPublicBuckets",
)


def build_context(env: dict[str, str]) -> dict[str, str]:
    return {
        "uploads_bucket": env.get("UPLOADS_BUCKET", ""),
        "evidence_vault_bucket": env.get("EVIDENCE_VAULT_BUCKET", ""),
        "phi_kms_key_arn": env.get("PHI_KMS_KEY_ARN", ""),
        "phi_kms_key_id": env.get("PHI_KMS_KEY_ID", ""),
        "lambda_role_name": env.get("LAMBDA_ROLE_NAME", ""),
    }


def _alert(
    detection_id: str,
    control_id: str,
    gap_id: str,
    severity: str,
    summary: str,
    detail: dict[str, Any],
) -> dict[str, Any]:
    return {
        "detection_id": detection_id,
        "control_id": control_id,
        "gap_id": gap_id,
        "severity": severity,
        "summary": summary,
        "cloudtrail": {
            "event_id": detail.get("eventID"),
            "event_name": detail.get("eventName"),
            "event_source": detail.get("eventSource"),
            "user": _user_label(detail.get("userIdentity", {})),
            "request_parameters": detail.get("requestParameters") or {},
        },
    }


def _user_label(identity: dict[str, Any]) -> str:
    if not identity:
        return "unknown"
    if identity.get("userName"):
        return str(identity["userName"])
    if identity.get("arn"):
        return str(identity["arn"])
    return str(identity.get("type", "unknown"))


def _is_phi_bucket(bucket: str, uploads_bucket: str, evidence_bucket: str) -> bool:
    if not bucket:
        return False
    if bucket in {uploads_bucket, evidence_bucket}:
        return True
    return bucket.startswith("acme-health-intake-uploads-")


def _public_access_weakened(params: dict[str, Any]) -> bool:
    config = params.get("publicAccessBlockConfiguration") or {}
    if not config:
        return False
    return any(config.get(field) is False for field in PAB_FIELDS)


def _policy_allows_anonymous_access(policy_document: Any) -> bool:
    if policy_document is None:
        return False
    if isinstance(policy_document, dict):
        text = json.dumps(policy_document)
    else:
        text = str(policy_document)
    compact = text.replace(" ", "")
    return '"Principal":"*"' in compact or '"Principal":"*"' in text


def _targets_phi_kms(params: dict[str, Any], ctx: dict[str, str]) -> bool:
    key_ref = str(params.get("keyId", ""))
    if not key_ref:
        return False
    return key_ref in {
        ctx["phi_kms_key_arn"],
        ctx["phi_kms_key_id"],
        f"arn:aws:kms:*:*:key/{ctx['phi_kms_key_id']}",
    }


def _targets_lambda_role(params: dict[str, Any], lambda_role_name: str) -> bool:
    if not lambda_role_name:
        return False
    role_name = str(params.get("roleName", ""))
    if role_name == lambda_role_name:
        return True
    return lambda_role_name in json.dumps(params)


def _iam_policy_regresses_to_wildcards(params: dict[str, Any]) -> bool:
    policy_document = params.get("policyDocument")
    if policy_document is None:
        return False
    text = (
        json.dumps(policy_document)
        if isinstance(policy_document, dict)
        else str(policy_document)
    )
    return "dynamodb:*" in text or "s3:*" in text


def classify_cloudtrail_event(
    detail: dict[str, Any], ctx: dict[str, str]
) -> dict[str, Any] | None:
    """Return a structured alert for PHI-relevant drift, or None to ignore."""
    event_name = detail.get("eventName", "")
    event_source = detail.get("eventSource", "")
    params = detail.get("requestParameters") or {}

    uploads_bucket = ctx["uploads_bucket"]
    evidence_bucket = ctx["evidence_vault_bucket"]
    lambda_role_name = ctx["lambda_role_name"]

    if event_source == "s3.amazonaws.com":
        bucket = str(params.get("bucketName", ""))

        if event_name == "PutBucketPublicAccessBlock" and _is_phi_bucket(
            bucket, uploads_bucket, evidence_bucket
        ):
            if _public_access_weakened(params):
                return _alert(
                    "DET-01",
                    "hipaa-164.312-a-1",
                    "GAP-01/03",
                    "HIGH",
                    "PHI bucket public access block weakened",
                    detail,
                )

        if event_name == "DeleteBucketPublicAccessBlock" and _is_phi_bucket(
            bucket, uploads_bucket, evidence_bucket
        ):
            return _alert(
                "DET-01",
                "hipaa-164.312-a-1",
                "GAP-01/03",
                "HIGH",
                "PHI bucket public access block removed",
                detail,
            )

        if event_name == "PutBucketPolicy" and _is_phi_bucket(
            bucket, uploads_bucket, evidence_bucket
        ):
            if _policy_allows_anonymous_access(params.get("policy")):
                return _alert(
                    "DET-01",
                    "hipaa-164.312-a-1",
                    "GAP-01/03",
                    "HIGH",
                    "PHI bucket policy allows anonymous access",
                    detail,
                )

        if event_name in {
            "PutObjectRetention",
            "PutObjectLegalHold",
            "BypassGovernanceRetention",
        }:
            if bucket == evidence_bucket:
                return _alert(
                    "DET-03",
                    "hipaa-164.312-b",
                    "evidence-vault",
                    "HIGH",
                    "Evidence vault retention or legal hold changed",
                    detail,
                )

    if event_source == "kms.amazonaws.com" and event_name in {
        "DisableKey",
        "ScheduleKeyDeletion",
    }:
        if _targets_phi_kms(params, ctx):
            return _alert(
                "DET-02",
                "hipaa-164.312-a-2-iv",
                "GAP-01/02",
                "CRITICAL",
                "PHI customer-managed KMS key disabled or scheduled for deletion",
                detail,
            )

    if event_source == "iam.amazonaws.com" and event_name in {
        "PutRolePolicy",
        "AttachRolePolicy",
    }:
        if _targets_lambda_role(params, lambda_role_name) and _iam_policy_regresses_to_wildcards(
            params
        ):
            return _alert(
                "DET-04",
                "hipaa-164.312-a-1",
                "GAP-07",
                "HIGH",
                "Intake Lambda IAM role regressed to wildcard data access",
                detail,
            )

    return None
