"""Replay CloudTrail fixtures against HIPAA detection logic (HIPAA 164.312)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from detector.classify import classify_cloudtrail_event

FIXTURES = Path(__file__).parent / "fixtures"

CTX = {
    "uploads_bucket": "acme-health-intake-uploads-deadbeef",
    "evidence_vault_bucket": "acme-health-intake-grc-evidence-vault-deadbeef",
    "phi_kms_key_arn": "arn:aws:kms:us-east-1:123456789012:key/11111111-2222-3333-4444-555555555555",
    "phi_kms_key_id": "11111111-2222-3333-4444-555555555555",
    "lambda_role_name": "acme-health-intake-lambda-deadbeef",
}


def load_fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def test_det_01_public_access_block_weakened():
    detail = load_fixture("det01_pab_weakened.json")
    alert = classify_cloudtrail_event(detail, CTX)

    assert alert is not None
    assert alert["detection_id"] == "DET-01"
    assert alert["control_id"] == "hipaa-164.312-a-1"
    assert alert["gap_id"] == "GAP-01/03"
    assert alert["severity"] == "HIGH"


def test_det_01_compliant_pab_update_is_ignored():
    detail = load_fixture("det01_pab_compliant.json")
    assert classify_cloudtrail_event(detail, CTX) is None


def test_det_02_kms_schedule_deletion():
    detail = load_fixture("det02_kms_delete.json")
    alert = classify_cloudtrail_event(detail, CTX)

    assert alert is not None
    assert alert["detection_id"] == "DET-02"
    assert alert["control_id"] == "hipaa-164.312-a-2-iv"
    assert alert["severity"] == "CRITICAL"


def test_det_03_evidence_vault_retention_change():
    detail = load_fixture("det03_evidence_retention.json")
    alert = classify_cloudtrail_event(detail, CTX)

    assert alert is not None
    assert alert["detection_id"] == "DET-03"
    assert alert["control_id"] == "hipaa-164.312-b"


def test_det_04_lambda_iam_wildcard_regression():
    detail = load_fixture("det04_iam_wildcard.json")
    alert = classify_cloudtrail_event(detail, CTX)

    assert alert is not None
    assert alert["detection_id"] == "DET-04"
    assert alert["gap_id"] == "GAP-07"


def test_unrelated_s3_event_is_ignored():
    detail = load_fixture("benign_cloudtrail_put_object.json")
    assert classify_cloudtrail_event(detail, CTX) is None


@pytest.mark.parametrize(
    "fixture_name,detection_id",
    [
        ("det01_pab_weakened.json", "DET-01"),
        ("det02_kms_delete.json", "DET-02"),
        ("det03_evidence_retention.json", "DET-03"),
        ("det04_iam_wildcard.json", "DET-04"),
    ],
)
def test_negative_cases_do_not_cross_trigger(fixture_name, detection_id):
    detail = load_fixture(fixture_name)
    detail["eventSource"] = "ec2.amazonaws.com"
    detail["eventName"] = "RunInstances"
    detail["requestParameters"] = {}
    assert classify_cloudtrail_event(detail, CTX) is None
