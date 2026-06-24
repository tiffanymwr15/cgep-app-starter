"""Lambda entry point: classify CloudTrail events, deduplicate, route to SNS."""

from __future__ import annotations

import json
import os
import time
from typing import Any

import boto3
from botocore.exceptions import ClientError

from classify import build_context, classify_cloudtrail_event

_dynamodb = None
_sns = None


def _get_dynamodb():
    global _dynamodb
    if _dynamodb is None:
        _dynamodb = boto3.client("dynamodb")
    return _dynamodb


def _get_sns():
    global _sns
    if _sns is None:
        _sns = boto3.client("sns")
    return _sns


def _dedup_table() -> str:
    table = os.environ.get("DEDUP_TABLE", "")
    if not table:
        raise ValueError("DEDUP_TABLE environment variable is required")
    return table


def _dedup_ttl_seconds() -> int:
    return int(os.environ.get("DEDUP_TTL_SECONDS", "3600"))


def is_duplicate(event_id: str, *, now: int | None = None) -> bool:
    if not event_id:
        return False

    current = now if now is not None else int(time.time())
    response = _get_dynamodb().get_item(
        TableName=_dedup_table(),
        Key={"event_id": {"S": event_id}},
        ConsistentRead=True,
    )
    item = response.get("Item")
    if not item:
        return False

    expires_at = int(item.get("expires_at", {}).get("N", "0"))
    return expires_at > current


def record_dedup(event_id: str, *, now: int | None = None) -> None:
    if not event_id:
        return

    current = now if now is not None else int(time.time())
    expires_at = current + _dedup_ttl_seconds()
    _get_dynamodb().put_item(
        TableName=_dedup_table(),
        Item={
            "event_id": {"S": event_id},
            "expires_at": {"N": str(expires_at)},
            "recorded_at": {"N": str(current)},
        },
        ConditionExpression="attribute_not_exists(event_id)",
    )


def publish_alert(alert: dict[str, Any]) -> str:
    topic_arn = os.environ["SNS_TOPIC_ARN"]
    subject = f"[{alert['severity']}] {alert['detection_id']} {alert['summary']}"
    response = _get_sns().publish(
        TopicArn=topic_arn,
        Subject=subject[:100],
        Message=json.dumps(alert, indent=2, sort_keys=True),
    )
    return response["MessageId"]


def handler(event: dict[str, Any], _context: Any) -> dict[str, Any]:
    detail = event.get("detail") or {}
    ctx = build_context(os.environ)
    alert = classify_cloudtrail_event(detail, ctx)
    if alert is None:
        return {"status": "ignored"}

    event_id = str(detail.get("eventID", ""))
    if is_duplicate(event_id):
        return {"status": "deduplicated", "event_id": event_id}

    try:
        record_dedup(event_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
            return {"status": "deduplicated", "event_id": event_id}
        raise

    message_id = publish_alert(alert)
    return {
        "status": "alerted",
        "detection_id": alert["detection_id"],
        "message_id": message_id,
    }
