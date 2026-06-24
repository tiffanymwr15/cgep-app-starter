"""Unit tests for alert deduplication (noise reduction)."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

import handler


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("DEDUP_TABLE", "acme-health-intake-alert-dedup-test")
    monkeypatch.setenv("DEDUP_TTL_SECONDS", "3600")
    monkeypatch.setenv("SNS_TOPIC_ARN", "arn:aws:sns:us-east-1:123456789012:security-alerts")
    handler._dynamodb = None
    handler._sns = None


def _patch_dynamodb(monkeypatch, fake_client: MagicMock) -> None:
    monkeypatch.setattr(handler, "_get_dynamodb", lambda: fake_client)


def test_is_duplicate_returns_false_for_new_event(monkeypatch):
    fake_client = MagicMock()
    fake_client.get_item.return_value = {}
    _patch_dynamodb(monkeypatch, fake_client)

    assert handler.is_duplicate("event-123", now=1_700_000_000) is False


def test_is_duplicate_returns_true_inside_ttl_window(monkeypatch):
    fake_client = MagicMock()
    fake_client.get_item.return_value = {
        "Item": {"expires_at": {"N": "1700003600"}}
    }
    _patch_dynamodb(monkeypatch, fake_client)

    assert handler.is_duplicate("event-123", now=1_700_000_000) is True


def test_is_duplicate_returns_false_after_ttl_expires(monkeypatch):
    fake_client = MagicMock()
    fake_client.get_item.return_value = {
        "Item": {"expires_at": {"N": "1699990000"}}
    }
    _patch_dynamodb(monkeypatch, fake_client)

    assert handler.is_duplicate("event-123", now=1_700_000_000) is False


def test_record_dedup_writes_ttl_attributes(monkeypatch):
    fake_client = MagicMock()
    _patch_dynamodb(monkeypatch, fake_client)

    handler.record_dedup("event-456", now=1_700_000_000)

    fake_client.put_item.assert_called_once()
    item = fake_client.put_item.call_args.kwargs["Item"]
    assert item["event_id"]["S"] == "event-456"
    assert item["expires_at"]["N"] == "1700003600"
