"""Unit tests for HttpEventShipper client."""

import httpx
import pytest

from collectors.common.schemas import EventType, SecurityEvent
from collectors.common.shipper import HttpEventShipper


def _sample_events():
    return [
        SecurityEvent(
            schema_version="1.0",
            event_id="evt_ship_1",
            timestamp="2026-10-15T00:00:00Z",
            observed_at="2026-10-15T00:00:01Z",
            source_host="kali-box",
            source_type="linux_auth",
            event_type=EventType.AUTHENTICATION_SUCCESS.value,
            raw_event="Accepted password for test",
        )
    ]


def test_shipper_successful_batch(monkeypatch):
    """Verify shipper constructs valid payload, headers, and processes JSON response."""

    def mock_post(client, url, json, headers):
        assert headers["X-API-Key"] == "secret-key"
        assert headers["X-Agent-ID"] == "agent-kali"
        assert len(json["events"]) == 1
        return httpx.Response(
            status_code=200,
            json={"status": "success", "ingested_count": 1, "duplicate_count": 0},
            request=httpx.Request("POST", url),
        )

    monkeypatch.setattr(httpx.Client, "post", mock_post)

    shipper = HttpEventShipper(
        api_url="http://127.0.0.1:8000/api/v1/ingest/batch",
        api_key="secret-key",
        agent_id="agent-kali",
    )
    result = shipper.ship_batch(_sample_events())
    assert result is not None
    assert result["ingested_count"] == 1


def test_shipper_network_failure_handling(monkeypatch):
    """Verify network exceptions are caught and return None without crashing."""

    def mock_error(client, url, json, headers):
        raise httpx.ConnectError("Connection refused")

    monkeypatch.setattr(httpx.Client, "post", mock_error)

    shipper = HttpEventShipper(
        api_url="http://127.0.0.1:8000/api/v1/ingest/batch",
        api_key="secret-key",
    )
    result = shipper.ship_batch(_sample_events())
    assert result is None


def test_shipper_empty_batch():
    shipper = HttpEventShipper()
    assert shipper.ship_batch([]) is None
