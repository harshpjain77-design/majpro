"""Unit tests for normalization, timestamp parsing, IP validation, and event ID hashing."""

from datetime import datetime, timezone
import pytest

from collectors.common.normalization import (
    clean_string,
    generate_event_id,
    normalize_utc_timestamp,
    sanitize_ip,
)


def test_clean_string():
    assert clean_string("  alice  ") == "alice"
    assert clean_string("") is None
    assert clean_string("   ") is None
    assert clean_string(None) is None
    assert clean_string("-") is None
    assert clean_string("None") is None
    assert clean_string("(null)") is None
    assert clean_string("NULL") is None
    assert clean_string("N/A") is None


def test_sanitize_ip_ipv4():
    assert sanitize_ip("192.168.1.100") == "192.168.1.100"
    assert sanitize_ip("10.0.0.1:44321") == "10.0.0.1"
    assert sanitize_ip("  172.16.0.5  ") == "172.16.0.5"


def test_sanitize_ip_ipv6():
    assert sanitize_ip("2001:db8::1") == "2001:db8::1"
    assert sanitize_ip("[2001:db8::cafe:1]") == "2001:db8::cafe:1"
    assert sanitize_ip("fe80::1ff:fe23:4567:890a") == "fe80::1ff:fe23:4567:890a"


def test_sanitize_ip_ipv4_mapped_ipv6():
    assert sanitize_ip("::ffff:192.168.1.50") == "192.168.1.50"


def test_sanitize_ip_invalid():
    assert sanitize_ip("not-an-ip") is None
    assert sanitize_ip("") is None
    assert sanitize_ip(None) is None
    assert sanitize_ip("999.999.999.999") is None


def test_normalize_utc_timestamp_iso():
    iso_str = "2026-10-14T20:00:00+02:00"
    normalized = normalize_utc_timestamp(iso_str)
    assert normalized == "2026-10-14T18:00:00Z"


def test_normalize_utc_timestamp_epoch():
    epoch = 1728936000.0
    normalized = normalize_utc_timestamp(epoch)
    assert normalized.endswith("Z")
    assert "T" in normalized


def test_normalize_utc_timestamp_syslog_format():
    syslog_str = "Oct 14 18:30:15"
    normalized = normalize_utc_timestamp(syslog_str)
    assert "-10-14T18:30:15Z" in normalized


def test_generate_event_id_deterministic():
    """Verify that identical inputs produce the exact same deterministic hash."""
    id1 = generate_event_id(
        source_host="srv1",
        source_type="linux_auth",
        timestamp="2026-10-14T20:00:00Z",
        raw_event="Failed password for root",
        record_id=100,
    )
    id2 = generate_event_id(
        source_host="srv1",
        source_type="linux_auth",
        timestamp="2026-10-14T20:00:00Z",
        raw_event="Failed password for root",
        record_id=100,
    )
    assert id1.startswith("evt_")
    assert id1 == id2


def test_generate_event_id_discriminative():
    """Verify that differing fields yield distinct hashes."""
    base_args = {
        "source_host": "srv1",
        "source_type": "linux_auth",
        "timestamp": "2026-10-14T20:00:00Z",
        "raw_event": "Failed password for root",
    }
    id_base = generate_event_id(**base_args)
    id_diff_time = generate_event_id(
        source_host="srv1",
        source_type="linux_auth",
        timestamp="2026-10-14T20:00:01Z",
        raw_event="Failed password for root",
    )
    id_diff_user = generate_event_id(
        source_host="srv1",
        source_type="linux_auth",
        timestamp="2026-10-14T20:00:00Z",
        raw_event="Failed password for admin",
    )
    assert id_base != id_diff_time
    assert id_base != id_diff_user
