"""Integration and flow tests for Linux and Windows collector agents."""

import json
from pathlib import Path
import pytest

from collectors.linux.collector import LinuxAuthCollector
from collectors.windows.collector import WindowsSecurityCollector


def test_linux_collector_incremental_and_deduplication_flow(tmp_path):
    """Test full file tailing flow: initial read, no-op duplicate check, and append read."""
    log_file = tmp_path / "auth.log"
    ckpt_file = tmp_path / "checkpoint_linux.json"
    out_file = tmp_path / "events_linux.jsonl"

    line1 = "Oct 14 22:00:01 kali sshd[100]: Accepted password for alice from 192.168.1.10 port 40001 ssh2\n"
    line2 = "Oct 14 22:00:05 kali sshd[101]: Failed password for bob from 192.168.1.20 port 40002 ssh2\n"

    # Step 1: Initial log write
    log_file.write_text(line1 + line2, encoding="utf-8")

    collector = LinuxAuthCollector(
        log_path=str(log_file),
        checkpoint_path=str(ckpt_file),
        output_path=str(out_file),
        host_override="kali-test",
    )

    # First collection pass: Should collect 2 events
    events1 = collector.collect()
    assert len(events1) == 2
    assert events1[0].username == "alice"
    assert events1[1].username == "bob"

    # Verify JSON Lines output file exists and has 2 valid JSON records
    lines = out_file.read_text(encoding="utf-8").strip().split("\n")
    assert len(lines) == 2
    for l in lines:
        parsed_json = json.loads(l)
        assert parsed_json["schema_version"] == "1.0"
        assert parsed_json["event_id"].startswith("evt_")

    # Step 2: Second collection pass without changes: Should collect 0 events (no duplicates!)
    events2 = collector.collect()
    assert len(events2) == 0

    # Step 3: Append two new lines
    line3 = "Oct 14 22:00:10 kali sshd[102]: Failed password for invalid user root from 192.168.1.30 port 40003 ssh2\n"
    line4 = "Oct 14 22:00:15 kali sudo:   alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/ls\n"
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(line3 + line4)

    # Third collection pass: Should collect only the 2 newly appended events
    events3 = collector.collect()
    assert len(events3) == 2
    assert events3[0].username == "root"
    assert events3[0].metadata["is_invalid_user"] is True
    assert events3[1].event_type == "privilege_escalation"

    # Verify total events in output file is 4
    total_lines = out_file.read_text(encoding="utf-8").strip().split("\n")
    assert len(total_lines) == 4


def test_linux_collector_truncation_recovery(tmp_path):
    """Test collector behavior when log file is truncated (e.g. copytruncate)."""
    log_file = tmp_path / "auth.log"
    ckpt_file = tmp_path / "checkpoint_linux.json"
    out_file = tmp_path / "events_linux.jsonl"

    initial_content = "Oct 14 22:00:01 kali sshd[100]: Accepted password for u1 from 192.168.1.1 port 40001 ssh2\n" * 20
    log_file.write_text(initial_content, encoding="utf-8")

    collector = LinuxAuthCollector(
        log_path=str(log_file),
        checkpoint_path=str(ckpt_file),
        output_path=str(out_file),
    )
    events = collector.collect()
    assert len(events) == 20

    # Truncate file and write 1 new line
    truncated_line = "Oct 14 22:05:00 kali sshd[200]: Failed password for u2 from 192.168.1.2 port 40002 ssh2\n"
    log_file.write_text(truncated_line, encoding="utf-8")

    # Run collector again -> Should detect size reset and read from offset 0
    events_after_trunc = collector.collect()
    assert len(events_after_trunc) == 1
    assert events_after_trunc[0].username == "u2"


def test_windows_collector_mocked_query(tmp_path, monkeypatch):
    """Test Windows Security Collector with mocked pywin32 API to verify collection logic."""
    fixture_path = Path("tests/fixtures/windows_events.xml")
    xml_content = fixture_path.read_text(encoding="utf-8")

    # Extract individual event XML chunks
    import xml.etree.ElementTree as ET

    root = ET.fromstring(xml_content)
    xml_chunks = [ET.tostring(child, encoding="unicode") for child in root]

    # Mock win32evtlog functions
    mock_handles = [1, 2, 3]

    class MockWin32EvtLog:
        EvtQueryChannelPath = 1
        EvtQueryForwardDirection = 2
        EvtQueryReverseDirection = 4
        EvtRenderEventXml = 1

        @staticmethod
        def EvtQuery(path, flags, Query=None, Session=None):
            return "mock_query_handle"

        @staticmethod
        def EvtNext(handle, count):
            if mock_handles:
                h = mock_handles.pop(0)
                return [h]
            return []

        @staticmethod
        def EvtRender(event_handle, flags):
            idx = (event_handle - 1) % len(xml_chunks)
            return xml_chunks[idx]

    import collectors.windows.collector as win_col_mod

    monkeypatch.setattr(win_col_mod, "HAS_WIN32", True)
    monkeypatch.setattr(win_col_mod, "win32evtlog", MockWin32EvtLog)

    ckpt_file = tmp_path / "checkpoint_windows.json"
    out_file = tmp_path / "events_windows.jsonl"

    collector = WindowsSecurityCollector(
        channel="Security",
        checkpoint_path=str(ckpt_file),
        output_path=str(out_file),
        initial_read_policy="all",
        host_override="WIN-SRV-TEST",
    )

    events = collector.collect()
    assert len(events) == 3
    assert events[0].windows_event_id == 4624
    assert events[1].windows_event_id == 4625
    assert events[2].windows_event_id == 4672

    # Checkpoint should have recorded highest record number
    assert collector.checkpoint.get_last_record_number() == 500103


def test_windows_collector_environment_discovery():
    collector = WindowsSecurityCollector()
    env = collector.discover_environment()
    assert "platform" in env
    assert "hostname" in env
    assert "pywin32_available" in env
