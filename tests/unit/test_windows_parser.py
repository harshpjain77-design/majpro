"""Unit tests for Windows Security Event Log XML parser."""

from pathlib import Path
import xml.etree.ElementTree as ET

from collectors.common.schemas import EventType, Severity
from collectors.windows.parsers import parse_windows_event_xml


def _extract_individual_events_from_fixture():
    fixture_path = Path("tests/fixtures/windows_events.xml")
    root = ET.parse(fixture_path).getroot()
    events_xml = []
    for elem in root:
        events_xml.append(ET.tostring(elem, encoding="unicode"))
    return events_xml


def test_parse_windows_event_4624_success():
    events = _extract_individual_events_from_fixture()
    xml_4624 = events[0]

    event = parse_windows_event_xml(xml_4624)
    assert event is not None
    assert event.windows_event_id == 4624
    assert event.event_type == EventType.AUTHENTICATION_SUCCESS.value
    assert event.username == "secadmin"
    assert event.source_ip == "127.0.0.1"
    assert event.metadata["domain"] == "LAB"
    assert event.metadata["logon_type"] == 2
    assert event.metadata["record_number"] == 500101
    assert event.severity == Severity.LOW.value


def test_parse_windows_event_4625_failure():
    events = _extract_individual_events_from_fixture()
    xml_4625 = events[1]

    event = parse_windows_event_xml(xml_4625)
    assert event is not None
    assert event.windows_event_id == 4625
    assert event.event_type == EventType.AUTHENTICATION_FAILURE.value
    assert event.username == "Administrator"
    assert event.source_ip == "192.168.56.200"
    assert event.metadata["domain"] == "LAB"
    assert event.metadata["status"] == "0xc000006d"
    assert event.metadata["sub_status"] == "0xc000006a"
    assert event.metadata["record_number"] == 500102
    assert event.severity == Severity.MEDIUM.value


def test_parse_windows_event_4672_privilege():
    events = _extract_individual_events_from_fixture()
    xml_4672 = events[2]

    event = parse_windows_event_xml(xml_4672)
    assert event is not None
    assert event.windows_event_id == 4672
    # Verify treated as privileged-logon indicator with informational severity (not assumed malicious)
    assert event.event_type == EventType.PRIVILEGE_ESCALATION.value
    assert event.severity == Severity.INFORMATIONAL.value
    assert event.username == "secadmin"


def test_parse_windows_event_partial_or_other():
    events = _extract_individual_events_from_fixture()
    xml_partial = events[3]

    event = parse_windows_event_xml(xml_partial)
    assert event is not None
    assert event.windows_event_id == 9999
    assert event.event_type == EventType.UNKNOWN.value


def test_parse_windows_event_invalid_xml():
    """Verify that malformed XML returns None safely without raising an exception."""
    junk_xml = "<Event><System><UnclosedTag></Event>"
    event = parse_windows_event_xml(junk_xml)
    assert event is None
