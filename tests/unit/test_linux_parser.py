"""Unit tests for Linux auth.log and systemd journal parsing."""

from pathlib import Path
import json

from collectors.common.schemas import EventType, Severity
from collectors.linux.parsers import parse_journal_entry, parse_linux_auth_line


def test_parse_ssh_accepted_password():
    line = "Oct 14 22:00:01 kali-node sshd[10201]: Accepted password for student from 192.168.56.101 port 45210 ssh2"
    event = parse_linux_auth_line(line, default_host="kali-node")
    assert event is not None
    assert event.event_type == EventType.AUTHENTICATION_SUCCESS.value
    assert event.username == "student"
    assert event.source_ip == "192.168.56.101"
    assert event.source_host == "kali-node"
    assert event.metadata["auth_method"] == "password"
    assert event.metadata["src_port"] == 45210
    assert event.severity == Severity.LOW.value


def test_parse_ssh_accepted_publickey_ipv6():
    line = "Oct 14 22:01:15 kali-node sshd[10255]: Accepted publickey for ansible from 2001:db8::cafe:1 port 52340 ssh2: RSA SHA256:dGhpc2lz"
    event = parse_linux_auth_line(line, default_host="kali-node")
    assert event is not None
    assert event.event_type == EventType.AUTHENTICATION_SUCCESS.value
    assert event.username == "ansible"
    assert event.source_ip == "2001:db8::cafe:1"
    assert event.metadata["auth_method"] == "publickey"


def test_parse_ssh_failed_password_valid_user():
    line = "Oct 14 22:05:30 kali-node sshd[10310]: Failed password for root from 192.168.56.200 port 38912 ssh2"
    event = parse_linux_auth_line(line, default_host="kali-node")
    assert event is not None
    assert event.event_type == EventType.AUTHENTICATION_FAILURE.value
    assert event.username == "root"
    assert event.source_ip == "192.168.56.200"
    assert event.metadata["is_invalid_user"] is False
    assert event.severity == Severity.MEDIUM.value


def test_parse_ssh_failed_password_invalid_user():
    line = "Oct 14 22:05:33 kali-node sshd[10314]: Failed password for invalid user administrator from 192.168.56.200 port 38914 ssh2"
    event = parse_linux_auth_line(line, default_host="kali-node")
    assert event is not None
    assert event.event_type == EventType.AUTHENTICATION_FAILURE.value
    assert event.username == "administrator"
    assert event.source_ip == "192.168.56.200"
    assert event.metadata["is_invalid_user"] is True


def test_parse_ssh_invalid_user_line():
    line = "Oct 14 22:05:32 kali-node sshd[10312]: Invalid user testuser from 10.0.0.99 port 38914"
    event = parse_linux_auth_line(line, default_host="kali-node")
    assert event is not None
    assert event.event_type == EventType.AUTHENTICATION_FAILURE.value
    assert event.username == "testuser"
    assert event.source_ip == "10.0.0.99"
    assert event.metadata["is_invalid_user"] is True


def test_parse_sudo_command():
    line = "Oct 14 22:10:00 kali-node sudo:   student : TTY=pts/0 ; PWD=/home/student ; USER=root ; COMMAND=/bin/cat /etc/shadow"
    event = parse_linux_auth_line(line, default_host="kali-node")
    assert event is not None
    assert event.event_type == EventType.PRIVILEGE_ESCALATION.value
    assert event.username == "root"
    assert event.metadata["invoker"] == "student"
    assert event.metadata["command"] == "/bin/cat /etc/shadow"


def test_parse_sudo_failure():
    line = "Oct 14 22:12:00 kali-node sudo:   guest : 3 incorrect password attempts ; TTY=pts/1 ; PWD=/home/guest ; USER=root ; COMMAND=/usr/bin/id"
    event = parse_linux_auth_line(line, default_host="kali-node")
    assert event is not None
    assert event.event_type == EventType.AUTHENTICATION_FAILURE.value
    assert event.metadata["invoker"] == "guest"
    assert event.severity == Severity.HIGH.value


def test_parse_pam_session():
    line = "Oct 14 22:20:00 kali-node sshd[10400]: pam_unix(sshd:session): session opened for user student(uid=1000) by (uid=0)"
    event = parse_linux_auth_line(line, default_host="kali-node")
    assert event is not None
    assert event.event_type == EventType.AUTHENTICATION_SUCCESS.value
    assert event.username == "student"


def test_parse_malformed_line_safe():
    """Verify that completely unparseable or junk lines do not crash the parser."""
    junk = "NOT_A_VALID_SYSLOG_LINE_AT_ALL_$$$$$$$%%%12345"
    event = parse_linux_auth_line(junk, default_host="test")
    assert event is not None
    assert event.event_type == EventType.UNKNOWN.value
    assert event.raw_event == junk


def test_parse_journal_entry():
    fixture_path = Path("tests/fixtures/journal_sample.json")
    with open(fixture_path, "r", encoding="utf-8") as f:
        entries = json.load(f)

    event1 = parse_journal_entry(entries[0])
    assert event1 is not None
    assert event1.source_type == "systemd_journal"
    assert event1.username == "labuser"
    assert event1.source_ip == "10.0.2.15"
    assert event1.event_type == EventType.AUTHENTICATION_SUCCESS.value
    assert event1.metadata["journal_cursor"] == entries[0]["__CURSOR"]

    event2 = parse_journal_entry(entries[1])
    assert event2 is not None
    assert event2.username == "root"
    assert event2.source_ip == "10.0.2.99"
    assert event2.event_type == EventType.AUTHENTICATION_FAILURE.value
