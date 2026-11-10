"""Parsers for Linux authentication logs and systemd journal entries."""

from datetime import datetime, timezone
import re
from typing import Any, Dict, Optional

from collectors.common.normalization import (
    clean_string,
    generate_event_id,
    normalize_utc_timestamp,
    sanitize_ip,
)
from collectors.common.schemas import EventType, SecurityEvent, Severity


# Regex patterns for standard Linux syslog / auth.log lines
# Example syslog prefix: "Oct 14 22:15:01 myhost sshd[12345]: "
SYSLOG_PREFIX_PATTERN = re.compile(
    r"^(?P<syslog_ts>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>[^\s]+)\s+"
    r"(?P<process>[a-zA-Z0-9_\-\.]+)(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<message>.*)$"
)

# RFC5424 / ISO timestamp syslog prefix: "2026-10-14T22:15:01.123456+00:00 myhost sshd[12345]: "
RFC5424_PREFIX_PATTERN = re.compile(
    r"^(?P<iso_ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))\s+"
    r"(?P<host>[^\s]+)\s+"
    r"(?P<process>[a-zA-Z0-9_\-\.]+)(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<message>.*)$"
)

# SSH Accepted: "Accepted password for root from 192.168.1.100 port 45678 ssh2"
SSH_ACCEPTED_PATTERN = re.compile(
    r"^Accepted\s+(?P<auth_method>[a-zA-Z0-9_\-]+)\s+for\s+(?P<user>[^\s]+)\s+from\s+(?P<src_ip>[^\s]+)\s+port\s+(?P<port>\d+)"
)

# SSH Failed: "Failed password for invalid user admin from 10.0.0.5 port 55432 ssh2"
# or "Failed password for root from 10.0.0.5 port 55432 ssh2"
SSH_FAILED_PATTERN = re.compile(
    r"^Failed\s+(?P<auth_method>[a-zA-Z0-9_\-]+)\s+for\s+(?:(?P<invalid>invalid user)\s+)?(?P<user>[^\s]+)\s+from\s+(?P<src_ip>[^\s]+)\s+port\s+(?P<port>\d+)"
)

# SSH Invalid user: "Invalid user test from 10.0.0.5 port 55433"
SSH_INVALID_USER_PATTERN = re.compile(
    r"^Invalid user\s+(?P<user>[^\s]+)\s+from\s+(?P<src_ip>[^\s]+)\s+port\s+(?P<port>\d+)"
)

# Sudo command execution: "sudo:   alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/bash"
SUDO_COMMAND_PATTERN = re.compile(
    r"^(?P<invoker>[^\s:]+)\s*:\s*TTY=(?P<tty>[^\s;]+)\s*;\s*PWD=(?P<pwd>[^\s;]+)\s*;\s*USER=(?P<target_user>[^\s;]+)\s*;\s*COMMAND=(?P<command>.*)$"
)

# Sudo authentication failure
SUDO_AUTH_FAILURE_PATTERN = re.compile(
    r"^(?P<invoker>[^\s:]+)\s*:\s*(?:\d+\s+incorrect password attempts?|authentication failure).*?(?:user=(?P<target_user>[^\s]+))?"
)


def parse_linux_auth_line(
    raw_line: str,
    default_host: str = "linux-host",
    collector_version: str = "0.1.0",
) -> Optional[SecurityEvent]:
    """Parse a single Linux authentication log line into a normalized SecurityEvent."""
    line = raw_line.strip()
    if not line:
        return None

    observed_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Match syslog header
    host = default_host
    timestamp_str = observed_at
    process = "unknown"
    message = line

    m_rfc = RFC5424_PREFIX_PATTERN.match(line)
    if m_rfc:
        timestamp_str = normalize_utc_timestamp(m_rfc.group("iso_ts"))
        host = m_rfc.group("host") or default_host
        process = m_rfc.group("process")
        message = m_rfc.group("message")
    else:
        m_syslog = SYSLOG_PREFIX_PATTERN.match(line)
        if m_syslog:
            timestamp_str = normalize_utc_timestamp(m_syslog.group("syslog_ts"))
            host = m_syslog.group("host") or default_host
            process = m_syslog.group("process")
            message = m_syslog.group("message")

    # Initialize extraction fields
    event_type = EventType.UNKNOWN.value
    severity = Severity.INFORMATIONAL.value
    username: Optional[str] = None
    source_ip: Optional[str] = None
    metadata: Dict[str, Any] = {"process": process}

    # 1. Check SSH accepted
    m_ssh_acc = SSH_ACCEPTED_PATTERN.search(message)
    if m_ssh_acc:
        event_type = EventType.AUTHENTICATION_SUCCESS.value
        severity = Severity.LOW.value
        username = clean_string(m_ssh_acc.group("user"))
        source_ip = sanitize_ip(m_ssh_acc.group("src_ip"))
        metadata["auth_method"] = m_ssh_acc.group("auth_method")
        metadata["src_port"] = int(m_ssh_acc.group("port"))

    # 2. Check SSH failed
    elif SSH_FAILED_PATTERN.search(message):
        m_ssh_fail = SSH_FAILED_PATTERN.search(message)
        assert m_ssh_fail is not None
        event_type = EventType.AUTHENTICATION_FAILURE.value
        severity = Severity.MEDIUM.value
        username = clean_string(m_ssh_fail.group("user"))
        source_ip = sanitize_ip(m_ssh_fail.group("src_ip"))
        metadata["auth_method"] = m_ssh_fail.group("auth_method")
        metadata["src_port"] = int(m_ssh_fail.group("port"))
        metadata["is_invalid_user"] = bool(m_ssh_fail.group("invalid"))

    # 3. Check SSH invalid user only
    elif SSH_INVALID_USER_PATTERN.search(message):
        m_inv = SSH_INVALID_USER_PATTERN.search(message)
        assert m_inv is not None
        event_type = EventType.AUTHENTICATION_FAILURE.value
        severity = Severity.MEDIUM.value
        username = clean_string(m_inv.group("user"))
        source_ip = sanitize_ip(m_inv.group("src_ip"))
        metadata["src_port"] = int(m_inv.group("port"))
        metadata["is_invalid_user"] = True

    # 4. Check Sudo commands
    elif process == "sudo" and SUDO_COMMAND_PATTERN.search(message):
        m_sudo = SUDO_COMMAND_PATTERN.search(message)
        assert m_sudo is not None
        event_type = EventType.PRIVILEGE_ESCALATION.value
        severity = Severity.LOW.value
        username = clean_string(m_sudo.group("target_user"))
        metadata["invoker"] = clean_string(m_sudo.group("invoker"))
        metadata["command"] = clean_string(m_sudo.group("command"))
        metadata["pwd"] = clean_string(m_sudo.group("pwd"))
        metadata["tty"] = clean_string(m_sudo.group("tty"))

    # 5. Check Sudo failures
    elif process == "sudo" and SUDO_AUTH_FAILURE_PATTERN.search(message):
        m_sudo_fail = SUDO_AUTH_FAILURE_PATTERN.search(message)
        assert m_sudo_fail is not None
        event_type = EventType.AUTHENTICATION_FAILURE.value
        severity = Severity.HIGH.value
        username = clean_string(m_sudo_fail.group("target_user")) or clean_string(
            m_sudo_fail.group("invoker")
        )
        metadata["invoker"] = clean_string(m_sudo_fail.group("invoker"))

    # 6. Generic PAM session opened/closed
    elif "session opened for user" in message:
        m_sess = re.search(r"session opened for user\s+([^\s\(]+)", message)
        if m_sess:
            event_type = EventType.AUTHENTICATION_SUCCESS.value
            severity = Severity.INFORMATIONAL.value
            username = clean_string(m_sess.group(1))
    elif "session closed for user" in message:
        m_sess = re.search(r"session closed for user\s+([^\s\(]+)", message)
        if m_sess:
            event_type = EventType.SESSION_LOGOFF.value
            severity = Severity.INFORMATIONAL.value
            username = clean_string(m_sess.group(1))

    event_id = generate_event_id(
        source_host=host,
        source_type="linux_auth",
        timestamp=timestamp_str,
        raw_event=line,
    )

    return SecurityEvent(
        schema_version="1.0",
        event_id=event_id,
        timestamp=timestamp_str,
        observed_at=observed_at,
        source_host=host,
        source_type="linux_auth",
        event_type=event_type,
        username=username,
        source_ip=source_ip,
        destination_ip=None,
        windows_event_id=None,
        severity=severity,
        raw_event=line,
        collector_version=collector_version,
        metadata=metadata,
    )


def parse_journal_entry(
    entry: Dict[str, Any],
    default_host: str = "linux-host",
    collector_version: str = "0.1.0",
) -> Optional[SecurityEvent]:
    """Parse a structured systemd journal dictionary entry into a SecurityEvent."""
    message = entry.get("MESSAGE")
    if not message:
        return None

    # Journal realtime timestamp is in microseconds since epoch
    rt_ts = entry.get("__REALTIME_TIMESTAMP")
    if rt_ts:
        try:
            ts_epoch = float(rt_ts) / 1_000_000.0
            timestamp_str = normalize_utc_timestamp(ts_epoch)
        except (ValueError, TypeError):
            timestamp_str = normalize_utc_timestamp(None)
    else:
        timestamp_str = normalize_utc_timestamp(None)

    host = clean_string(entry.get("_HOSTNAME")) or default_host
    cursor = entry.get("__CURSOR")
    process = clean_string(entry.get("_COMM")) or "systemd"

    # Synthetic syslog line from journal entry for unified parsing
    synth_line = f"{timestamp_str} {host} {process}: {message}"
    parsed = parse_linux_auth_line(
        raw_line=synth_line,
        default_host=host,
        collector_version=collector_version,
    )
    if parsed:
        parsed.source_type = "systemd_journal"
        if cursor:
            parsed.metadata["journal_cursor"] = cursor
        parsed.metadata["pid"] = entry.get("_PID")
        parsed.metadata["unit"] = entry.get("_SYSTEMD_UNIT")

    return parsed
