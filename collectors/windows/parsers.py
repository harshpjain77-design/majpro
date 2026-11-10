"""Windows Security Event XML parser."""

from datetime import datetime, timezone
from typing import Any, Dict, Optional
import xml.etree.ElementTree as ET

from collectors.common.normalization import (
    clean_string,
    generate_event_id,
    normalize_utc_timestamp,
    sanitize_ip,
)
from collectors.common.schemas import EventType, SecurityEvent, Severity

# XML Namespace for Windows Event Logs
WIN_EVENT_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"


def _find_text(element: Optional[ET.Element], path: str) -> Optional[str]:
    if element is None:
        return None
    node = element.find(path)
    if node is not None and node.text:
        return node.text.strip()
    return None


def parse_windows_event_xml(
    xml_content: str,
    default_host: str = "windows-server",
    collector_version: str = "0.1.0",
    collector_id: Optional[str] = None,
) -> Optional[SecurityEvent]:
    """Parse Windows Event Log XML string into a canonical SecurityEvent.

    Supports Event IDs 4624 (Logon), 4625 (Logon Failure), 4672 (Special Privileges),
    and falls back safely for other security events.
    """
    raw_clean = xml_content.strip()
    if not raw_clean:
        return None

    try:
        root = ET.fromstring(raw_clean)
    except ET.ParseError:
        return None

    # Namespace stripping helper
    def ns_tag(tag: str) -> str:
        return f"{WIN_EVENT_NS}{tag}" if root.tag.startswith("{") else tag

    system = root.find(ns_tag("System"))
    event_data = root.find(ns_tag("EventData"))

    # Extract System header fields
    event_id_str = _find_text(system, ns_tag("EventID"))
    try:
        event_id_num = int(event_id_str) if event_id_str else None
    except ValueError:
        event_id_num = None

    provider_node = system.find(ns_tag("Provider")) if system is not None else None
    provider = provider_node.get("Name") if provider_node is not None else None

    level_str = _find_text(system, ns_tag("Level"))
    try:
        level_num = int(level_str) if level_str else None
    except ValueError:
        level_num = None

    record_id_str = _find_text(system, ns_tag("EventRecordID"))
    record_number = int(record_id_str) if record_id_str and record_id_str.isdigit() else None

    computer = _find_text(system, ns_tag("Computer")) or default_host

    time_created_node = system.find(ns_tag("TimeCreated")) if system is not None else None
    sys_time = time_created_node.get("SystemTime") if time_created_node is not None else None
    timestamp_str = normalize_utc_timestamp(sys_time)
    observed_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Extract EventData key-value pairs
    data_dict: Dict[str, str] = {}
    if event_data is not None:
        for data_elem in event_data.findall(ns_tag("Data")):
            name = data_elem.get("Name")
            if name:
                data_dict[name] = data_elem.text.strip() if data_elem.text else ""

    # Map Event IDs to types and severities
    event_type = EventType.UNKNOWN.value
    severity = Severity.INFORMATIONAL.value

    # Default entities
    username: Optional[str] = None
    domain: Optional[str] = None
    source_ip: Optional[str] = None
    logon_type: Optional[int] = None

    if "LogonType" in data_dict and data_dict["LogonType"].isdigit():
        logon_type = int(data_dict["LogonType"])

    raw_ip = data_dict.get("IpAddress")
    if raw_ip:
        source_ip = sanitize_ip(raw_ip)

    if event_id_num == 4624:
        # Successful Logon
        event_type = EventType.AUTHENTICATION_SUCCESS.value
        severity = Severity.LOW.value
        username = clean_string(data_dict.get("TargetUserName"))
        domain = clean_string(data_dict.get("TargetDomainName"))

    elif event_id_num == 4625:
        # Failed Logon
        event_type = EventType.AUTHENTICATION_FAILURE.value
        severity = Severity.MEDIUM.value
        username = clean_string(data_dict.get("TargetUserName"))
        domain = clean_string(data_dict.get("TargetDomainName"))

    elif event_id_num == 4672:
        # Special Privileges Assigned to Logon (Treated as privileged indicator, NOT proof of malice)
        event_type = EventType.PRIVILEGE_ESCALATION.value
        severity = Severity.INFORMATIONAL.value
        username = clean_string(data_dict.get("SubjectUserName"))
        domain = clean_string(data_dict.get("SubjectDomainName"))

    else:
        # Fallback for other Windows Security Event IDs (e.g. 4634 logoff, 4720 account created)
        if event_id_num == 4634:
            event_type = EventType.SESSION_LOGOFF.value
        elif event_id_num == 4720:
            event_type = EventType.ACCOUNT_CREATED.value
            severity = Severity.MEDIUM.value
        elif event_id_num == 4740:
            event_type = EventType.ACCOUNT_LOCKOUT.value
            severity = Severity.HIGH.value

        username = clean_string(data_dict.get("TargetUserName")) or clean_string(
            data_dict.get("SubjectUserName")
        )
        domain = clean_string(data_dict.get("TargetDomainName")) or clean_string(
            data_dict.get("SubjectDomainName")
        )

        # Fallback severity based on Windows event Level if not explicitly set by Event ID
        if event_id_num not in (4634, 4720, 4740) and level_num is not None:
            if level_num == 1:
                severity = Severity.CRITICAL.value
            elif level_num == 2:
                severity = Severity.HIGH.value
            elif level_num == 3:
                severity = Severity.MEDIUM.value
            elif level_num in (4, 0):
                severity = Severity.INFORMATIONAL.value

    channel_name = _find_text(system, ns_tag("Channel")) or "Security"
    source_type = "windows_security" if channel_name.lower() == "security" else f"windows_{channel_name.lower()}"

    metadata: Dict[str, Any] = {
        "channel": channel_name,
        "provider": provider,
        "level": level_num,
        "collector_id": collector_id,
        "domain": domain,
        "logon_type": logon_type,
        "record_number": record_number,
        "status": data_dict.get("Status"),
        "sub_status": data_dict.get("SubStatus"),
        "workstation_name": clean_string(data_dict.get("WorkstationName")),
        "logon_process": clean_string(data_dict.get("LogonProcessName")),
        "auth_package": clean_string(data_dict.get("AuthenticationPackageName")),
    }

    # Prune None metadata entries
    metadata = {k: v for k, v in metadata.items() if v is not None}

    event_id = generate_event_id(
        source_host=computer,
        source_type=source_type,
        timestamp=timestamp_str,
        raw_event=raw_clean,
        record_id=record_number,
    )

    return SecurityEvent(
        schema_version="1.0",
        event_id=event_id,
        timestamp=timestamp_str,
        observed_at=observed_at,
        source_host=computer,
        source_type=source_type,
        event_type=event_type,
        username=username,
        source_ip=source_ip,
        destination_ip=None,
        windows_event_id=event_id_num,
        severity=severity,
        raw_event=raw_clean,
        collector_version=collector_version,
        metadata=metadata,
    )
