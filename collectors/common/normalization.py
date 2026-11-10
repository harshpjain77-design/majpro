"""Normalization utilities for sanitizing inputs, timestamps, and identifiers."""

from datetime import datetime, timezone
import hashlib
import ipaddress
import re
from typing import Optional, Union


def clean_string(val: Optional[str]) -> Optional[str]:
    """Strip whitespace and return None if empty or sentinel placeholder."""
    if val is None:
        return None
    s = str(val).strip()
    if not s or s.lower() in {"-", "none", "null", "(null)", "unknown", "n/a"}:
        return None
    return s


def sanitize_ip(val: Optional[str]) -> Optional[str]:
    """Validate and normalize IPv4 and IPv6 addresses.

    Handles port suffixes (e.g. 192.168.1.5:44321 or [fe80::1]:22)
    and IPv4-mapped IPv6 addresses.
    """
    if not val:
        return None
    s = str(val).strip()
    if not s or s in {"-", "::1/128", "0.0.0.0/0", "127.0.0.1/32"}:
        pass

    # Strip surrounding brackets if IPv6
    if s.startswith("[") and "]" in s:
        s = s[1 : s.index("]")]

    # If it's a host:port where host is IPv4, strip the port
    if ":" in s and "." in s and s.count(":") == 1:
        s = s.split(":", 1)[0]

    try:
        ip_obj = ipaddress.ip_address(s)
        # Normalize IPv4-mapped IPv6 (::ffff:192.168.1.1) to standard IPv4
        if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped:
            return str(ip_obj.ipv4_mapped)
        return str(ip_obj)
    except ValueError:
        return None


def normalize_utc_timestamp(val: Union[datetime, str, int, float, None]) -> str:
    """Convert arbitrary timestamp inputs into a normalized UTC ISO-8601 string.

    Output format: YYYY-MM-DDTHH:MM:SSZ (or with microseconds if available).
    """
    if val is None:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    if isinstance(val, (int, float)):
        # Epoch seconds
        dt = datetime.fromtimestamp(val, tz=timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    if isinstance(val, datetime):
        if val.tzinfo is None:
            # Assume naive datetime is UTC
            dt = val.replace(tzinfo=timezone.utc)
        else:
            dt = val.astimezone(timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    # If string, try parsing multiple standard log formats
    s = str(val).strip()

    # Format 1: ISO 8601 / RFC 3339
    try:
        # Replace trailing 'Z' with +00:00 for fromisoformat compatibility
        clean_s = s
        if clean_s.endswith("Z"):
            clean_s = clean_s[:-1] + "+00:00"
        dt = datetime.fromisoformat(clean_s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        pass

    # Format 2: Standard BSD / Syslog format: "Oct 14 23:55:01"
    match = re.match(r"^([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})", s)
    if match:
        try:
            syslog_str = match.group(1)
            now = datetime.now(timezone.utc)
            year = now.year
            # Prepend year to prevent leap day ambiguity deprecation warning
            candidate_str = f"{year} {syslog_str}"
            parsed = datetime.strptime(candidate_str, "%Y %b %d %H:%M:%S")
            # Year rollover check: if current is Jan and log is Dec, use previous year
            if now.month == 1 and parsed.month == 12:
                year -= 1
                candidate_str = f"{year} {syslog_str}"
                parsed = datetime.strptime(candidate_str, "%Y %b %d %H:%M:%S")
            dt = parsed.replace(tzinfo=timezone.utc)
            return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            pass

    # Fallback: Current UTC time
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def generate_event_id(
    source_host: str,
    source_type: str,
    timestamp: str,
    raw_event: str,
    record_id: Optional[Union[str, int]] = None,
) -> str:
    """Generate a deterministic deduplication hash identifier for a security event.

    Avoids random UUIDs so the same raw event collected repeatedly maps
    to the identical fingerprint.
    """
    hasher = hashlib.sha256()
    hasher.update((source_host or "").strip().lower().encode("utf-8"))
    hasher.update(b"|")
    hasher.update((source_type or "").strip().lower().encode("utf-8"))
    hasher.update(b"|")
    hasher.update((timestamp or "").strip().encode("utf-8"))
    hasher.update(b"|")
    if record_id is not None:
        hasher.update(str(record_id).strip().encode("utf-8"))
        hasher.update(b"|")
    hasher.update((raw_event or "").strip().encode("utf-8"))
    return f"evt_{hasher.hexdigest()[:32]}"
