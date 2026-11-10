"""Live traffic and attack scenario generator for testing SOC detection and response in real-time."""

import argparse
from datetime import datetime, timezone
from pathlib import Path
import random
import sys
import time
from typing import List

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from collectors.common.normalization import generate_event_id
from collectors.common.schemas import EventType, SecurityEvent, Severity
from collectors.common.shipper import HttpEventShipper


def make_event(
    event_type: str,
    username: str,
    source_ip: str,
    source_host: str = "WORKSTATION-01",
    severity: str = Severity.LOW.value,
    windows_event_id: int = 4624,
) -> SecurityEvent:
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    raw = f"<Event><System><EventID>{windows_event_id}</EventID><TimeCreated SystemTime='{now_str}'/><Computer>{source_host}</Computer></System><EventData><Data Name='TargetUserName'>{username}</Data><Data Name='IpAddress'>{source_ip}</Data></EventData></Event>"
    event_id = generate_event_id(
        source_host=source_host,
        source_type="windows_security",
        timestamp=now_str,
        raw_event=raw,
    )
    return SecurityEvent(
        schema_version="1.0",
        event_id=event_id,
        timestamp=now_str,
        observed_at=now_str,
        source_host=source_host,
        source_type="windows_security",
        event_type=event_type,
        username=username,
        source_ip=source_ip,
        windows_event_id=windows_event_id,
        severity=severity,
        raw_event=raw,
        collector_version="0.1.0",
        metadata={"channel": "Security", "simulated": True},
    )


def simulate_brute_force(shipper: HttpEventShipper, target_user: str = "secadmin", attacker_ip: str = "203.0.113.55"):
    print(f"\n[ATTACK] Simulating Brute Force (RULE-001) against user '{target_user}' from IP '{attacker_ip}'...")
    events: List[SecurityEvent] = []
    for i in range(6):
        ev = make_event(
            event_type=EventType.AUTHENTICATION_FAILURE.value,
            username=target_user,
            source_ip=attacker_ip,
            severity=Severity.MEDIUM.value,
            windows_event_id=4625,
        )
        events.append(ev)
        time.sleep(0.2)
    shipper.ship_batch(events)
    print(f"[OK] Shipped 6 failed logon events in rapid succession. Check Incidents & Alerts in dashboard!")


def simulate_benign_traffic(shipper: HttpEventShipper, count: int = 5):
    users = ["alice", "bob", "carol", "david", "elena"]
    hosts = ["HR-LAPTOP", "FINANCE-PC", "DEV-WORKSTATION", "CORP-DESK-01"]
    ips = ["192.168.1.101", "192.168.1.102", "192.168.1.103", "192.168.1.104"]

    print(f"\n[STREAM] Streaming {count} normal authentication events...")
    for _ in range(count):
        user = random.choice(users)
        host = random.choice(hosts)
        ip = random.choice(ips)
        ev = make_event(
            event_type=EventType.AUTHENTICATION_SUCCESS.value,
            username=user,
            source_ip=ip,
            source_host=host,
            severity=Severity.LOW.value,
            windows_event_id=4624,
        )
        shipper.ship_batch([ev])
        print(f"  -> Ingested successful login for {user}@{host} ({ip})")
        time.sleep(1)


def main():
    parser = argparse.ArgumentParser(description="Live SOC Event Simulator")
    parser.add_argument("--mode", choices=["benign", "brute-force", "continuous"], default="brute-force")
    parser.add_argument("--api-url", default="http://127.0.0.1:8000/api/v1/ingest/batch")
    parser.add_argument("--api-key", default="test-collector-api-key-replace-in-production")
    parser.add_argument("--interval", type=int, default=3)
    args = parser.parse_args()

    shipper = HttpEventShipper(api_url=args.api_url, api_key=args.api_key)

    if args.mode == "brute-force":
        simulate_brute_force(shipper)
    elif args.mode == "benign":
        simulate_benign_traffic(shipper, count=10)
    elif args.mode == "continuous":
        print(f"[STREAM] Continuous live traffic generation running every {args.interval}s. Press Ctrl+C to stop.")
        try:
            while True:
                simulate_benign_traffic(shipper, count=2)
                time.sleep(args.interval)
        except KeyboardInterrupt:
            print("\nStopped.")


if __name__ == "__main__":
    main()
