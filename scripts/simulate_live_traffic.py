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
    source_host: str = "KALI-ENDPOINT-01",
    severity: str = Severity.LOW.value,
    windows_event_id: int = 4624,
    metadata: dict = None,
) -> SecurityEvent:
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    raw = f"AUTH EVENT: {event_type} on {source_host} by {username} from {source_ip}"
    event_id = generate_event_id(
        source_host=source_host,
        source_type="linux_audit",
        timestamp=now_str,
        raw_event=raw,
    )
    meta = {"source": "threatgrid_simulator", "simulated": True}
    if metadata:
        meta.update(metadata)

    return SecurityEvent(
        schema_version="1.0",
        event_id=event_id,
        timestamp=now_str,
        observed_at=now_str,
        source_host=source_host,
        source_type="linux_audit",
        event_type=event_type,
        username=username,
        source_ip=source_ip,
        windows_event_id=windows_event_id,
        severity=severity,
        raw_event=raw,
        collector_version="0.1.0",
        metadata=meta,
    )


def simulate_brute_force(shipper: HttpEventShipper, target_user: str = "root", attacker_ip: str = "192.168.80.128"):
    """RULE-001: 6 rapid failed authentications from single source."""
    print(f"\n[ATTACK: RULE-001] Simulating SSH Brute Force against '{target_user}' from '{attacker_ip}'...")
    events: List[SecurityEvent] = []
    for i in range(6):
        ev = make_event(
            event_type=EventType.AUTHENTICATION_FAILURE.value,
            username=target_user,
            source_ip=attacker_ip,
            severity=Severity.MEDIUM.value,
        )
        events.append(ev)
        time.sleep(0.15)
    shipper.ship_batch(events)
    print(f"[OK] Shipped 6 authentication failures. Triggers RULE-001 (Repeated Failed Authentications)!")


def simulate_failed_then_success(shipper: HttpEventShipper, target_user: str = "kali", attacker_ip: str = "192.168.80.128"):
    """RULE-002: 4 failed logins followed by a successful login."""
    print(f"\n[ATTACK: RULE-002] Simulating Brute Force followed by Compromise for '{target_user}'...")
    events: List[SecurityEvent] = []
    for _ in range(4):
        events.append(
            make_event(
                event_type=EventType.AUTHENTICATION_FAILURE.value,
                username=target_user,
                source_ip=attacker_ip,
                severity=Severity.MEDIUM.value,
            )
        )
        time.sleep(0.15)
    
    # Successful login
    events.append(
        make_event(
            event_type=EventType.AUTHENTICATION_SUCCESS.value,
            username=target_user,
            source_ip=attacker_ip,
            severity=Severity.LOW.value,
        )
    )
    shipper.ship_batch(events)
    print(f"[OK] Shipped 4 failures followed by SUCCESS. Triggers RULE-002 (Potential Compromise)!")


def simulate_password_spray(shipper: HttpEventShipper, target_user: str = "admin"):
    """RULE-003: Failures against single account from 4 distinct distributed IPs."""
    ips = ["198.51.100.12", "198.51.100.34", "198.51.100.56", "198.51.100.78"]
    print(f"\n[ATTACK: RULE-003] Simulating Distributed Password Spray against '{target_user}' across 4 IPs...")
    events: List[SecurityEvent] = []
    for ip in ips:
        events.append(
            make_event(
                event_type=EventType.AUTHENTICATION_FAILURE.value,
                username=target_user,
                source_ip=ip,
                severity=Severity.MEDIUM.value,
            )
        )
        time.sleep(0.1)
    shipper.ship_batch(events)
    print(f"[OK] Shipped distributed password spray events. Triggers RULE-003 (Multi-Source Spray)!")


def simulate_privilege_escalation(shipper: HttpEventShipper, command: str = "cat /etc/shadow"):
    """RULE-004: Sensitive sudo command execution."""
    print(f"\n[ATTACK: RULE-004] Simulating Sensitive Sudo Command Execution: '{command}'...")
    ev = make_event(
        event_type=EventType.PRIVILEGE_ESCALATION.value,
        username="root",
        source_ip="192.168.80.128",
        severity=Severity.HIGH.value,
        metadata={
            "command": command,
            "invoker": "kali",
            "tty": "/dev/pts/1",
            "pwd": "/home/kali",
        },
    )
    shipper.ship_batch([ev])
    print(f"[OK] Shipped privilege escalation event. Triggers RULE-004 (Unusual Privileged Account Activity)!")


def simulate_recon_sequence(shipper: HttpEventShipper, attacker_ip: str = "192.168.80.128"):
    """RULE-005: Invalid username reconnaissance followed by targeted login."""
    print(f"\n[ATTACK: RULE-005] Simulating Username Enumeration Reconnaissance followed by Targeted Login...")
    events: List[SecurityEvent] = []
    invalid_users = ["oracle", "ftpuser", "testadmin"]
    for u in invalid_users:
        events.append(
            make_event(
                event_type=EventType.AUTHENTICATION_FAILURE.value,
                username=u,
                source_ip=attacker_ip,
                severity=Severity.LOW.value,
                metadata={"is_invalid_user": True},
            )
        )
        time.sleep(0.1)

    # Now targeted attempt against valid user
    events.append(
        make_event(
            event_type=EventType.AUTHENTICATION_FAILURE.value,
            username="kali",
            source_ip=attacker_ip,
            severity=Severity.MEDIUM.value,
            metadata={"is_invalid_user": False},
        )
    )
    shipper.ship_batch(events)
    print(f"[OK] Shipped recon sequence events. Triggers RULE-005 (Invalid User Recon to Target)!")


def simulate_full_kill_chain(shipper: HttpEventShipper):
    """Full Attack Kill-Chain: Recon -> Brute Force -> Breach -> Root Escalation."""
    print(f"\n[KILL-CHAIN] Launching Multi-Stage APT Attack Simulation...")
    print("Stage 1: Reconnaissance / Enumeration")
    simulate_recon_sequence(shipper)
    time.sleep(1)

    print("Stage 2: Brute Force & Credential Compromise")
    simulate_failed_then_success(shipper)
    time.sleep(1)

    print("Stage 3: Credential Dumping / Shadow File Access")
    simulate_privilege_escalation(shipper, "cat /etc/shadow")
    print(f"\n[CRITICAL] Full Kill-Chain Deployed! Check the Incident Queue for Correlated Incident Dossier.")


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
        )
        shipper.ship_batch([ev])
        print(f"  -> Ingested successful login for {user}@{host} ({ip})")
        time.sleep(0.5)


def main():
    parser = argparse.ArgumentParser(description="ThreadGrid Live SOC Event & Attack Simulator")
    parser.add_argument(
        "--mode",
        choices=[
            "brute-force",
            "compromise",
            "spray",
            "privilege",
            "recon",
            "kill-chain",
            "benign",
            "continuous",
        ],
        default="kill-chain",
        help="Attack scenario to simulate",
    )
    parser.add_argument("--api-url", default="http://127.0.0.1:8000/api/v1/ingest")
    parser.add_argument("--api-key", default="test-collector-api-key-replace-in-production")
    parser.add_argument("--interval", type=int, default=3)
    args = parser.parse_args()

    shipper = HttpEventShipper(api_url=args.api_url, api_key=args.api_key)

    if args.mode == "brute-force":
        simulate_brute_force(shipper)
    elif args.mode == "compromise":
        simulate_failed_then_success(shipper)
    elif args.mode == "spray":
        simulate_password_spray(shipper)
    elif args.mode == "privilege":
        simulate_privilege_escalation(shipper)
    elif args.mode == "recon":
        simulate_recon_sequence(shipper)
    elif args.mode == "kill-chain":
        simulate_full_kill_chain(shipper)
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
