"""Kali / Debian Linux security log collector agent."""

import argparse
import json
import logging
import os
from pathlib import Path
import platform
import socket
import sys
import time
from typing import Generator, List, Optional

from collectors.common.schemas import SecurityEvent
from collectors.common.shipper import HttpEventShipper
from collectors.linux.checkpoint import LinuxCheckpoint
from collectors.linux.parsers import parse_journal_entry, parse_linux_auth_line

logger = logging.getLogger("LinuxCollector")


class LinuxAuthCollector:
    """Collects, normalizes, and emits Linux authentication events with durable checkpointing."""

    DEFAULT_AUTH_LOGS = [
        "/var/log/auth.log",  # Debian, Ubuntu, Kali Linux
        "/var/log/secure",  # RHEL, CentOS, Fedora
    ]

    def __init__(
        self,
        log_path: Optional[str] = None,
        checkpoint_path: str = "checkpoint_linux.json",
        output_path: Optional[str] = None,
        use_journal: bool = False,
        collector_version: str = "0.1.0",
        host_override: Optional[str] = None,
        shipper: Optional[HttpEventShipper] = None,
    ):
        self.collector_version = collector_version
        self.host = host_override or socket.gethostname()
        self.checkpoint = LinuxCheckpoint(checkpoint_path)
        self.output_path = Path(output_path) if output_path else None
        self.use_journal = use_journal
        self.log_path = self._resolve_log_path(log_path) if not use_journal else None
        self.shipper = shipper

        if self.output_path:
            self.output_path.parent.mkdir(parents=True, exist_ok=True)

    def _resolve_log_path(self, explicit_path: Optional[str]) -> Optional[str]:
        if explicit_path:
            return explicit_path
        for candidate in self.DEFAULT_AUTH_LOGS:
            if os.path.exists(candidate):
                return candidate
        return None

    def detect_environment(self) -> dict:
        """Report detected logging configuration and accessibility status."""
        status = {
            "os": platform.system(),
            "release": platform.release(),
            "hostname": self.host,
            "auth_log_found": False,
            "auth_log_path": self.log_path,
            "auth_log_readable": False,
            "journalctl_available": False,
        }

        if self.log_path and os.path.exists(self.log_path):
            status["auth_log_found"] = True
            status["auth_log_readable"] = os.access(self.log_path, os.R_OK)

        # Check journalctl binary availability
        import shutil

        if shutil.which("journalctl") is not None:
            status["journalctl_available"] = True

        return status

    def read_file_events(self) -> Generator[SecurityEvent, None, None]:
        """Read newly appended lines from log file, handling rotation and truncation."""
        if not self.log_path or not os.path.exists(self.log_path):
            logger.warning(
                f"Log file {self.log_path} does not exist. Check file path or run as member of 'adm' group."
            )
            return

        if not os.access(self.log_path, os.R_OK):
            logger.error(
                f"Permission denied reading {self.log_path}. Add user to 'adm' group: sudo usermod -aG adm $USER"
            )
            return

        stat = os.stat(self.log_path)
        current_inode = stat.st_ino
        current_size = stat.st_size

        offset = self.checkpoint.get_offset()
        if self.checkpoint.is_rotated_or_truncated(current_inode, current_size):
            logger.info("Log rotation or truncation detected. Resetting file read offset to 0.")
            offset = 0

        with open(self.log_path, "r", encoding="utf-8", errors="replace") as f:
            f.seek(offset)
            while True:
                line = f.readline()
                if not line:
                    break
                event = parse_linux_auth_line(
                    raw_line=line,
                    default_host=self.host,
                    collector_version=self.collector_version,
                )
                if event:
                    yield event

            new_offset = f.tell()
            self.checkpoint.update_file_position(
                file_path=self.log_path,
                inode=current_inode,
                offset=new_offset,
                file_size=current_size,
            )

    def read_journal_events(self, max_records: int = 100) -> Generator[SecurityEvent, None, None]:
        """Stream events using systemd journalctl JSON output format."""
        import shutil
        import subprocess

        if shutil.which("journalctl") is None:
            logger.warning("journalctl command not found on this system.")
            return

        cursor = self.checkpoint.get_journal_cursor()
        cmd = ["journalctl", "-u", "ssh.service", "-o", "json", "-n", str(max_records)]
        if cursor:
            cmd.extend(["--after-cursor", cursor])

        try:
            res = subprocess.run(cmd, capture_output=True, text=True, check=False)
            if res.returncode != 0:
                logger.error(f"journalctl error (code {res.returncode}): {res.stderr.strip()}")
                return

            last_cursor = cursor
            for line in res.stdout.splitlines():
                if not line.strip():
                    continue
                try:
                    entry = json.loads(line)
                    event = parse_journal_entry(
                        entry=entry,
                        default_host=self.host,
                        collector_version=self.collector_version,
                    )
                    if event:
                        yield event
                    if "__CURSOR" in entry:
                        last_cursor = entry["__CURSOR"]
                except json.JSONDecodeError:
                    continue

            if last_cursor and last_cursor != cursor:
                self.checkpoint.update_journal_cursor(last_cursor)
        except Exception as e:
            logger.error(f"Error executing journalctl: {e}")

    def collect(self) -> List[SecurityEvent]:
        """Execute a collection run and return collected SecurityEvent objects."""
        events: List[SecurityEvent] = []
        if self.use_journal:
            events.extend(self.read_journal_events())
        else:
            events.extend(self.read_file_events())

        if self.output_path and events:
            with open(self.output_path, "a", encoding="utf-8") as out:
                for ev in events:
                    out.write(ev.to_jsonl() + "\n")

        if self.shipper and events:
            self.shipper.ship_batch(events)

        return events


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    parser = argparse.ArgumentParser(description="Kali Linux Auth Log Collector")
    parser.add_argument("--config", help="Path to JSON configuration file")
    parser.add_argument("--file", help="Path to auth.log file to tail")
    parser.add_argument("--journal", action="store_true", help="Ingest from systemd journald")
    parser.add_argument("--checkpoint", default="checkpoint_linux.json", help="Checkpoint file path")
    parser.add_argument("--output", help="Output JSONL destination file")
    parser.add_argument("--api-url", help="Central SIEM Ingestion API URL (e.g. http://192.168.80.1:8000/api/v1/events/batch)")
    parser.add_argument("--api-key", default="test-collector-api-key-replace-in-production", help="Collector API key")
    parser.add_argument("--once", action="store_true", help="Run single collection and exit")
    parser.add_argument("--interval", type=int, default=5, help="Poll interval in seconds")
    parser.add_argument("--check-env", action="store_true", help="Print detected logging environment and exit")

    args = parser.parse_args()

    # Load configuration file if specified
    config = {}
    if args.config and os.path.exists(args.config):
        with open(args.config, "r", encoding="utf-8") as cf:
            config = json.load(cf)

    log_path = args.file or config.get("file_path")
    use_journal = args.journal or config.get("use_journal", False)
    checkpoint_path = args.checkpoint or config.get("checkpoint_path", "checkpoint_linux.json")
    output_path = args.output or config.get("output_path", "output/events_linux.jsonl")
    api_url = args.api_url or config.get("api_url")
    api_key = args.api_key or config.get("api_key", "test-collector-api-key-replace-in-production")

    shipper = None
    if api_url:
        shipper = HttpEventShipper(
            api_url=api_url,
            api_key=api_key,
            agent_id="kali-collector-agent",
        )

    collector = LinuxAuthCollector(
        log_path=log_path,
        checkpoint_path=checkpoint_path,
        output_path=output_path,
        use_journal=use_journal,
        shipper=shipper,
    )

    if args.check_env:
        status = collector.detect_environment()
        print(json.dumps(status, indent=2))
        sys.exit(0)

    logger.info(f"Starting Linux Collector (journal={use_journal}, target={collector.log_path})")

    if args.once:
        collected = collector.collect()
        logger.info(f"Single run completed. Collected {len(collected)} event(s).")
    else:
        try:
            while True:
                events = collector.collect()
                if events:
                    logger.info(f"Collected {len(events)} event(s).")
                time.sleep(args.interval)
        except KeyboardInterrupt:
            logger.info("Collector stopped by operator.")


if __name__ == "__main__":
    main()
