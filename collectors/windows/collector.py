"""Windows Security Event Log collector using native Windows Event Log API."""

import argparse
import json
import logging
import os
from pathlib import Path
import platform
import socket
import sys
import time
from typing import Any, Dict, Generator, List, Optional

from collectors.common.schemas import SecurityEvent
from collectors.common.shipper import HttpEventShipper
from collectors.windows.checkpoint import WindowsCheckpoint
from collectors.windows.parsers import parse_windows_event_xml

logger = logging.getLogger("WindowsCollector")

# Platform-isolated import
try:
    import win32evtlog  # type: ignore
    import win32con  # type: ignore

    HAS_WIN32 = True
except ImportError:
    HAS_WIN32 = False
    win32evtlog = None
    win32con = None


class WindowsSecurityCollector:
    """Collects security events from native Windows Event Log channels."""

    def __init__(
        self,
        channel: str = "Security",
        checkpoint_path: str = "checkpoint_windows.json",
        output_path: Optional[str] = None,
        initial_read_policy: str = "latest",  # "latest" or "all"
        max_batch_size: int = 100,
        collector_version: str = "0.1.0",
        collector_id: Optional[str] = None,
        host_override: Optional[str] = None,
        shipper: Optional[HttpEventShipper] = None,
        auto_fallback: bool = True,
    ):
        self.channel = channel
        self.collector_version = collector_version
        self.collector_id = collector_id or os.getenv("COLLECTOR_ID", "windows-server-2012")
        self.host = host_override or socket.gethostname()
        self.checkpoint = WindowsCheckpoint(checkpoint_path)
        self.output_path = Path(output_path) if output_path else None
        self.initial_read_policy = initial_read_policy.lower()
        self.max_batch_size = max_batch_size
        self.shipper = shipper
        self.auto_fallback = auto_fallback

        if self.output_path:
            self.output_path.parent.mkdir(parents=True, exist_ok=True)

    def discover_environment(self) -> Dict[str, Any]:
        """Discover and document the host/server operating system version and privileges."""
        info: Dict[str, Any] = {
            "platform": platform.platform(),
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "architecture": platform.machine(),
            "hostname": self.host,
            "pywin32_available": HAS_WIN32,
            "windows_version_detail": None,
            "security_log_accessible": False,
            "access_error": None,
        }

        if sys.platform == "win32":
            win_ver = sys.getwindowsversion()
            info["windows_version_detail"] = {
                "major": win_ver.major,
                "minor": win_ver.minor,
                "build": win_ver.build,
                "platform": win_ver.platform,
                "service_pack": win_ver.service_pack,
            }

            if HAS_WIN32:
                try:
                    # Test whether Security log can be opened
                    h = win32evtlog.EvtQuery(
                        self.channel,
                        win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryForwardDirection,
                        Query="*",
                    )
                    info["security_log_accessible"] = True
                except Exception as e:
                    info["access_error"] = str(e)

        return info

    def build_query_filter(self, start_record: Optional[int] = None) -> str:
        """Construct XPath query filter for targeted events."""
        if self.channel.lower() == "security":
            id_filter = "(System/EventID=4624 or System/EventID=4625 or System/EventID=4672)"
            if start_record and start_record > 0:
                return f"*[System[{id_filter} and EventRecordID > {start_record}]]"
            return f"*[System[{id_filter}]]"
        else:
            if start_record and start_record > 0:
                return f"*[System[EventRecordID > {start_record}]]"
            return "*"

    def read_events(self) -> Generator[SecurityEvent, None, None]:
        """Read Security events from the Windows Event Log using EvtQuery."""
        if not HAS_WIN32:
            logger.info("pywin32 is not installed. Using native Windows wevtutil fallback.")
            yield from self._read_events_wevtutil()
            return

        last_record = self.checkpoint.get_last_record_number()

        # Handle initial startup policy
        if last_record == 0 and self.initial_read_policy == "latest":
            # Start from the current latest record to avoid dumping thousands of historical events
            try:
                rev_query = (
                    "*[System[(System/EventID=4624 or System/EventID=4625 or System/EventID=4672)]]"
                    if self.channel.lower() == "security"
                    else "*"
                )
                h_rev = win32evtlog.EvtQuery(
                    self.channel,
                    win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection,
                    Query=rev_query,
                )
                recent_events = win32evtlog.EvtNext(h_rev, 1)
                if recent_events:
                    xml_str = win32evtlog.EvtRender(recent_events[0], win32evtlog.EvtRenderEventXml)
                    parsed = parse_windows_event_xml(
                        xml_str,
                        default_host=self.host,
                        collector_version=self.collector_version,
                        collector_id=self.collector_id,
                    )
                    if parsed and parsed.metadata.get("record_number"):
                        last_record = parsed.metadata["record_number"]
                        logger.info(
                            f"Initial policy 'latest': Starting event tailing on '{self.channel}' from record {last_record}."
                        )
                        self.checkpoint.update_record(last_record)
            except Exception as e:
                logger.warning(f"Could not determine latest record number on '{self.channel}': {e}")

        xpath = self.build_query_filter(start_record=last_record)
        logger.debug(f"Executing EvtQuery on channel '{self.channel}' with XPath: {xpath}")

        try:
            h_query = win32evtlog.EvtQuery(
                self.channel,
                win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryForwardDirection,
                Query=xpath,
            )
        except Exception as e:
            if self.channel.lower() == "security" and self.auto_fallback:
                logger.warning(
                    f"Access denied querying Windows 'Security' log: {e}. "
                    "Reading Security log requires Administrator privileges or membership in 'Event Log Readers' group. "
                    "Automatically falling back to 'System' channel to capture live host OS events."
                )
                self.channel = "System"
                self.checkpoint.update_record(0)
                yield from self.read_events()
                return
            else:
                logger.error(
                    f"Failed to query Windows Event Log '{self.channel}': {e}. Ensure process user is in 'Event Log Readers' group or run as Administrator."
                )
                return

        max_seen_record = last_record

        while True:
            try:
                events = win32evtlog.EvtNext(h_query, self.max_batch_size)
            except Exception as e:
                logger.error(f"Error fetching next event batch: {e}")
                break

            if not events:
                break

            for h_event in events:
                try:
                    xml_str = win32evtlog.EvtRender(h_event, win32evtlog.EvtRenderEventXml)
                    parsed_event = parse_windows_event_xml(
                        xml_str,
                        default_host=self.host,
                        collector_version=self.collector_version,
                        collector_id=self.collector_id,
                    )
                    if parsed_event:
                        rec_num = parsed_event.metadata.get("record_number")
                        if rec_num and rec_num > max_seen_record:
                            max_seen_record = rec_num
                        yield parsed_event
                except Exception as ex:
                    logger.warning(f"Failed to render or parse individual event: {ex}")

        if max_seen_record > last_record:
            self.checkpoint.update_record(max_seen_record)

    def _read_events_wevtutil(self) -> Generator[SecurityEvent, None, None]:
        """Read events using Windows built-in wevtutil.exe when pywin32 is not installed."""
        import subprocess
        import xml.etree.ElementTree as ET

        last_record = self.checkpoint.get_last_record_number()
        query = self.build_query_filter(start_record=last_record)
        cmd = [
            "wevtutil.exe",
            "qe",
            self.channel,
            f"/q:{query}",
            f"/c:{self.max_batch_size}",
            "/f:xml",
        ]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
            if proc.returncode != 0:
                if self.channel.lower() == "security" and self.auto_fallback:
                    logger.warning(
                        "Access denied to 'Security' channel via wevtutil. Falling back to 'System' channel."
                    )
                    self.channel = "System"
                    self.checkpoint.update_record(0)
                    yield from self.read_events()
                else:
                    logger.error(f"wevtutil query failed: {proc.stderr.strip()}")
                return

            xml_output = proc.stdout.strip()
            if not xml_output:
                return

            wrapped = f"<Events>{xml_output}</Events>"
            try:
                root = ET.fromstring(wrapped)
            except Exception as e:
                logger.error(f"Failed to parse wevtutil XML stream: {e}")
                return

            max_seen = last_record
            for elem in root:
                event_xml = ET.tostring(elem, encoding="unicode")
                parsed = parse_windows_event_xml(
                    event_xml,
                    default_host=self.host,
                    collector_version=self.collector_version,
                    collector_id=self.collector_id,
                )
                if parsed:
                    rec = parsed.metadata.get("record_number")
                    if rec and rec > max_seen:
                        max_seen = rec
                    yield parsed

            if max_seen > last_record:
                self.checkpoint.update_record(max_seen)
        except Exception as e:
            logger.error(f"Error executing wevtutil: {e}")

    def collect(self) -> List[SecurityEvent]:
        """Execute a single collection pass and return parsed SecurityEvents."""
        events: List[SecurityEvent] = []
        for ev in self.read_events():
            events.append(ev)

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

    default_api_url = os.getenv("SIEM_INGEST_URL") or os.getenv(
        "INGESTION_API_URL", "http://192.168.203.1:8000/api/v1/ingest/batch"
    )
    default_collector_id = os.getenv("COLLECTOR_ID", "windows-server-2012")

    parser = argparse.ArgumentParser(description="Windows Security Event Log Collector")
    parser.add_argument("--config", help="Path to JSON configuration file")
    parser.add_argument("--channel", default="Security", help="Event log channel name")
    parser.add_argument("--checkpoint", default="checkpoint_windows.json", help="Checkpoint file path")
    parser.add_argument("--output", help="Output JSONL destination file")
    parser.add_argument("--policy", choices=["latest", "all"], default="latest", help="Initial collection policy")
    parser.add_argument("--once", action="store_true", help="Run single collection and exit")
    parser.add_argument("--interval", type=int, default=5, help="Poll interval in seconds")
    parser.add_argument("--check-env", action="store_true", help="Print detected OS environment and exit")
    parser.add_argument("--ship", action="store_true", help="Ship events to central ingestion API")
    parser.add_argument(
        "--collector-id",
        default=default_collector_id,
        help="Collector identification string",
    )
    parser.add_argument(
        "--api-url",
        default=default_api_url,
        help="Central ingestion API URL (or set SIEM_INGEST_URL)",
    )
    parser.add_argument(
        "--api-key",
        default=os.getenv("INGESTION_API_KEY", "test-collector-api-key-replace-in-production"),
        help="API authentication key",
    )
    parser.add_argument(
        "--no-fallback",
        action="store_true",
        help="Disable automatic fallback to System channel if Security log access is denied",
    )

    args = parser.parse_args()

    # Load configuration file if specified
    config = {}
    if args.config and os.path.exists(args.config):
        with open(args.config, "r", encoding="utf-8") as cf:
            config = json.load(cf)

    channel = args.channel or config.get("channel", "Security")
    checkpoint_path = args.checkpoint or config.get("checkpoint_path", "checkpoint_windows.json")
    output_path = args.output or config.get("output_path", "output/events_windows.jsonl")
    policy = args.policy or config.get("initial_read_policy", "latest")
    collector_id = args.collector_id or config.get("collector_id", default_collector_id)

    shipper = None
    if args.ship or config.get("ship_events", False):
        api_url = args.api_url or config.get("api_url", default_api_url)
        api_key = args.api_key or config.get("api_key", "test-collector-api-key-replace-in-production")
        shipper = HttpEventShipper(
            api_url=api_url,
            api_key=api_key,
            agent_id=collector_id,
            collector_version="0.1.0",
        )

    collector = WindowsSecurityCollector(
        channel=channel,
        checkpoint_path=checkpoint_path,
        output_path=output_path,
        initial_read_policy=policy,
        collector_id=collector_id,
        shipper=shipper,
        auto_fallback=not args.no_fallback,
    )

    if args.check_env:
        env_info = collector.discover_environment()
        print(json.dumps(env_info, indent=2))
        sys.exit(0)

    logger.info(
        f"Starting Windows Collector '{collector_id}' on channel '{channel}' (policy={policy}, ship={shipper is not None})"
    )

    if args.once:
        events = collector.collect()
        logger.info(f"Single run completed. Collected {len(events)} event(s).")
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
