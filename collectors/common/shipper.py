"""HTTP client for shipping normalized events to the Central Ingestion API."""

import logging
from typing import List, Optional
try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False

import json
import urllib.error
import urllib.request

from collectors.common.schemas import SecurityEvent

logger = logging.getLogger("EventShipper")


class HttpEventShipper:
    """Transmits normalized events to the Central Ingestion API over authenticated HTTP/HTTPS."""

    def __init__(
        self,
        api_url: str = "http://127.0.0.1:8000/api/v1/ingest/batch",
        api_key: str = "test-collector-api-key-replace-in-production",
        agent_id: str = "collector-agent",
        collector_version: str = "0.1.0",
        timeout_seconds: float = 10.0,
    ):
        self.api_url = api_url.rstrip("/")
        if not self.api_url.endswith("/batch"):
            if self.api_url.endswith("/ingest"):
                self.api_url += "/batch"
            else:
                self.api_url += "/api/v1/ingest/batch"

        self.api_key = api_key
        self.agent_id = agent_id
        self.collector_version = collector_version
        self.timeout = timeout_seconds

    def ship_batch(self, events: List[SecurityEvent]) -> Optional[dict]:
        """Send a batch of events to the ingestion API."""
        if not events:
            return None

        headers = {
            "X-API-Key": self.api_key,
            "X-Agent-ID": self.agent_id,
            "X-Agent-Version": self.collector_version,
            "Content-Type": "application/json",
        }

        payload = {
            "events": [
                e.model_dump(mode="json")
                if hasattr(e, "model_dump")
                else e.dict()
                if hasattr(e, "dict")
                else e
                for e in events
            ],
            "agent_id": self.agent_id,
            "collector_version": self.collector_version,
        }

        if HAS_HTTPX:
            try:
                with httpx.Client(timeout=self.timeout) as client:
                    response = client.post(self.api_url, json=payload, headers=headers)
                    if response.status_code == 200:
                        data = response.json()
                        logger.info(
                            f"Successfully shipped {len(events)} events. "
                            f"Ingested: {data.get('ingested_count')}, Duplicates: {data.get('duplicate_count')}"
                        )
                        return data
                    else:
                        logger.error(
                            f"Failed to ship events: HTTP {response.status_code} - {response.text}"
                        )
                        return None
            except httpx.RequestError as e:
                logger.error(f"Network error connecting to Ingestion API at {self.api_url}: {e}")
                return None
        else:
            try:
                req_data = json.dumps(payload).encode("utf-8")
                req = urllib.request.Request(
                    self.api_url, data=req_data, headers=headers, method="POST"
                )
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    resp_body = resp.read().decode("utf-8")
                    data = json.loads(resp_body)
                    logger.info(
                        f"Successfully shipped {len(events)} events via urllib. "
                        f"Ingested: {data.get('ingested_count')}, Duplicates: {data.get('duplicate_count')}"
                    )
                    return data
            except urllib.error.HTTPError as e:
                err_text = e.read().decode("utf-8") if e.fp else str(e)
                logger.error(f"Failed to ship events: HTTP {e.code} - {err_text}")
                return None
            except urllib.error.URLError as e:
                logger.error(f"Network error connecting to Ingestion API at {self.api_url}: {e}")
                return None
