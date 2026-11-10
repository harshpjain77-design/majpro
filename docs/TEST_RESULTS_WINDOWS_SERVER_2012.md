# Test Results: Real Windows Server 2012 Telemetry Ingestion

**Document Version:** 1.0  
**Test Date:** 2026-10-15  
**Platform:** AI Cyber Defense Platform (Academic Research Prototype)

---

## 1. Environment Specifications

| Component | Value | Notes |
| :--- | :--- | :--- |
| **SIEM Host OS** | Windows 11 Build 26300 (AMD64) | Running FastAPI Ingestion Backend & React SOC Dashboard |
| **SIEM Host VMware Adapter** | `VMware Network Adapter VMnet1` | Host-only virtual switch |
| **SIEM Host IP** | `192.168.203.1` | Netmask `255.255.255.0` |
| **SIEM Host Port** | `8000` | FastAPI listening on `0.0.0.0:8000` |
| **Windows Server 2012 VM IP** | `192.168.203.10` | Netmask `255.255.255.0` (VMware VMnet1) |
| **Collector Implementations** | `collectors/windows/collector.py`<br>`collectors/windows/collector.ps1` | Python 3.8+ collector (with urllib fallback) & native PowerShell 3.0+ collector |
| **Collector Agent ID** | `windows-server-2012` | Specified via `COLLECTOR_ID` or `--collector-id` |
| **Central Ingestion Endpoint**| `POST http://192.168.203.1:8000/api/v1/ingest/batch` | Authenticated via `X-API-Key` |
| **Event Database** | `output/soc_events.sqlite` | SQLite in Write-Ahead Logging (WAL) mode |

---

## 2. Test Execution & Verification Matrix

| Test Item | Status | Verification Details |
| :--- | :--- | :--- |
| **1. TCP Connectivity** | **PASS** | `Test-NetConnection 192.168.203.1 -Port 8000` verified from Windows Server 2012 (`TcpTestSucceeded: True`). FastAPI successfully bound to `0.0.0.0:8000`. |
| **2. Collector Startup** | **PASS** | Both `collectors/windows/collector.py` and native PowerShell `collector.ps1` start cleanly, discover environment, and read configuration. |
| **3. Windows Event Log Access** | **PASS** | Access to native Windows Event subsystem verified. When run with Administrator privileges, accesses `Security` channel. When un-elevated, gracefully falls back to `System` channel without dying. |
| **4. Event Shipping** | **PASS** | Batches containing canonical `SecurityEvent` v1.0 schemas transmitted over HTTP to `http://192.168.203.1:8000/api/v1/ingest/batch` with `X-API-Key` and `X-Agent-ID: windows-server-2012`. |
| **5. Database Insertion** | **PASS** | HTTP 200 response returned (`ingested_count: 1`). Record persisted to `output/soc_events.sqlite` with full XML, timestamp, host, and metadata. |
| **6. Dashboard Display** | **PASS** | Querying `GET /api/v1/events?host=WIN-SRV-2012` retrieves the event with `collector_id: windows-server-2012`. Event is visible in React UI at `http://localhost:3000`. |
| **7. Checkpoint Behavior** | **PASS** | Atomic write to `checkpoint_windows.json` records highest `last_record_number`. On restart, collector resumes tailing without backfilling historical events. |
| **8. Duplicate Prevention** | **PASS** | Re-transmitting the identical event yielded `ingested_count: 0, duplicate_count: 1`. SHA-256 fingerprinting successfully prevented storage duplication. |
| **9. Detection Compatibility** | **PARTIAL** | Core authentication and privilege escalation rules operate directly on real event IDs (4624, 4625, 4672). Lateral movement rule is partially supported as it requires >= 3 distinct host streams. |

---

## 3. Detection Rule Compatibility Analysis

| Rule ID | Rule Name | Compatibility | Justification |
| :--- | :--- | :--- | :--- |
| **RULE-001** | Authentication Brute Force | **SUPPORTED** | Real Windows Security Event ID 4625 produces normalized `authentication_failure` with target `username` and caller `source_ip`. Windowed threshold (>= 5 failures / 60s) executes cleanly. |
| **RULE-002** | Failed Followed by Success | **SUPPORTED** | Evaluates sequence of 4625 failures followed by 4624 logon for identical username within the configured time window. |
| **RULE-003** | Distributed Password Spray | **SUPPORTED** | Evaluates multiple 4625 events from a single `source_ip` attempting > 3 distinct usernames. |
| **RULE-004** | Off-Hours Admin Activity | **SUPPORTED** | Evaluates 4672 (Special Privileges Assigned) and administrative logons during configured off-hours (22:00 - 06:00 UTC). |
| **RULE-005** | Lateral Movement | **PARTIALLY SUPPORTED** | Requires authentication attempts for a single account across $\ge 3$ distinct host entities within 5 minutes. Works once additional telemetry sources (e.g. Linux, Windows 7, domain controllers) are concurrently ingesting. |

---

## 4. Exact Commands to Execute on Windows Server 2012

### Option A: Native PowerShell Collector (Recommended — Zero Extra Dependencies)

Open PowerShell (**Run as Administrator**) on Windows Server 2012 and run:

```powershell
# 1. Download the updated collector script directly from the SIEM host:
(New-Object System.Net.WebClient).DownloadFile("http://192.168.203.1:8000/collector.ps1", "C:\collector.ps1")

# 2. Reset any previous checkpoint so historical events are immediately ingested:
Remove-Item C:\checkpoint_windows.json -ErrorAction SilentlyContinue

# 3. Start live continuous collection across All channels (Security, System, Application):
powershell -ExecutionPolicy Bypass -File C:\collector.ps1 -Channel "All" -Interval 3 -Lookback 50
```

### Option B: Python Windows Collector (If Python 3.8+ is installed on the VM)

```powershell
# Set environment variables
$env:SIEM_INGEST_URL = "http://192.168.203.1:8000/api/v1/ingest/batch"
$env:INGESTION_API_KEY = "test-collector-api-key-replace-in-production"
$env:COLLECTOR_ID = "windows-server-2012"

# Single verification pass:
python -m collectors.windows.collector --once --ship --api-url http://192.168.203.1:8000/api/v1/ingest/batch

# Continuous background tailing:
python -m collectors.windows.collector --interval 5 --ship --api-url http://192.168.203.1:8000/api/v1/ingest/batch
```

---

## 5. Current Limitations & Next Steps

1. **Host-to-Server Ping**: Windows Server 2012 ICMP Echo Request is blocked by default Windows Server Firewall profile. This has zero impact on HTTP ingestion because all telemetry flows outbound from Server 2012 to the SIEM Host.
2. **Security Channel DACL**: On Windows Server 2012, reading `Security` (IDs 4624/4625) requires running the collector under an elevated command prompt (`Run as administrator`) or adding the collector service account to `Event Log Readers`. If unprivileged, the collector automatically falls back to `System` channel.
3. **Multi-Source Lateral Movement**: Testing RULE-005 end-to-end requires connecting additional telemetry sources (e.g. Linux workstation, second Windows client) to trigger multi-host correlation.
