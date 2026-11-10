# PROJECT_SPEC.md — System Specification & Intended Architecture

## 1. Project Title
**AI Cyber Defense Platform: A SOC with Intelligent Threat Detection & Automated Response**

## 2. Research Objective & Nature of the Project
This project is an academic research prototype, not a direct competitor or enterprise replacement for established commercial SIEMs such as Splunk.
**Central Research Hypothesis**:
Combining explainable anomaly detection, deterministic rule-based correlation, alert deduplication, and evidence-grounded AI assistance significantly reduces security analyst investigation time and alert fatigue without unacceptable degradation of threat detection recall and precision.

## 3. High-Level Architecture Pipeline
The end-to-end platform is structured into modular, independently testable stages:
```
[ Log Sources (Kali Linux, Windows Server, Syslog) ]
                          │
                          ▼
             [ Custom Python Collectors ]
   (auth.log/journald tailing, WinEventLog native API)
                          │
                          ▼
              [ Event Normalization ]
         (Canonical JSON Schema v1.0, UTC)
                          │
                          ▼
            [ Authenticated Ingestion API ]
       (FastAPI, bearer token, rate-limited)
                          │
                          ▼
           [ Validation & Deduplication ]
     (Content hashing, source-specific keys)
                          │
                          ▼
              [ Storage & Indexing ]
        (SQLite / PostgreSQL, query engine)
                          │
                          ▼
  [ Rule Detection ] ──► [ ML Anomaly Detection ]
   (Brute-force, Spray,     (Isolation Forest,
    Privilege Escalation)    Time-window behavioral)
                          │
                          ▼
        [ Alert Deduplication & Correlation ]
      (Fingerprinting, temporal clustering, entity graphs)
                          │
                          ▼
        [ Incident Management & Risk Scoring ]
       (Risk formula, triage status, timeline)
                          │
                          ▼
              [ SOC Analyst Frontend ]
           (React + TypeScript SOC Dashboard)
                          │
                          ▼
        [ Evidence-Grounded AI Assistant ]
   (Local LLM / provider, grounded strictly on logs)
                          │
                          ▼
      [ Approval-Gated Automated Response Engine ]
     (Lab firewall block, account lockout, dry-run default)
```

## 4. Key Functional Modules
1. **Collectors (`collectors/`)**:
   - `linux`: Collects authentication events from `/var/log/auth.log` or `systemd-journald`. Features durable checkpointing, log rotation handling (inode tracking and size reset), IPv4/IPv6 extraction, invalid user tagging, SSH success/failure detection.
   - `windows`: Collects Windows Security Event Logs via native Windows Event Log API (`win32evtlog`), handles Event IDs 4624 (Logon), 4625 (Failed Logon), 4672 (Special Privilege Logon), handles XML parsing, handles log clearings / record number resets, incremental bookmarking.
2. **Event Schema & Normalization (`collectors/common/`)**:
   - Canonical JSON schema defining mandatory and optional fields.
   - Strict UTC ISO-8601 timestamps, null values for missing data (never invented fields), stable event fingerprint generation.
3. **Ingestion API (`backend/api/` - Phase 2)**:
   - FastAPI server with token-based authentication.
   - Single and batch event ingestion, schema validation, rate-limiting.
4. **Storage & Search Engine (`backend/storage/` - Phase 3)**:
   - Initial persistent relational storage with indexed querying (timestamp, host, user, IP, event type).
   - Abstract repository interface to allow swap to OpenSearch if scale demands.
5. **Detection & Correlation Engine (`backend/detection/` - Phases 4 & 5)**:
   - Deterministic security rules with configurable thresholds.
   - Alert deduplication using stable fingerprints within sliding time windows.
   - Cross-source multi-event incident correlation.
6. **Machine Learning Anomaly Detection (`backend/ml/` - Phase 6)**:
   - Baseline statistical and Isolation Forest anomaly models.
   - Feature engineering on authentication velocity, failed/success ratios, targeted account entropy.
7. **SOC Dashboard & AI Analyst (`frontend/` & `backend/ai/` - Phase 7)**:
   - High-density SOC interface with real-time incident queues, event explorer, and investigation timelines.
   - Evidence-grounded AI copilot generating structured analysis (Facts, Hypotheses, Recommendations).
8. **Automated Response Engine (`backend/response/` - Phase 8)**:
   - Reversible actions in an isolated lab: IP blocking, test account disabling.
   - Enforces human-in-the-loop approval, dry-run mode, and audit trails.

## 5. Security & Trust Boundaries
- **Untrusted Input**: All incoming log data is treated as untrusted. Sanitized against log injection, path traversal, and prompt injection attacks.
- **Least Privilege**: Collectors run with minimal local read rights (e.g., `adm`/`systemd-journal` groups on Linux; Event Log Readers on Windows Server).
- **Network Isolation**: Default binding to loopback (`127.0.0.1`) or host-only virtual networking between the host and VMs.
