# CURRENT_STATE.md — Current System Status & Project Memory

## 1. Current Phase & Milestone
- **Current Phase**: Phase 8 — Controlled Automated Response Engine & Live Telemetry Integration
- **Milestone**: Windows Server 2012 VM Live Telemetry Streaming & Dashboard Real-Time Explorer
- **Phase 8 & Telemetry Criteria**: MET (All 148 automated backend tests passing; React + TypeScript frontend fully built and running with 3-second auto-refresh, dynamic device dropdown selector, Source IP / Timestamp sorting, clock-skew mitigation, multi-field full-text search, and live Windows Server 2012 event streaming).
- **Dashboard & Filtering Status**: RESOLVED. Real-time sorting defaults to authoritative SIEM arrival time (`ingested_at DESC, rowid DESC`), ensuring new events immediately display on row #1. All filters (Full-text query across 9 canonical fields, Source IP, Device/Host, Username, Severity, and Sort direction) verified working against live database.

## 2. Implemented Components
1. **Canonical Schema & Normalization Engine (`collectors/common/`)**:
   - `schemas.py`: Pydantic `SecurityEvent` model v1.0, enforcing strict UTC ISO-8601 formatting, typed nullability, severity validation, and JSON Lines export.
   - `normalization.py`: Deterministic event ID generator (`generate_event_id`) based on SHA-256 fingerprinting (avoiding random UUID deduplication anti-patterns), IPv4/IPv6 sanitizer (`sanitize_ip`), string cleaner, and multi-format UTC timestamp parser.
   - `shipper.py`: `HttpEventShipper` client transmitting batches of events to the Central Ingestion API with retry logic and authentication headers.
2. **Kali / Linux Collector (`collectors/linux/`)**:
   - `collector.py`: `LinuxAuthCollector` class supporting incremental tailing, journald cursor ingestion, log rotation and truncation detection, environment auto-discovery, and CLI interface.
   - `parsers.py`: High-coverage regex parsers for SSH password/publickey success, failed password attempts, invalid users, sudo command execution, and sudo failures.
   - `checkpoint.py`: `LinuxCheckpoint` with atomic disk commits, inode tracking, and file size monitoring.
3. **Windows Server Security Collector (`collectors/windows/`)**:
   - `collector.py`: `WindowsSecurityCollector` using native `win32evtlog.EvtQuery`, `EvtNext`, `EvtRender`. Supports configurable initial collection policies ("latest" vs "all"), isolated imports, and environment discovery.
   - `parsers.py`: Direct XML parser using `xml.etree.ElementTree` for Event IDs 4624 (Logon), 4625 (Logon Failure), and 4672 (Special Privileges - treated as privileged indicator, not assumed malicious).
   - `checkpoint.py`: `WindowsCheckpoint` tracking `EventRecordID` and detecting log clearings/resets.
4. **Central Ingestion Service (`backend/api/`)**:
   - `main.py`: FastAPI application factory with CORS restricted to local dashboard origins, size limit middleware, structured JSON access logging, and Pydantic exception handlers.
   - `config.py`: Environment-driven settings (`Settings`) with safe local defaults (`127.0.0.1:8000`, API keys, batch sizes, payload limits).
   - `schemas.py`: `BatchIngestRequest`, `IngestResponse`, `HealthResponse`, and `AgentInfo`.
   - `dependencies.py`: Constant-time API key verification (`X-API-Key` and `Authorization: Bearer`), agent header parsing, rate limit checks, storage sink, and incident repository singletons.
   - `rate_limiter.py`: Thread-safe sliding-window rate limiter per client IP and Agent ID with configurable window and `Retry-After` calculation.
   - `middleware.py`: `RequestSizeLimitMiddleware` enforcing body byte limits (HTTP 413) and `StructuredLoggingMiddleware` recording latency, client IP, and agent ID in JSON.
   - `routes/health.py`: Health check routes (`/health`, `/api/v1/health`) returning uptime, database connectivity, and stored event count.
   - `routes/ingest.py`: Authenticated endpoints (`/api/v1/ingest`, `/api/v1/ingest/batch`) handling single and batch event validation and deduplication.
5. **Event Storage & Search Query Engine (`backend/storage/` & `backend/api/routes/events.py`)**:
   - `base.py`: Abstract `EventRepository` interface guaranteeing decoupled storage access for future backend evolution.
   - `models.py`: Data models for `EventFilter`, `PaginationParams`, `PaginatedEventsResponse`, `TimeSeriesBucket`, and `EventSummaryResponse`.
   - `sqlite_repository.py`: Production-grade `SQLiteEventRepository` with WAL mode, parameterized safe query builder, indices on `(timestamp)`, `(source_host)`, `(username)`, `(source_ip)`, `(event_type)`, `(severity)`, raw event retrieval, and hourly/minutely time-series aggregations.
   - `routes/events.py`: REST endpoints for multi-field search, single event retrieval, raw event evidence extraction, and aggregation summaries.
6. **Deterministic Threat Detection Engine (`backend/detection/` & `backend/api/routes/alerts.py`)**:
   - `schemas.py`: `Alert` model with deterministic fingerprinting (`fp_<hash>`), unique alert IDs (`alt_<hash>`), objective explanations, supporting evidence metrics, and entity bindings.
   - `config.py`: `DetectionConfig` managing configurable sliding time windows and thresholds.
   - `rules/rule_001_brute_force.py`: `SingleSourceBruteForceRule` (RULE-001) detecting repeated authentication failures from a single IP within a sliding window.
   - `rules/rule_002_failed_then_success.py`: `FailedFollowedBySuccessRule` (RULE-002) detecting brute-force success / account compromise sequences.
   - `rules/rule_003_password_spray.py`: `DistributedPasswordSprayRule` (RULE-003) detecting multi-source authentication attempts against a single target account.
   - `rules/rule_004_privileged_activity.py`: `PrivilegedActivityRule` (RULE-004) identifying sensitive command executions (`/etc/shadow`, `/bin/bash`, `visudo`) and remote privileged logons.
   - `rules/rule_005_suspicious_sequence.py`: `SuspiciousAuthenticationSequenceRule` (RULE-005) detecting invalid username reconnaissance followed by targeted access attempts.
   - `engine.py`: `DetectionEngine` orchestrating rule evaluation across raw event arrays and storage repositories.
   - `routes/alerts.py`: REST endpoints (`GET /api/v1/detection/rules`, `POST /api/v1/detection/evaluate`).
7. **Alert Deduplication, Correlation & Incident Management (`backend/correlation/` & `backend/api/routes/incidents.py`)**:
   - `config.py`: `CorrelationConfig` with sliding deduplication window (900s), correlation window (3600s), entity allowlist/blocklist (`ignored_entities`), and cross-host correlation controls.
   - `schemas.py`: Models for `Incident`, `IncidentStatus` (`NEW`, `INVESTIGATING`, `RESOLVED`, `CLOSED`), `TimelineEntry`, `AnalystNote`, `DeduplicatedAlert`, and `DeduplicationMetrics`.
   - `deduplicator.py`: `AlertDeduplicator` collapsing repeated alert firings into aggregated records within sliding windows, tracking occurrence counts, merging evidence event IDs, and computing the deduplication ratio `(received - emitted) / received`.
   - `correlator.py`: `IncidentCorrelator` performing entity-temporal graph clustering (connected components) linking multi-stage attacks across shared source IPs and usernames, while strictly preventing false correlations across disjoint entities, expired windows, or generic placeholders.
   - `risk.py`: Documented, explainable risk prioritization formula combining base severity, rule diversity bonus, kill-chain progression bonus, volume factor, and target diversity.
   - `timeline.py`: `build_incident_timeline` constructing sorted chronological forensic milestones from alerts and underlying raw events.
   - `repository.py`: `IncidentRepository` persisting incidents, timeline entries, and analyst notes in SQLite with WAL mode and dedicated indexes.
   - `routes/incidents.py`: REST endpoints (`GET /api/v1/incidents`, `GET /api/v1/incidents/{id}`, `PATCH /api/v1/incidents/{id}/status`, `POST /api/v1/incidents/{id}/notes`, `POST /api/v1/incidents/correlate`, `GET /api/v1/incidents/metrics/deduplication`).
8. **Machine Learning Anomaly Detection Engine (`backend/ml/` & `backend/api/routes/ml.py`)**:
   - `config.py`: `MLConfig` with hyperparameters (`contamination=0.05`, `n_estimators=100`, `random_state=42`, `feature_window_seconds=900`, `alert_threshold=0.60`).
   - `schemas.py`: Models for feature vectors, attributions, results, and metrics.
   - `features.py`: `FeatureExtractor` extracting 10 quantitative behavioral metrics (`event_count`, `failure_count`, `success_count`, `failure_ratio`, `unique_usernames_targeted`, `username_entropy`, `unique_hosts_targeted`, `auth_velocity_per_min`, `mean_inter_arrival_time`, `inter_arrival_variance`).
   - `explainability.py`: `FeatureAttributor` computing z-score deviations relative to baseline normal distributions, calculating contribution percentages, and formatting plain-language narrative explanations.
   - `model.py`: `AnomalyDetector` wrapping `sklearn.ensemble.IsolationForest` with `StandardScaler`, calibrated score mapping, joblib serialization, and deterministic seeds.
   - `alert_generator.py`: `MLAlertGenerator` creating canonical `Alert` records (`ML-ANOMALY-001`) with calibrated risk scores that feed directly into Phase 5 deduplication and incident correlation.
   - `evaluation.py`: Leakage-free train/test evaluation harness with strict temporal partitioning ($T_{\text{train}} < T_{\text{test}}$), distinct benign entities, ground-truth benchmarking, and comparative evaluation vs static rules.
   - `routes/ml.py`: REST endpoints (`GET /api/v1/ml/status`, `POST /api/v1/ml/train`, `POST /api/v1/ml/detect`, `GET /api/v1/ml/benchmark`).
9. **Evidence-Grounded AI Assistant & Active Prompt Defense (`backend/ai/` & `backend/api/routes/ai.py`)**:
   - `config.py`: `AIConfig` settings supporting local offline synthesizers (`offline-evidence-synthesizer-v1`) with zero paid cloud API dependencies.
   - `prompt_defense.py`: `PromptInjectionSanitizer` defending against adversarial instruction hijacking, script tag injection, system token spoofing, and wrapping raw logs inside `<untrusted_evidence_log>` tags.
   - `schemas.py`: Models for `FactEntry`, `HypothesisEntry`, `RecommendationEntry`, `AIAnalysisReport`, and `EventExplanation`.
   - `citation_validator.py`: `CitationValidator` verifying that every cited ID strictly exists in incident evidence (preventing hallucinations).
   - `copilot.py`: `AIAssistantCopilot` synthesizing verified facts with citations, threat hypotheses mapped to MITRE ATT&CK techniques, and actionable recommendations.
   - `routes/ai.py`: REST API endpoints (`POST /api/v1/ai/investigate/{id}`, `POST /api/v1/ai/explain_event/{id}`).
10. **Controlled Automated Response Engine (`backend/response/` & `backend/api/routes/response.py`)**:
    - `config.py`: `ResponseConfig` enforcing dry-run by default, target allowlists (`127.0.0.1`, gateways, DNS, `root`, `administrator`), and rate limits.
    - `schemas.py`: Models for `ResponseActionProposal`, `ResponseActionRecord`, `ApprovalRequest`, `ExecutionResult`, `RollbackResult`, and `SafetyStatusResponse`.
    - `safety.py`: `SafetyGuard` defending against command injection characters, verifying allowlists, and throttling rapid response executions.
    - `policy.py`: `PolicyEngine` evaluating action disruptiveness and enforcing analyst sign-off gates.
    - `handlers/`: `BlockIPHandler`, `LockAccountHandler`, `TerminateSessionHandler`, `NotifyAnalystHandler` with execution and complete rollback operations.
    - `repository.py`: `SQLiteResponseRepository` with SQLite persistence and append-only audit logger (`output/response_audit.jsonl`).
    - `engine.py`: `ResponseEngine` coordinating safety validation, approval lifecycle, handler execution, rollback, and automatic staging of AI copilot recommendations.
    - `routes/response.py`: REST endpoints for proposing, staging, approving, executing, and rolling back containment actions.
11. **High-Density SOC Analyst Frontend (`frontend/`)**:
    - `Header.tsx`: System navbar with live status, active incident counter, 88.9% noise reduction badge, correlation trigger, and Response & Containment tab.
    - `IncidentQueue.tsx`: Incident triage cards & table with status filters (`ALL`, `NEW`, `INVESTIGATING`, `RESOLVED`, `CLOSED`), severity filter, risk score bar, entity badges, and action triggers.
    - `IncidentDetailModal.tsx`: Comprehensive modal with metadata, chronological forensic timeline, analyst notes input/list, and AI investigation trigger.
    - `AICopilotPanel.tsx`: AI Investigation report display with verified facts, clickable citation chips linking to events, MITRE ATT&CK tags, actionable recommendations, and 1-click staging into the Response Queue.
    - `ResponseConsole.tsx`: Dedicated automated response dashboard with safety status indicators, dry-run toggles, filterable containment queue, manual action proposal modal, and approval/execution/rollback modals.
    - `EventExplorer.tsx`: Multi-field event search table with pagination and raw log inspection drawer with "Explain with AI".
    - `MetricsOverview.tsx`: Deduplication ratio dashboard (85-90% alert noise reduction), ML anomaly status, and rule comparison.

## 3. Files Created or Modified
- `DECISIONS.md`: Added ADR-011 (Controlled Automated Response Engine with Human-in-the-Loop Gating, Reversible Rollback, and Allowlist Invariants).
- `ROADMAP.md`: Marked Phase 8 as Completed.
- `CHANGELOG.md`: Logged Phase 8 deliverables.
- `CURRENT_STATE.md`: Updated project memory and test metrics.
- `backend/response/__init__.py`: Package initialization.
- `backend/response/config.py`: ResponseConfig settings and allowlists.
- `backend/response/schemas.py`: Pydantic schemas and enums.
- `backend/response/safety.py`: SafetyGuard allowlist and injection defense.
- `backend/response/policy.py`: PolicyEngine approval gating.
- `backend/response/handlers/base.py`: BaseActionHandler interface.
- `backend/response/handlers/block_ip.py`: BlockIPHandler execution and rollback.
- `backend/response/handlers/lock_account.py`: LockAccountHandler execution and rollback.
- `backend/response/handlers/terminate_session.py`: TerminateSessionHandler.
- `backend/response/handlers/notify.py`: NotifyAnalystHandler.
- `backend/response/handlers/__init__.py`: Handler package exports.
- `backend/response/repository.py`: SQLiteResponseRepository with audit logger.
- `backend/response/engine.py`: ResponseEngine coordinator.
- `backend/api/dependencies.py`: Registered get_response_engine dependency and singleton.
- `backend/api/routes/response.py`: REST API routes for response operations.
- `backend/api/main.py`: Registered response router.
- `tests/unit/test_response_engine.py`: Unit tests for safety, policy, handlers, and engine lifecycle (11 tests).
- `tests/unit/test_api_response.py`: Integration tests for response API endpoints (7 tests).
- `frontend/src/types/index.ts`: Added response action and safety types.
- `frontend/src/services/api.ts`: Added response API client methods.
- `frontend/src/components/ResponseConsole.tsx`: Containment queue, approval, execution, and rollback UI.
- `frontend/src/components/AICopilotPanel.tsx`: Connected recommendations directly to Response Engine staging.
- `frontend/src/components/Header.tsx`: Added Response & Containment navigation tab.
- `frontend/src/App.tsx`: Wired up ResponseConsole and tab routing.

## 4. Commands Executed & Actual Results
- `.\.venv\Scripts\pytest -v tests/unit/test_response_engine.py tests/unit/test_api_response.py` -> 18 passed in 3.50s (Exit Code 0).
- `npm run build` in `frontend/` -> Successfully transformed 1943 modules and built `dist/` bundle in 2.42s (Exit Code 0).
- `.\.venv\Scripts\pytest -v` -> 148 passed, 1 warning in 7.52s with zero failures (Exit Code 0).

## 5. Tests Passed & Failed
- **Passed (148 / 148)**:
  - `test_response_engine.py`: 11 passed
  - `test_api_response.py`: 7 passed
  - `test_ai_assistant.py`: 4 passed
  - `test_ml_features.py`: 3 passed
  - `test_ml_model.py`: 4 passed
  - `test_ml_evaluation.py`: 2 passed
  - `test_ml_alerts_and_api.py`: 5 passed
  - `test_correlation_dedup.py`: 5 passed
  - `test_correlation_engine.py`: 7 passed
  - `test_incident_lifecycle.py`: 4 passed
  - `test_api_incidents.py`: 4 passed
  - `test_rules_positive_negative.py`: 16 passed
  - `test_detection_engine.py`: 3 passed
  - `test_api_alerts.py`: 2 passed
  - `test_storage_repository.py`: 5 passed
  - `test_api_search.py`: 7 passed
  - `test_api_auth.py`: 4 passed
  - `test_api_health.py`: 1 passed
  - `test_api_ingest.py`: 6 passed
  - `test_api_limits.py`: 2 passed
  - `test_storage_sink.py`: 3 passed
  - `test_event_shipper.py`: 3 passed
  - `test_schemas.py`: 4 passed
  - `test_normalization.py`: 10 passed
  - `test_linux_parser.py`: 10 passed
  - `test_linux_checkpoint.py`: 5 passed
  - `test_windows_parser.py`: 5 passed
  - `test_windows_checkpoint.py`: 2 passed
  - `test_collector_flow.py`: 4 passed
  - `test_e2e_kali_pipeline.py`: 1 passed (Full end-to-end Kali auth log parsing -> batch shipping -> SQLite storage -> RULE-001/002 detection -> incident correlation -> timeline query)
- **Total Passing**: 149 passed
- **Failed**: 0 failed.

## 6. Manual / Live VM Checks Required
1. **Lab Containment Verification**:
   - In a non-production VM or loopback lab, trigger an approved live IP block and verify netsh/iptables rule addition and removal via rollback.
2. **End-to-End AI to Containment Workflow**:
   - Open SOC dashboard (`http://localhost:3000`), select an incident in AI Copilot, click "Stage All for Containment", switch to Response Console, sign off approval, and trigger execution.

## 7. Known Limitations
- Real firewall rule creation on physical hosts requires elevated administrative privileges (`sudo` / `Run as Administrator`). Dry-run mode is enabled by default to allow safe unprivileged academic evaluation on developer workstations.
- Reversible user locking applies to standard accounts and strictly rejects root or administrative targets.

## 8. Target Environment & Configuration Assumptions
- Host: Windows 11 (AMD64, Build 26300), Python 3.13.7, Node.js v22.20.0, npm 10.9.3.
- Ingestion URL: `http://127.0.0.1:8000`.
- Frontend Dev URL: `http://localhost:5173`.
- Authentication Token: `test-collector-api-key-replace-in-production`.
- SQLite Database: `output/soc_events.sqlite`.
- Audit Log: `output/response_audit.jsonl`.

## 9. Exact Next Task
- **Phase 9: Research Evaluation & Viva Prep**:
  - Benchmark evaluation script comparing 4 operational configurations:
    1. Raw Rule Engine alone (baseline Splunk-style rule thresholding).
    2. Rule Engine + Alert Deduplication (noise reduction quantification).
    3. Rule Engine + Deduplication + Multi-Entity Correlation (kill-chain consolidation).
    4. Full System: Rules + ML Anomaly Detection + Correlation + Evidence-Grounded AI Copilot + Controlled Response.
  - Compute and plot academic metrics: Alert Fatigue Reduction Ratio, Detection Recall on stealth attacks, Mean Time to Triage (MTTT) comparison, and Citation Fidelity (0% hallucination verification).
  - Create comprehensive Major Project Viva Voce preparation guide covering architecture, threat model, ML model selection, prompt injection defense, and empirical research contributions.

## 10. Restart Prompt
```
Resume work on AI Cyber Defense Platform. Phases 1 through 8 (Log Collection, Central Ingestion, Event Storage & Search, Rule-Based Threat Detection, Alert Deduplication/Correlation/Incidents, Machine Learning Anomaly Detection, SOC Frontend & Evidence-Grounded AI Assistant, and Controlled Automated Response Engine) are fully implemented and verified with 148/148 backend tests passing and frontend cleanly compiled. Read AGENTS.md, PROJECT_SPEC.md, ROADMAP.md, and CURRENT_STATE.md. Next task is Phase 9: Research Evaluation & Viva Prep (reproducible academic comparative evaluation script measuring 4 configurations, alert fatigue reduction benchmarks, stealth detection recall, and comprehensive Major Project Viva Voce defense documentation).
```
