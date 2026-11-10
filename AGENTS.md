# AGENTS.md — Permanent Instructions and Engineering Conventions

## Project Overview
This repository contains the **AI Cyber Defense Platform: A SOC with Intelligent Threat Detection & Automated Response**, an academic research prototype and lightweight, locally deployable Security Information and Event Management (SIEM) and Security Operations Center (SOC) platform inspired by enterprise systems like Splunk.

## Core Directives & Working Principles
1. **Academic Honesty & Precision**: This is an academic research prototype, not a direct enterprise Splunk replacement. Do not make unsupported claims that existing SIEM products lack specific capabilities. Never claim superiority over Splunk without fair, reproducible benchmark comparisons. Never fabricate performance numbers, IP addresses, or test results.
2. **Inspect Before Modifying**:
   - Inspect existing directory structure and files before making changes.
   - Read project documentation and configuration.
   - Identify implemented vs incomplete features.
   - Run relevant existing tests before adding new code.
   - Preserve working code unless a change is explicitly justified.
   - Avoid replacing entire files unnecessarily.
3. **Make Small, Verifiable Changes**:
   - Implement one milestone at a time according to `ROADMAP.md`.
   - Never mark a task complete based only on code generation.
   - Never claim a feature works or tests passed unless verified by actual execution.
   - Fix all errors introduced by changes before moving to subsequent milestones.
4. **Preserve Context in Repository Files**:
   - Always update `CURRENT_STATE.md`, `ROADMAP.md`, `CHANGELOG.md`, and other tracking files at the end of every work session or major milestone.
   - Record exact commands executed, tests passed/failed, known limitations, and precise next steps.
5. **Architectural Separation & Modularity**:
   - Keep clear module boundaries: collectors, ingestion API, normalization, detection engine, correlation engine, AI assistant, and response engine must be independently testable.
   - Keep Windows-only imports (e.g., `win32evtlog`, `win32con`, `pywin32`) isolated in platform-specific modules so cross-platform and Linux modules/tests can run without import errors on Linux or non-Windows hosts.
6. **Defensive Security & Safe Defaults**:
   - Treat all logs and external inputs as untrusted input (susceptible to log injection, malformed syntax, prompt injection).
   - Ingestion APIs must default to localhost/loopback or protected lab networks with authentication. Never bind insecurely to public interfaces.
   - Automated response actions must have dry-run mode enabled by default, require explicit approval for disruptive actions, enforce allowlists, maintain audit logs, and support rollback. Never allow untrusted AI/LLM models to execute arbitrary shell commands directly.

## Coding Standards
- **Python**: 3.10+ (current host runs Python 3.13). Use strict type annotations (`typing`).
- **Dependencies**: Pin or constrain in `requirements.txt` / `pyproject.toml`.
- **Configuration**: Environment variables with safe fallback values, documented in `.env.example`.
- **Testing**: `pytest` for unit and integration testing. Use synthetic fixtures to decouple tests from live OS dependencies where appropriate, while providing integration test harnesses for live systems.
- **Error Handling**: Graceful degradation, explicit structured logging, durable checkpointing, never suppress errors silently.
