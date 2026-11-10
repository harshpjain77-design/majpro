# docs/TESTING.md — Test Instructions and Known Limitations

## 1. Testing Philosophy
- **Verification First**: Never claim a feature works or tests passed without actual execution logs.
- **Decoupled Unit Testing**: Tests for parsers, normalization, checkpointing, and deduplication must run in any environment (including Windows host) using synthetic log fixtures and mocks without requiring active VMs.
- **Explicit Separation**: Clearly delineate host-executable unit tests from VM-dependent live environment tests.

---

## 2. Running Automated Tests on Current Host
To run the automated test suite on Windows 11 host:
```powershell
.\.venv\Scripts\pytest -v tests/
```
Or for coverage:
```powershell
.\.venv\Scripts\pytest -v --cov=collectors tests/
```

---

## 3. Test Suites
- `tests/unit/test_schemas.py`: Verifies Pydantic canonical event schema validation, field types, UTC timestamp coercion, and missing field handling.
- `tests/unit/test_normalization.py`: Verifies fingerprint generation, IP validation, and raw event preservation.
- `tests/unit/test_linux_parser.py`: Verifies parsing of SSH success, SSH failure, invalid user, sudo privilege escalation, and journald JSON records against synthetic fixtures.
- `tests/unit/test_linux_checkpoint.py`: Verifies durable checkpoint file persistence, resumption, log rotation detection, and file truncation recovery.
- `tests/unit/test_windows_parser.py`: Verifies parsing of Windows XML events 4624 (Logon), 4625 (Failed Logon), and 4672 (Special Logon) against synthetic XML fixtures without requiring live Windows Security event log channels.
- `tests/unit/test_windows_checkpoint.py`: Verifies record number tracking, reset handling, and checkpoint persistence.

---

## 4. Manual / Live VM Verification Checks
The following tests require execution inside specific VM environments:
1. **Kali Linux VM**:
   - Live tailing of `/var/log/auth.log` during real SSH login (`ssh user@localhost`).
   - Journald cursor streaming (`journalctl -u ssh`).
   - Inode rotation test using `logrotate -f /etc/logrotate.d/rsyslog`.
2. **Windows Server VM**:
   - Querying live `win32evtlog.EvtQuery` channel `Security`.
   - Testing Event 4625 generation with bad password login.
   - Verifying non-admin operation under `Event Log Readers` group.

---

## 5. Known Limitations
- Event Log XML parsing handles standard schema elements (`<Event xmlns="...">`, `<System>`, `<EventData>`, `<Data Name="...">`). Non-standard custom event providers may produce unstructured `<Data>` nodes requiring additional generic parsers.
- Linux log parsing relies on standard OpenSSH and PAM formats. Custom PAM module formats may yield fallback informational events.
