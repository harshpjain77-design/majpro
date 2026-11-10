# docs/SETUP.md — Environment Setup and Deployment Guide

## 1. System Overview
The platform components run across three environments in the testing laboratory:
- **Physical Host (Windows 11)**: Development, central backend/ingestion API (FastAPI), data store, detection engine, SOC dashboard.
- **VM 1: Kali Linux (VMware Workstation)**: Security testing, attack simulation, and Linux authentication event collection (`/var/log/auth.log` or `journald`).
- **VM 2: Windows Server (VMware Workstation)**: Enterprise authentication log source emitting Security Event Log records (Logon 4624, Failed Logon 4625, Special Privileges 4672).

---

## 2. Windows 11 Host Setup
1. **Prerequisites**:
   - Python 3.10+ (tested on Python 3.13)
   - Node.js 18+ (for Phase 7 frontend)
   - Git
2. **Environment Initialization**:
   ```powershell
   # Clone / enter directory
   cd c:\Users\jainh\OneDrive\Desktop\major

   # Create virtual environment
   python -m venv .venv

   # Activate virtual environment
   .\.venv\Scripts\Activate.ps1

   # Install dependencies
   pip install -r requirements.txt
   ```
3. **Configuration**:
   Copy `.env.example` to `.env` and configure local parameters:
   ```powershell
   Copy-Item config\collector.example.json config\collector.json
   ```

---

## 3. Kali Linux Collector Setup
1. **Prerequisites**:
   - Python 3.10+
   - Read permissions for authentication logs (`/var/log/auth.log`) or `systemd-journald`.
2. **Minimum Necessary Permissions**:
   Avoid running collectors as `root`.
   - On Debian/Ubuntu/Kali:
     ```bash
     # Add collector service user to the 'adm' and 'systemd-journal' groups:
     sudo usermod -a -G adm,systemd-journal <collector_user>
     ```
   - Verify access:
     ```bash
     tail -n 5 /var/log/auth.log
     journalctl -u ssh.service -n 5
     ```
3. **Execution**:
   ```bash
   python3 -m collectors.linux.collector --config config/collector.linux.json
   ```

---

## 4. Windows Server Collector Setup
1. **Prerequisites**:
   - Windows Server 2016 / 2019 / 2022 / 2025 (exact version will be documented upon VM discovery).
   - Python 3.10+ with `pywin32`.
2. **Minimum Necessary Permissions**:
   - The collector user must be a member of the built-in **"Event Log Readers"** local security group.
   - Do **NOT** run as Domain Admin or local SYSTEM unnecessarily.
3. **Windows Audit Policy Requirements**:
   To generate authentication failure and success telemetry:
   ```cmd
   auditpol /set /subcategory:"Logon" /success:enable /failure:enable
   auditpol /set /subcategory:"Special Logon" /success:enable /failure:disable
   ```
4. **Execution**:
   ```cmd
   python -m collectors.windows.collector --config config\collector.windows.json
   ```

---

## 5. Lab Networking & Virtualization Mode
- **Current Mode**: Bridged network.
- **Security Recommendation**: Configure VMware Workstation virtual network adapters to **Host-Only** (e.g. `VMnet1`) for isolated penetration testing and security evaluation, preventing any accidental broadcast or exposure of vulnerable target ports to the wider physical LAN.
