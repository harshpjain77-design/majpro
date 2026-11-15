import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  BookOpen,
  Shield,
  Zap,
  CheckCircle2,
  Copy,
  Check,
  ExternalLink,
  FileText,
  AlertTriangle,
  Lock,
  Server,
  UserCheck,
  Activity,
  Terminal,
  ArrowRight,
  Search,
  SlidersHorizontal,
  Layers,
  ShieldAlert,
  Download,
  Clock,
  Eye,
  RefreshCw,
  X
} from 'lucide-react';
import { api } from '../services/api';
import { Incident } from '../types';

/* ==========================================================================
   Playbook Data Models & Catalog Definitions (Derived from RubySummers101 Repo)
   ========================================================================== */

interface PlaybookStep {
  stage: 'Identification' | 'Classification' | 'Containment' | 'Eradication' | 'Recovery' | 'Lessons Learned';
  step_number: number;
  title: string;
  description: string;
  actions: string[];
  cli_commands?: string[];
  tools?: string[];
  automated?: boolean;
}

interface Playbook {
  id: string;
  title: string;
  category: 'Threat Detection' | 'Incident Response' | 'Zero Trust' | 'Risk Governance';
  severity: 'critical' | 'high' | 'medium' | 'low';
  mitre_technique: string;
  target_rule?: string;
  sla_minutes: number;
  description: string;
  summary: string;
  protect_surfaces: string[];
  steps: PlaybookStep[];
  automation_support: boolean;
}

const PLAYBOOKS_CATALOG: Playbook[] = [
  {
    id: 'PB-001',
    title: 'Sustained SSH & Kerberos Brute Force Attack Response',
    category: 'Threat Detection',
    severity: 'high',
    mitre_technique: 'T1110.001 - Password Guessing',
    target_rule: 'RULE-001 (SingleSourceBruteForce)',
    sla_minutes: 15,
    summary: 'Standard Operating Procedure for handling high-frequency authentication failures targeting SSH (Linux) or Kerberos (Windows).',
    description: 'Triggered when repeated failed logon attempts exceed the deterministic threshold from a single originating IP within a sliding window. Requires automated or manual perimeter containment to prevent credential compromise.',
    protect_surfaces: ['Authentication Daemons (sshd, lsass)', 'Identity Services', 'Perimeter Gateways'],
    automation_support: true,
    steps: [
      {
        stage: 'Identification',
        step_number: 1,
        title: 'Correlate Telemetry in SIEM Ingestion Stream',
        description: 'Verify failure velocity and ensure that failures originate from an unauthorized or external source IP.',
        actions: [
          'Inspect raw authentication log events in ThreadGrid Events Explorer.',
          'Identify targeted accounts (e.g. root, administrator, service accounts).',
          'Verify originating IP geolocation and reverse DNS PTR records.',
        ],
        tools: ['ThreadGrid SIEM', 'Linux /var/log/auth.log', 'Windows Event ID 4625'],
      },
      {
        stage: 'Classification',
        step_number: 2,
        title: 'Classify Attack Velocity & Blast Radius',
        description: 'Distinguish between automated internet noise, targeted single-source brute force, and multi-source spraying.',
        actions: [
          'Calculate failure rate (attempts per minute).',
          'Evaluate if attempts belong to authorized vulnerability scanning or penetration testing.',
          'Classify severity as High if targeting privileged accounts.',
        ],
      },
      {
        stage: 'Containment',
        step_number: 3,
        title: 'Execute Immediate Perimeter Firewall Drop',
        description: 'Enforce immediate boundary drop rule to sever threat actor connectivity.',
        actions: [
          'Stage and execute firewall drop rule in ThreadGrid Response Console.',
          'Apply localized firewall drop on host.',
          'Verify threat actor connection dropped via netstat/ss.',
        ],
        cli_commands: [
          '# Linux iptables boundary drop:\nsudo iptables -I INPUT -s {SOURCE_IP} -j DROP',
          '# Windows Server netsh boundary drop:\nnetsh advfirewall firewall add rule name="Block-Attacker-IP" dir=in action=block remoteip={SOURCE_IP}',
        ],
        automated: true,
      },
      {
        stage: 'Eradication',
        step_number: 4,
        title: 'Invalidate Active Threat Sessions & Clear Vectors',
        description: 'Ensure attacker did not establish any persistent backdoor or shell session.',
        actions: [
          'Check for active network connections from source IP.',
          'Inspect `/etc/ssh/sshd_config` or Windows remote access policies.',
          'Revoke temporary connection tokens.',
        ],
        cli_commands: [
          '# Terminate active SSH connections from source IP:\nsudo pkill -9 -t $(who | grep {SOURCE_IP} | awk \'{print $2}\')',
        ],
      },
      {
        stage: 'Recovery',
        step_number: 5,
        title: 'Restore Normal Access & Enable Continuous Monitoring',
        description: 'Verify service availability for authorized users while monitoring for threat resurgence.',
        actions: [
          'Confirm legitimate administrative users can log in successfully.',
          'Ensure fail2ban or Windows Account Lockout Policy is synchronized.',
          'Maintain elevated monitoring threshold for 24 hours.',
        ],
      },
      {
        stage: 'Lessons Learned',
        step_number: 6,
        title: 'Hardening & Post-Incident Review',
        description: 'Archive incident telemetry and deploy preventative defensive safeguards.',
        actions: [
          'Enforce SSH key-based authentication and disable password logins (`PasswordAuthentication no`).',
          'Change default SSH port or enforce VPN gateway requirement.',
          'Archive incident evidence into enterprise SIEM compliance repository.',
        ],
      },
    ],
  },
  {
    id: 'PB-002',
    title: 'Credential Stuffing Leading to Post-Compromise Logon',
    category: 'Threat Detection',
    severity: 'critical',
    mitre_technique: 'T1110.004 - Credential Stuffing & T1078 - Valid Accounts',
    target_rule: 'RULE-002 (FailedFollowedBySuccess)',
    sla_minutes: 10,
    summary: 'Critical Breach SOP: Rapid containment when failed logon attempts are immediately succeeded by a successful logon.',
    description: 'Indicates high-confidence credential compromise. The adversary has successfully guessed, brute-forced, or stuffed stolen credentials and established an authenticated foothold.',
    protect_surfaces: ['Compromised User Identity', 'Internal LAN Subnets', 'Kerberos Ticket Granting Service'],
    automation_support: true,
    steps: [
      {
        stage: 'Identification',
        step_number: 1,
        title: 'Detect Validated Account Compromise Sequence',
        description: 'Identify exact timestamp of failed logon cluster and subsequent authentication success.',
        actions: [
          'Extract target username and attacker IP address.',
          'Verify if the successful logon originated from the exact attacking IP.',
          'Flag incident as Critical Severity with immediate paging.',
        ],
        tools: ['ThreadGrid Correlator', 'Linux Event 4624/4625', 'Auditd'],
      },
      {
        stage: 'Classification',
        step_number: 2,
        title: 'Triage Account Type & Privilege Level',
        description: 'Determine if compromised identity possesses administrative (root/Domain Admin) or standard privileges.',
        actions: [
          'Check account group memberships and sudoers privileges.',
          'Identify assets accessible by the compromised credential.',
        ],
      },
      {
        stage: 'Containment',
        step_number: 3,
        title: 'Immediate Reversible Account Lockout & Session Severing',
        description: 'Terminate all active sessions for the compromised user and lock account access.',
        actions: [
          'Lock user account immediately (reversible).',
          'Kill all active terminal sessions and processes owned by the user.',
          'Drop attacker source IP at firewall perimeter.',
        ],
        cli_commands: [
          '# Linux Account Lock & Session Termination:\nsudo usermod -L {USERNAME}\nsudo pkill -KILL -u {USERNAME}',
          '# Windows Account Disable & Session Logoff:\nnet user {USERNAME} /active:no\nquery user {USERNAME}',
        ],
        automated: true,
      },
      {
        stage: 'Eradication',
        step_number: 4,
        title: 'Revoke Credentials & Audit Lateral Movement',
        description: 'Eliminate persistence mechanisms planted during the compromised session.',
        actions: [
          'Audit `~/.ssh/authorized_keys` for unauthorized public keys.',
          'Check cron jobs (`/etc/cron*`) and Windows Scheduled Tasks for persistence.',
          'Force global password reset across all directory domains.',
        ],
        cli_commands: [
          '# Inspect unauthorized SSH keys:\nsudo cat /home/{USERNAME}/.ssh/authorized_keys',
        ],
      },
      {
        stage: 'Recovery',
        step_number: 5,
        title: 'Re-enable Account with Mandatory MFA',
        description: 'Restore business operations after credential rotation and out-of-band identity verification.',
        actions: [
          'Verify user identity via out-of-band channel (phone/video).',
          'Issue temporary single-use password requiring immediate rotation.',
          'Mandate hardware-bound Multi-Factor Authentication (FIDO2/WebAuthn).',
        ],
      },
      {
        stage: 'Lessons Learned',
        step_number: 6,
        title: 'Root Cause & Threat Matrix Audit',
        description: 'Determine credential leakage source (dark web dump, phishing, or weak password).',
        actions: [
          'Run credential audit against known breach databases.',
          'Enforce enterprise password complexity and minimum 16-character passphrases.',
          'File mandatory breach disclosure report if PII was accessible.',
        ],
      },
    ],
  },
  {
    id: 'PB-003',
    title: 'Distributed Multi-Source Password Spraying Defense',
    category: 'Threat Detection',
    severity: 'high',
    mitre_technique: 'T1110.003 - Password Spraying',
    target_rule: 'RULE-003 (DistributedPasswordSpray)',
    sla_minutes: 30,
    summary: 'SOP for countering low-and-slow distributed authentication campaigns originating from multiple IPs against single accounts.',
    description: 'Adversaries spray common passwords across multiple IP addresses to evade single-source rate limiting and lockout thresholds.',
    protect_surfaces: ['Active Directory Domain Controllers', 'Single Sign-On (SSO) Portals', 'Cloud IdP'],
    automation_support: true,
    steps: [
      {
        stage: 'Identification',
        step_number: 1,
        title: 'Cluster Multi-Source IP Telemetry',
        description: 'Use ThreadGrid Correlation Engine to group disparate source IPs targeting the same identity within 60 minutes.',
        actions: [
          'Identify list of all originating spray IPs (botnet / proxy nodes).',
          'Calculate total targeted user accounts across the enterprise.',
        ],
      },
      {
        stage: 'Classification',
        step_number: 2,
        title: 'Determine Spray Mechanism & Attacker Infrastructure',
        description: 'Inspect user-agent strings and network ASNs to identify automated attack tooling (e.g. SprayingToolkit, Ruler).',
        actions: [
          'Check ASN reputation (residential proxies, bulletproof hosting, TOR exit nodes).',
          'Check if spraying targeted internal service accounts or executive accounts.',
        ],
      },
      {
        stage: 'Containment',
        step_number: 3,
        title: 'Stage Automated Subnet & Geo-Fence Blocking',
        description: 'Implement distributed boundary drop and temporary smart lockout.',
        actions: [
          'Drop identified spray IP list at border firewall.',
          'Enable CAPTCHA and smart lockout delay on public login interfaces.',
        ],
        cli_commands: [
          '# Drop spray IP list via iptables ipset:\nsudo ipset create SPRAY_BLOCK hash:ip\nsudo iptables -I INPUT -m set --match-set SPRAY_BLOCK src -j DROP',
        ],
        automated: true,
      },
      {
        stage: 'Eradication',
        step_number: 4,
        title: 'Audit for Successful Hits During Spray Window',
        description: 'Verify that zero spray attempts achieved authentication success.',
        actions: [
          'Cross-reference all spray timestamps against Event 4624 / Accepted password events.',
          'Lock any account that exhibited a successful logon during the spray window.',
        ],
      },
      {
        stage: 'Recovery',
        step_number: 5,
        title: 'Review Account Status & Clear Temporary Blocks',
        description: 'Release locked accounts after confirming no compromise occurred.',
        actions: [
          'Unlock accounts after password validation.',
          'Restore normal rate limiting thresholds.',
        ],
      },
      {
        stage: 'Lessons Learned',
        step_number: 6,
        title: 'Deploy Identity Protection Controls',
        description: 'Implement behavioral risk-based conditional access policies.',
        actions: [
          'Block authentications from untrusted residential proxy networks.',
          'Enforce continuous authentication evaluation (CAE).',
        ],
      },
    ],
  },
  {
    id: 'PB-004',
    title: 'Unauthorized Privilege Escalation & Sensitive Execution',
    category: 'Threat Detection',
    severity: 'critical',
    mitre_technique: 'T1068 - Exploitation for Privilege Escalation & T1548 - Abuse Elevation Mechanisms',
    target_rule: 'RULE-004 (PrivilegedActivity)',
    sla_minutes: 10,
    summary: 'Emergency SOP for containing sensitive file tampering (/etc/shadow, visudo, /bin/bash execution) or remote privileged logons.',
    description: 'Adversaries attempting to elevate privileges or execute root-level commands without explicit administrative authorization.',
    protect_surfaces: ['Kernel & SUID Binaries', 'Shadow Password Database', 'Windows lsass.exe Memory'],
    automation_support: true,
    steps: [
      {
        stage: 'Identification',
        step_number: 1,
        title: 'Inspect Command Line Execution & Parent Process Lineage',
        description: 'Extract raw command arguments, process ID (PID), parent PID (PPID), and executing user.',
        actions: [
          'Identify executed sensitive binary (e.g. `cat /etc/shadow`, `visudo`, `bash -i`).',
          'Verify if execution matches an approved IT change management ticket.',
        ],
      },
      {
        stage: 'Classification',
        step_number: 2,
        title: 'Assess Scope of Local Escalation',
        description: 'Determine if adversary obtained interactive root/SYSTEM shell.',
        actions: [
          'Check effective UID (euid=0).',
          'Evaluate if remote lateral traversal tools were downloaded (`curl`, `wget`, `nc`).',
        ],
      },
      {
        stage: 'Containment',
        step_number: 3,
        title: 'Host Network Quarantine & Process Termination',
        description: 'Sever network connectivity to isolate the affected host while maintaining SOC management telemetry.',
        actions: [
          'Isolate host network adapter (leaving loopback and SIEM agent port open).',
          'Terminate rogue process tree immediately.',
        ],
        cli_commands: [
          '# Kill unauthorized shell and all subprocesses:\nsudo kill -9 {ROGUE_PID}',
          '# Linux Host Isolation (allow SIEM traffic to 8000 only):\nsudo iptables -P INPUT DROP\nsudo iptables -A OUTPUT -p tcp --dport 8000 -j ACCEPT',
        ],
        automated: true,
      },
      {
        stage: 'Eradication',
        step_number: 4,
        title: 'Forensic Triage & File Integrity Verification',
        description: 'Identify and remove implants, rootkits, or modified SUID binaries.',
        actions: [
          'Audit `/etc/passwd`, `/etc/shadow`, `/etc/sudoers` for unauthorized accounts.',
          'Run integrity check on system binaries using `debsums -c` or `sfc /scannow`.',
          'Collect volatile memory dump for rootkit analysis.',
        ],
      },
      {
        stage: 'Recovery',
        step_number: 5,
        title: 'Re-image Host or Restore from Verified Golden Image',
        description: 'For mission-critical servers, re-provision from verified infrastructure-as-code baseline.',
        actions: [
          'Re-deploy operating system and authorized application containers.',
          'Re-attach to domain with freshly generated machine credentials.',
        ],
      },
      {
        stage: 'Lessons Learned',
        step_number: 6,
        title: 'Enforce Least Privilege & Application Whitelisting',
        description: 'Implement AppArmor/SELinux mandatory access control policies.',
        actions: [
          'Strictly restrict sudo permissions to specific binary paths with `NOPASSWD` forbidden.',
          'Mount `/tmp` and `/var/tmp` with `noexec,nosuid,nodev`.',
        ],
      },
    ],
  },
  {
    id: 'PB-005',
    title: 'Account Reconnaissance & Username Enumeration Response',
    category: 'Threat Detection',
    severity: 'medium',
    mitre_technique: 'T1087 - Account Discovery',
    target_rule: 'RULE-005 (SuspiciousAuthenticationSequence)',
    sla_minutes: 60,
    summary: 'SOP for handling invalid user reconnaissance followed by targeted authentication attempts.',
    description: 'Adversaries probe public-facing services with random or common usernames to detect valid user accounts before launching targeted brute-force or spear-phishing.',
    protect_surfaces: ['Edge Boundary Routers', 'Public Application Portals'],
    automation_support: true,
    steps: [
      {
        stage: 'Identification',
        step_number: 1,
        title: 'Extract Enumerated Usernames & Query Patterns',
        description: 'Filter logs for `Invalid user` strings and tally distinct query identifiers.',
        actions: [
          'List queried usernames (e.g. admin, test, guest, deploy, oracle).',
          'Determine if any queried username matched a genuine internal account.',
        ],
      },
      {
        stage: 'Classification',
        step_number: 2,
        title: 'Classify Reconnaissance Tooling',
        description: 'Inspect scan cadence to detect automated tools like Hydra, Nmap, or Metasploit.',
        actions: [
          'Triage scanning IP against public threat intelligence feeds.',
          'Verify if scanning transitioned from invalid names to genuine employee accounts.',
        ],
      },
      {
        stage: 'Containment',
        step_number: 3,
        title: 'Blacklist Reconnaissance Source IP at Perimeter',
        description: 'Add reconnaissance IP to automated border drop list.',
        actions: [
          'Execute border firewall drop rule.',
          'Review edge NAT logs for related scanner probes on other ports (e.g. 80, 443, 3389).',
        ],
        cli_commands: [
          'sudo iptables -I INPUT -s {SOURCE_IP} -j DROP',
        ],
        automated: true,
      },
      {
        stage: 'Eradication',
        step_number: 4,
        title: 'Verify No Target Discovery Success',
        description: 'Confirm that the adversary received zero positive validation signals.',
        actions: [
          'Ensure server configuration masks user existence differences in response timings.',
        ],
      },
      {
        stage: 'Recovery',
        step_number: 5,
        title: 'Maintain Reconnaissance Watchlist',
        description: 'Retain scanner signature in SIEM correlation watchlist for 30 days.',
        actions: [
          'Add IP and ASN to threat intel blocklist.',
        ],
      },
      {
        stage: 'Lessons Learned',
        step_number: 6,
        title: 'Deploy Obfuscation & Uniform Authentication Responses',
        description: 'Configure services to return identical error messages and constant-time responses.',
        actions: [
          'Disable verbose service banners.',
          'Deploy honeypot user accounts with active alerting alarms.',
        ],
      },
    ],
  },
  {
    id: 'PB-006',
    title: 'Zero Trust Architecture (ZTA) Mission-Critical Framework',
    category: 'Zero Trust',
    severity: 'medium',
    mitre_technique: 'Enterprise Architecture & Defense-in-Depth',
    sla_minutes: 120,
    summary: 'Strategic leadership playbook based on "Never Trust, Always Verify" principles across 5 Technology Pillars.',
    description: 'Framework directly implementing the Zero Trust Architecture guide from the military cybersecurity playbook repository. Governs protect surfaces, transaction flows, microsegmentation, and continuous monitoring.',
    protect_surfaces: ['Data, Assets, Applications, Services (DAAS)', 'Software-Defined Perimeters (SDP)', 'Identity-Aware Proxies'],
    automation_support: false,
    steps: [
      {
        stage: 'Identification',
        step_number: 1,
        title: 'Identify & Classify Protect Surfaces (DAAS)',
        description: 'Define critical Data, Assets, Applications, and Services requiring continuous verification.',
        actions: [
          'Inventory high-value data stores, credential vaults, and mission-critical hosts.',
          'Assign risk tiers and explicit executive ownership.',
        ],
        tools: ['Asset Inventory', 'Data Classification Matrix', 'ThreadGrid Entity Explorer'],
      },
      {
        stage: 'Classification',
        step_number: 2,
        title: 'Map Transaction Flows & Behavioral Baselines',
        description: 'Document typical communication paths between users, microservices, and protect surfaces.',
        actions: [
          'Trace East-West and North-South network flows.',
          'Establish baseline traffic patterns for automated anomaly detection.',
        ],
      },
      {
        stage: 'Containment',
        step_number: 3,
        title: 'Architect Microsegmentation & Software-Defined Perimeter',
        description: 'Eliminate flat networks by enforcing granular network microsegmentation.',
        actions: [
          'Deploy host-based firewall microsegmentation rules.',
          'Route all administrative and application traffic through identity-aware gateways.',
        ],
        cli_commands: [
          '# Example host microsegmentation (restrict database port to application backend):\nsudo iptables -A INPUT -p tcp --dport 5432 -s 192.168.1.50 -j ACCEPT\nsudo iptables -A INPUT -p tcp --dport 5432 -j DROP',
        ],
      },
      {
        stage: 'Eradication',
        step_number: 4,
        title: 'Enforce Strict Identity & Least Privilege Access',
        description: 'Implement mandatory Multi-Factor Authentication (MFA) and Just-in-Time (JIT) access.',
        actions: [
          'Eliminate standing administrative privileges.',
          'Mandate short-lived session tokens and time-bound sudo elevation.',
        ],
      },
      {
        stage: 'Recovery',
        step_number: 5,
        title: 'Enable Continuous Real-Time Telemetry & Monitoring',
        description: 'Feed 100% of authentication decisions, firewall rejects, and process telemetry into SIEM.',
        actions: [
          'Verify continuous streaming from Kali and Windows Server collectors into ThreadGrid API.',
          'Tune detection rules for zero-trust anomaly alerts.',
        ],
      },
      {
        stage: 'Lessons Learned',
        step_number: 6,
        title: 'Zero Trust Maturity Metric Review',
        description: 'Audit success metrics: reduced lateral movement, 100% MFA adoption, access policy accuracy.',
        actions: [
          'Quarterly review of Zero Trust Technology Pillars.',
          'Conduct purple-team breach simulations to validate microsegmentation boundaries.',
        ],
      },
    ],
  },
  {
    id: 'PB-007',
    title: 'Enterprise Cyber Risk Assessment & Governance Register',
    category: 'Risk Governance',
    severity: 'medium',
    mitre_technique: 'Governance, Risk & Compliance (GRC)',
    sla_minutes: 240,
    summary: 'Executive leadership SOP for tracking, scoring, mitigating, and reviewing mission-critical cybersecurity risks.',
    description: 'Grounds incident handling in standard risk scoring: Risk Score = Likelihood (1-5) × Impact (1-5). Establishes executive accountability and mitigation milestone tracking.',
    protect_surfaces: ['Enterprise Risk Register', 'Regulatory Compliance Posture', 'Executive Oversight'],
    automation_support: false,
    steps: [
      {
        stage: 'Identification',
        step_number: 1,
        title: 'Log Risk Scenario & Impacted Business Function',
        description: 'Document the specific threat scenario, vulnerability, and potential operational consequence.',
        actions: [
          'Record risk identifier, title, description, and source in the enterprise risk register.',
          'Identify specific business assets, databases, or client services affected.',
        ],
      },
      {
        stage: 'Classification',
        step_number: 2,
        title: 'Calculate Qualitative & Quantitative Risk Score',
        description: 'Score Likelihood (1: Rare to 5: Almost Certain) and Impact (1: Negligible to 5: Catastrophic).',
        actions: [
          'Compute Risk Score = Likelihood × Impact (Scale: 1 - 25).',
          'Assign Risk Tier: Critical (20-25), High (15-19), Medium (8-14), Low (1-7).',
        ],
      },
      {
        stage: 'Containment',
        step_number: 3,
        title: 'Assign Executive Ownership & Establish Containment SLA',
        description: 'Designate responsible C-Suite / SOC Lead owner and define mitigation deadline.',
        actions: [
          'Assign Risk Owner (e.g. CISO, SOC Lead, Infrastructure Architect).',
          'Set containment SLA: Critical = 1 Hour, High = 4 Hours, Medium = 24 Hours.',
        ],
      },
      {
        stage: 'Eradication',
        step_number: 4,
        title: 'Formulate & Execute Mitigation Strategy',
        description: 'Implement administrative, physical, or technical security controls to reduce residual risk.',
        actions: [
          'Deploy defensive controls (firewall rules, patch deployment, MFA enforcement).',
          'Determine Residual Risk score after control implementation.',
        ],
      },
      {
        stage: 'Recovery',
        step_number: 5,
        title: 'Verify Control Effectiveness & Compliance Validation',
        description: 'Confirm that implemented controls operate as designed without business disruption.',
        actions: [
          'Audit SIEM telemetry and automated response logs.',
          'Verify alignment with NIST CSF, ISO 27001, and SOC2 frameworks.',
        ],
      },
      {
        stage: 'Lessons Learned',
        step_number: 6,
        title: 'Continuous Review Cycle & Risk Register Sign-off',
        description: 'Conduct scheduled review cycles and report status to executive risk committee.',
        actions: [
          'Schedule 30-day follow-up audit.',
          'Archive sign-off documentation into central audit registry.',
        ],
      },
    ],
  },
];

/* ==========================================================================
   Zero Trust Architecture Pillars Data
   ========================================================================== */

const ZTA_PILLARS = [
  {
    pillar: 'User Trust',
    focus: 'Identity, Multi-Factor Authentication (MFA), Least Privilege, Continuous Behavioral Analytics',
    monitored_controls: ['MFA Enforcement', 'JIT Privilege Elevation', 'Conditional Access Policies', 'Suspicious Logon Detection'],
    tools: ['Okta', 'Azure AD / Entra ID', 'Ping Identity', 'ThreadGrid AI Copilot'],
    metrics: '100% MFA adoption, zero standing domain administrator sessions, <2s anomaly flag',
    status: 'Operational',
    statusColor: '#10b981',
  },
  {
    pillar: 'Device Trust',
    focus: 'Endpoint Posture, OS Compliance, Hardware-Rooted Integrity, EDR Telemetry',
    monitored_controls: ['Secure Boot Verification', 'Disk Encryption (BitLocker/LUKS)', 'EDR Agent Health', 'Patch Level Compliance'],
    tools: ['CrowdStrike Falcon', 'SentinelOne', 'Microsoft Defender for Endpoint', 'ThreadGrid Collectors'],
    metrics: '<1% unmanaged device connections, 100% EDR telemetry streaming',
    status: 'Operational',
    statusColor: '#10b981',
  },
  {
    pillar: 'Application Trust',
    focus: 'Access Policies, Single Sign-On (SSO), Software-Defined Perimeter, API Authentication',
    monitored_controls: ['JWT / OAuth2 Token Validation', 'Per-Application Segmentation', 'WAF Protection', 'Rate Limiting'],
    tools: ['Zscaler ZPA', 'Cloudflare Access', 'Palo Alto Prisma Access', 'ThreadGrid Ingestion Middleware'],
    metrics: 'Zero implicit network trust, 100% authenticated API gateway routing',
    status: 'Operational',
    statusColor: '#10b981',
  },
  {
    pillar: 'Data Trust',
    focus: 'Data Classification (DAAS), AES-256 Encryption at Rest & in Transit, DLP Enforcement',
    monitored_controls: ['TLS 1.3 Strict Transport', 'Immutable Database WAL Logs', 'SHA-256 Event Fingerprinting', 'Audit Log Encryption'],
    tools: ['HashiCorp Vault', 'AWS KMS', 'SQLite WAL Mode', 'ThreadGrid Storage Sink'],
    metrics: '100% cryptographic integrity, zero unencrypted telemetry transmission',
    status: 'Compliant',
    statusColor: '#38bdf8',
  },
  {
    pillar: 'Network Trust',
    focus: 'Microsegmentation, Software-Defined Perimeter, Strict Boundary Ingress/Egress Filtering',
    monitored_controls: ['Host-based iptables/netsh isolation', 'Subnet Microsegmentation', 'Automated IP Quarantine', 'East-West Traffic Inspection'],
    tools: ['Iptables / Netfilter', 'Windows Advanced Firewall', 'Cisco Duo Network Gateway', 'ThreadGrid Response Engine'],
    metrics: '<5 min automated boundary containment, zero unauthorized lateral subnet traversal',
    status: 'Active Defense',
    statusColor: '#a855f7',
  },
];

/* ==========================================================================
   Main PlaybooksPage Component
   ========================================================================== */

export const PlaybooksPage: React.FC = () => {
  const navigate = useNavigate();

  // Tab State: 'catalog' | 'detail' | 'generator' | 'zerotrust' | 'risk'
  const [activeTab, setActiveTab] = useState<'catalog' | 'zerotrust' | 'generator' | 'risk'>('catalog');
  const [selectedPlaybook, setSelectedPlaybook] = useState<Playbook | null>(null);
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [selectedCategory, setSelectedCategory] = useState<string>('All');
  const [copiedIndex, setCopiedIndex] = useState<string | null>(null);

  // IR Generator State
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [selectedIncidentForIR, setSelectedIncidentForIR] = useState<string>('');
  const [irFormData, setIrFormData] = useState({
    incidentId: '',
    title: '',
    detectedTime: new Date().toISOString(),
    detectionSource: 'ThreadGrid Deterministic SIEM / Correlation Engine',
    initialIndicators: '',
    systemsAffected: '',
    severityLevel: 'High',
    incidentType: 'Unauthorized Access / Brute Force',
    scope: 'Host & Inbound Perimeter',
    containmentShortTerm: '',
    containmentLongTerm: '',
    rootCause: '',
    eradicationActions: '',
    toolsUsed: 'ThreadGrid Response Engine, iptables, netsh',
    recoverySystems: '',
    returnApprovedBy: 'Lead SOC Incident Commander',
    lessonsLearned: '',
    preventionMeasures: '',
  });
  const [copiedIR, setCopiedIR] = useState<boolean>(false);

  // Load incidents for IR Generator
  useEffect(() => {
    api.getIncidents({ limit: 50 })
      .then((res) => {
        if (res && res.incidents) {
          setIncidents(res.incidents);
          if (res.incidents.length > 0) {
            handleSelectIncidentToPrepopulate(res.incidents[0]);
          }
        }
      })
      .catch((err) => console.error('Failed to load incidents for IR generator:', err));
  }, []);

  const handleSelectIncidentToPrepopulate = (inc: Incident) => {
    setSelectedIncidentForIR(inc.incident_id);
    const ips = inc.entities.source_ips || [];
    const users = inc.entities.usernames || [];
    const hosts = inc.entities.hosts || [];

    setIrFormData({
      incidentId: inc.incident_id,
      title: inc.title,
      detectedTime: inc.first_seen,
      detectionSource: `ThreadGrid Detection Engine (${inc.distinct_rules.join(', ')})`,
      initialIndicators: `Observed correlated alerts: ${inc.related_alert_ids.join(', ')} across ${inc.related_event_ids.length} raw telemetry events.`,
      systemsAffected: `Target Host(s): ${hosts.join(', ') || 'N/A'} | Attacker IP(s): ${ips.join(', ') || 'N/A'} | User Account(s): ${users.join(', ') || 'N/A'}`,
      severityLevel: inc.severity.toUpperCase(),
      incidentType: inc.distinct_rules.includes('RULE-001')
        ? 'Single-Source SSH/Kerberos Brute Force'
        : inc.distinct_rules.includes('RULE-002')
        ? 'Credential Stuffing & Validated Compromise'
        : inc.distinct_rules.includes('RULE-004')
        ? 'Privileged Activity Escalation'
        : 'Suspicious Authentication Attack',
      scope: `Isolated Host (${hosts.join(', ')}) & Perimeter Ingress`,
      containmentShortTerm: ips.length > 0
        ? `Execute immediate perimeter firewall drop for IP ${ips.join(', ')}. Lock targeted user ${users.join(', ')}.`
        : 'Sever remote terminal sessions and monitor network ingress.',
      containmentLongTerm: 'Apply subnet microsegmentation, rotate compromised credentials, enforce strict public-key MFA.',
      rootCause: `High-frequency unauthorized access attempts exploiting exposed service port. Rule correlation verified risk score ${inc.risk_score.toFixed(1)}/100.`,
      eradicationActions: 'Terminated active rogue sessions, invalidated unauthorized SSH keys, verified shadow password database integrity.',
      toolsUsed: 'ThreadGrid Automated Response Engine, iptables, netsh advfirewall, fail2ban',
      recoverySystems: `Host ${hosts.join(', ')} connectivity restored after credential rotation and boundary drop validation.`,
      returnApprovedBy: 'Lead SOC Incident Commander / CISO',
      lessonsLearned: 'Exposure of password-based authentication to untrusted subnets allowed brute-force velocity. Moving to Zero Trust Architecture.',
      preventionMeasures: 'Deploy mandatory FIDO2 MFA, disable root password SSH logins, implement automated IP throttling via ipset.',
    });
  };

  const handleCopyCommand = (cmd: string, key: string) => {
    navigator.clipboard.writeText(cmd);
    setCopiedIndex(key);
    setTimeout(() => setCopiedIndex(null), 2500);
  };

  const generateMarkdownReport = () => {
    return `# Incident Response Report — ${irFormData.incidentId || 'INC-DRAFT'}
**Title:** ${irFormData.title}  
**Classification:** ${irFormData.severityLevel} Severity | Type: ${irFormData.incidentType}  
**Generated At:** ${new Date().toISOString()}  
**Reference Framework:** Military & Mission-Critical IR Lifecycle (NIST/DoD SOP)

---

## 1. Incident Identification
- **Date/Time Detected:** ${irFormData.detectedTime}
- **Detection Source:** ${irFormData.detectionSource}
- **Initial Indicators:** ${irFormData.initialIndicators}
- **Systems Affected:** ${irFormData.systemsAffected}

---

## 2. Incident Classification
- **Severity Level:** ${irFormData.severityLevel}
- **Threat Type:** ${irFormData.incidentType}
- **Scope:** ${irFormData.scope}

---

## 3. Containment Strategy
- **Short-Term (Immediate Action):**
  - ${irFormData.containmentShortTerm}
- **Long-Term (Sustained Containment):**
  - ${irFormData.containmentLongTerm}

---

## 4. Eradication Plan
- **Root Cause Identified:** ${irFormData.rootCause}
- **Actions Taken:** ${irFormData.eradicationActions}
- **Tools Used:** ${irFormData.toolsUsed}

---

## 5. Recovery Steps
- **Systems Restored:** ${irFormData.recoverySystems}
- **Monitoring in Place:** Continuous ThreadGrid SIEM rule correlation & EDR event streaming.
- **Return to Operations Approved By:** ${irFormData.returnApprovedBy}

---

## 6. Lessons Learned & Strategic Hardening
- **Incident Summary:** ${irFormData.lessonsLearned}
- **Prevention Measures:** ${irFormData.preventionMeasures}
- **Documentation Stored At:** ThreadGrid SIEM Audit Registry & Enterprise SharePoint

---

## 🧾 Appendix: Forensic Evidence & Audit Signatures
- **SIEM Engine:** ThreadGrid SIEM v1.0
- **Verification Hash:** SHA-256 Evidence Validated
`;
  };

  const handleCopyMarkdown = () => {
    navigator.clipboard.writeText(generateMarkdownReport());
    setCopiedIR(true);
    setTimeout(() => setCopiedIR(false), 3000);
  };

  const handleDownloadMarkdown = () => {
    const text = generateMarkdownReport();
    const blob = new Blob([text], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `IR_Report_${irFormData.incidentId || 'Incident'}.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const filteredPlaybooks = PLAYBOOKS_CATALOG.filter((pb) => {
    const matchesSearch =
      pb.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      pb.id.toLowerCase().includes(searchQuery.toLowerCase()) ||
      pb.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (pb.target_rule && pb.target_rule.toLowerCase().includes(searchQuery.toLowerCase()));

    const matchesCategory =
      selectedCategory === 'All' || pb.category === selectedCategory;

    return matchesSearch && matchesCategory;
  });

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      {/* ------------------------------------------------------------------- */}
      {/* Page Header                                                         */}
      {/* ------------------------------------------------------------------- */}
      <div
        className="soc-card"
        style={{
          padding: '1.25rem 1.5rem',
          background: 'linear-gradient(135deg, #0f172a 0%, #1e1b4b 100%)',
          border: '1px solid rgba(168, 85, 247, 0.3)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '1rem',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
          <div
            style={{
              width: '44px',
              height: '44px',
              borderRadius: '10px',
              background: 'linear-gradient(135deg, #f59e0b 0%, #d97706 100%)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              boxShadow: '0 0 15px rgba(245, 158, 11, 0.4)',
            }}
          >
            <BookOpen size={24} color="#ffffff" />
          </div>
          <div>
            <h1 style={{ fontSize: '1.35rem', fontWeight: 700, color: '#f8fafc', margin: 0, letterSpacing: '-0.01em' }}>
              Cybersecurity Incident Playbooks & SOPs
            </h1>
            <p style={{ fontSize: '0.8125rem', color: '#94a3b8', margin: '0.25rem 0 0 0' }}>
              Standard Operating Procedures based on military and mission-critical incident response frameworks & Zero Trust principles.
            </p>
          </div>
        </div>

        {/* Action button to stage actions */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <button
            onClick={() => navigate('/response')}
            style={{
              padding: '0.5rem 0.875rem',
              background: 'linear-gradient(135deg, #7c3aed 0%, #a855f7 100%)',
              color: '#ffffff',
              border: 'none',
              borderRadius: '8px',
              fontSize: '0.8125rem',
              fontWeight: 600,
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '0.375rem',
              boxShadow: '0 0 12px rgba(168, 85, 247, 0.4)',
            }}
          >
            <Zap size={15} />
            Response Console
          </button>
        </div>
      </div>

      {/* ------------------------------------------------------------------- */}
      {/* Top-Level KPI Summary Cards                                         */}
      {/* ------------------------------------------------------------------- */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '1rem' }}>
        <div className="soc-card" style={{ padding: '1rem 1.25rem', background: '#0f172a', borderLeft: '4px solid #f59e0b' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', color: '#94a3b8', fontSize: '0.75rem', fontWeight: 600, textTransform: 'uppercase' }}>
            <span>Active Playbooks</span>
            <BookOpen size={16} color="#f59e0b" />
          </div>
          <div style={{ fontSize: '1.75rem', fontWeight: 700, color: '#f8fafc', marginTop: '0.35rem' }}>
            {PLAYBOOKS_CATALOG.length} SOPs
          </div>
          <div style={{ fontSize: '0.6875rem', color: '#10b981', marginTop: '0.25rem' }}>
            100% Rule & Framework Coverage
          </div>
        </div>

        <div className="soc-card" style={{ padding: '1rem 1.25rem', background: '#0f172a', borderLeft: '4px solid #7c3aed' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', color: '#94a3b8', fontSize: '0.75rem', fontWeight: 600, textTransform: 'uppercase' }}>
            <span>Automated Execution</span>
            <Zap size={16} color="#a855f7" />
          </div>
          <div style={{ fontSize: '1.75rem', fontWeight: 700, color: '#f8fafc', marginTop: '0.35rem' }}>
            5 Procedures
          </div>
          <div style={{ fontSize: '0.6875rem', color: '#a855f7', marginTop: '0.25rem' }}>
            One-Click Response Console Staging
          </div>
        </div>

        <div className="soc-card" style={{ padding: '1rem 1.25rem', background: '#0f172a', borderLeft: '4px solid #10b981' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', color: '#94a3b8', fontSize: '0.75rem', fontWeight: 600, textTransform: 'uppercase' }}>
            <span>Zero Trust Compliance</span>
            <Shield size={16} color="#10b981" />
          </div>
          <div style={{ fontSize: '1.75rem', fontWeight: 700, color: '#f8fafc', marginTop: '0.35rem' }}>
            94.2%
          </div>
          <div style={{ fontSize: '0.6875rem', color: '#10b981', marginTop: '0.25rem' }}>
            5 Pillars Actively Monitored
          </div>
        </div>

        <div className="soc-card" style={{ padding: '1rem 1.25rem', background: '#0f172a', borderLeft: '4px solid #38bdf8' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', color: '#94a3b8', fontSize: '0.75rem', fontWeight: 600, textTransform: 'uppercase' }}>
            <span>Containment SLA</span>
            <Clock size={16} color="#38bdf8" />
          </div>
          <div style={{ fontSize: '1.75rem', fontWeight: 700, color: '#f8fafc', marginTop: '0.35rem' }}>
            ≤ 15 Minutes
          </div>
          <div style={{ fontSize: '0.6875rem', color: '#38bdf8', marginTop: '0.25rem' }}>
            Mission-Critical Containment Target
          </div>
        </div>
      </div>

      {/* ------------------------------------------------------------------- */}
      {/* Navigation Sub-Tabs                                                 */}
      {/* ------------------------------------------------------------------- */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: '0.5rem',
          borderBottom: '1px solid rgba(255, 255, 255, 0.08)',
          paddingBottom: '0.25rem',
          flexWrap: 'wrap',
        }}
      >
        <button
          onClick={() => setActiveTab('catalog')}
          style={{
            padding: '0.5rem 1rem',
            background: activeTab === 'catalog' ? 'rgba(245, 158, 11, 0.15)' : 'transparent',
            border: activeTab === 'catalog' ? '1px solid #f59e0b' : '1px solid transparent',
            borderRadius: '6px',
            color: activeTab === 'catalog' ? '#f59e0b' : '#94a3b8',
            fontWeight: 600,
            fontSize: '0.8125rem',
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: '0.375rem',
          }}
        >
          <BookOpen size={15} />
          Standard Incident Playbooks ({PLAYBOOKS_CATALOG.length})
        </button>

        <button
          onClick={() => setActiveTab('zerotrust')}
          style={{
            padding: '0.5rem 1rem',
            background: activeTab === 'zerotrust' ? 'rgba(16, 185, 129, 0.15)' : 'transparent',
            border: activeTab === 'zerotrust' ? '1px solid #10b981' : '1px solid transparent',
            borderRadius: '6px',
            color: activeTab === 'zerotrust' ? '#10b981' : '#94a3b8',
            fontWeight: 600,
            fontSize: '0.8125rem',
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: '0.375rem',
          }}
        >
          <Shield size={15} />
          Zero Trust Implementation Framework
        </button>

        <button
          onClick={() => setActiveTab('generator')}
          style={{
            padding: '0.5rem 1rem',
            background: activeTab === 'generator' ? 'rgba(124, 58, 237, 0.15)' : 'transparent',
            border: activeTab === 'generator' ? '1px solid #a855f7' : '1px solid transparent',
            borderRadius: '6px',
            color: activeTab === 'generator' ? '#d8b4fe' : '#94a3b8',
            fontWeight: 600,
            fontSize: '0.8125rem',
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: '0.375rem',
          }}
        >
          <FileText size={15} />
          IR Template Report Generator (Live Telemetry)
        </button>

        <button
          onClick={() => setActiveTab('risk')}
          style={{
            padding: '0.5rem 1rem',
            background: activeTab === 'risk' ? 'rgba(56, 189, 248, 0.15)' : 'transparent',
            border: activeTab === 'risk' ? '1px solid #38bdf8' : '1px solid transparent',
            borderRadius: '6px',
            color: activeTab === 'risk' ? '#38bdf8' : '#94a3b8',
            fontWeight: 600,
            fontSize: '0.8125rem',
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: '0.375rem',
          }}
        >
          <Activity size={15} />
          Enterprise Risk Governance Matrix
        </button>
      </div>

      {/* =================================================================== */}
      {/* TAB 1: STANDARD PLAYBOOKS CATALOG                                   */}
      {/* =================================================================== */}
      {activeTab === 'catalog' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          {/* Search & Category Filter Toolbar */}
          <div
            className="soc-card"
            style={{
              padding: '0.75rem 1rem',
              background: '#0f172a',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              gap: '1rem',
              flexWrap: 'wrap',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flex: 1, minWidth: '240px' }}>
              <Search size={15} color="#94a3b8" />
              <input
                type="text"
                placeholder="Search playbooks by title, MITRE technique, target rule, or keywords..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                style={{
                  width: '100%',
                  background: 'transparent',
                  border: 'none',
                  color: '#f8fafc',
                  fontSize: '0.8125rem',
                  outline: 'none',
                }}
              />
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem', flexWrap: 'wrap' }}>
              {['All', 'Threat Detection', 'Zero Trust', 'Risk Governance'].map((cat) => (
                <button
                  key={cat}
                  onClick={() => setSelectedCategory(cat)}
                  style={{
                    padding: '0.3rem 0.65rem',
                    background: selectedCategory === cat ? '#1e293b' : 'transparent',
                    border: selectedCategory === cat ? '1px solid #a855f7' : '1px solid transparent',
                    color: selectedCategory === cat ? '#f8fafc' : '#94a3b8',
                    borderRadius: '6px',
                    fontSize: '0.75rem',
                    cursor: 'pointer',
                  }}
                >
                  {cat}
                </button>
              ))}
            </div>
          </div>

          {/* Playbooks Grid */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(360px, 1fr))', gap: '1rem' }}>
            {filteredPlaybooks.map((pb) => {
              const severityColor =
                pb.severity === 'critical' ? '#ef4444' : pb.severity === 'high' ? '#f97316' : '#3b82f6';

              return (
                <div
                  key={pb.id}
                  className="soc-card"
                  style={{
                    padding: '1.25rem',
                    background: '#0f172a',
                    border: '1px solid rgba(255, 255, 255, 0.08)',
                    borderRadius: '10px',
                    display: 'flex',
                    flexDirection: 'column',
                    justifyContent: 'space-between',
                    gap: '1rem',
                    transition: 'all 0.2s ease',
                    cursor: 'pointer',
                  }}
                  onMouseEnter={(e) => {
                    e.currentTarget.style.borderColor = '#f59e0b';
                    e.currentTarget.style.transform = 'translateY(-2px)';
                  }}
                  onMouseLeave={(e) => {
                    e.currentTarget.style.borderColor = 'rgba(255, 255, 255, 0.08)';
                    e.currentTarget.style.transform = 'translateY(0)';
                  }}
                  onClick={() => setSelectedPlaybook(pb)}
                >
                  <div>
                    {/* Header Badges */}
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '0.5rem', marginBottom: '0.5rem' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                        <span
                          style={{
                            fontFamily: 'monospace',
                            fontSize: '0.75rem',
                            fontWeight: 700,
                            color: '#f59e0b',
                            background: 'rgba(245, 158, 11, 0.12)',
                            padding: '0.15rem 0.4rem',
                            borderRadius: '4px',
                            border: '1px solid rgba(245, 158, 11, 0.3)',
                          }}
                        >
                          {pb.id}
                        </span>
                        <span
                          style={{
                            fontSize: '0.6875rem',
                            fontWeight: 700,
                            color: severityColor,
                            background: `${severityColor}20`,
                            padding: '0.15rem 0.4rem',
                            borderRadius: '4px',
                            border: `1px solid ${severityColor}40`,
                            textTransform: 'uppercase',
                          }}
                        >
                          {pb.severity}
                        </span>
                      </div>

                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem', fontSize: '0.6875rem', color: '#94a3b8' }}>
                        <Clock size={12} />
                        <span>SLA {pb.sla_minutes}m</span>
                      </div>
                    </div>

                    {/* Title & Summary */}
                    <h3 style={{ fontSize: '0.9375rem', fontWeight: 600, color: '#f8fafc', margin: '0 0 0.4rem 0', lineHeight: 1.35 }}>
                      {pb.title}
                    </h3>
                    <p style={{ fontSize: '0.78125rem', color: '#94a3b8', margin: 0, lineHeight: 1.45 }}>
                      {pb.summary}
                    </p>

                    {/* MITRE & Target Rule */}
                    <div style={{ marginTop: '0.75rem', display: 'flex', flexDirection: 'column', gap: '0.25rem', fontSize: '0.7rem' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem', color: '#cbd5e1' }}>
                        <span style={{ color: '#64748b' }}>MITRE:</span>
                        <span style={{ fontFamily: 'monospace', color: '#38bdf8' }}>{pb.mitre_technique}</span>
                      </div>
                      {pb.target_rule && (
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem', color: '#cbd5e1' }}>
                          <span style={{ color: '#64748b' }}>Detection:</span>
                          <span style={{ fontFamily: 'monospace', color: '#a855f7' }}>{pb.target_rule}</span>
                        </div>
                      )}
                    </div>
                  </div>

                  {/* Card Footer */}
                  <div
                    style={{
                      borderTop: '1px solid rgba(255, 255, 255, 0.06)',
                      paddingTop: '0.75rem',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      fontSize: '0.75rem',
                    }}
                  >
                    <span style={{ color: pb.automation_support ? '#10b981' : '#94a3b8', display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
                      {pb.automation_support ? <Zap size={13} /> : <BookOpen size={13} />}
                      {pb.automation_support ? 'Automated Response Ready' : 'Leadership SOP'}
                    </span>
                    <span style={{ color: '#a855f7', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '0.2rem' }}>
                      View Lifecycle <ArrowRight size={13} />
                    </span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* =================================================================== */}
      {/* PLAYBOOK DETAIL MODAL / DRAWER                                      */}
      {/* =================================================================== */}
      {selectedPlaybook && (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            backgroundColor: 'rgba(0, 0, 0, 0.75)',
            backdropFilter: 'blur(5px)',
            zIndex: 9999,
            display: 'flex',
            justifyContent: 'flex-end',
          }}
          onClick={() => setSelectedPlaybook(null)}
        >
          <div
            style={{
              width: '740px',
              maxWidth: '100vw',
              height: '100vh',
              background: '#090d16',
              borderLeft: '1px solid rgba(168, 85, 247, 0.35)',
              boxShadow: '-20px 0 50px rgba(0, 0, 0, 0.8)',
              display: 'flex',
              flexDirection: 'column',
              overflow: 'hidden',
              cursor: 'default',
            }}
            onClick={(e) => e.stopPropagation()}
          >
            {/* Drawer Header */}
            <div
              style={{
                padding: '1.25rem 1.5rem',
                background: 'linear-gradient(90deg, #1e1b4b 0%, #0f172a 100%)',
                borderBottom: '1px solid rgba(255, 255, 255, 0.1)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                gap: '1rem',
              }}
            >
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.35rem' }}>
                  <span style={{ padding: '0.15rem 0.5rem', borderRadius: '4px', background: 'rgba(245, 158, 11, 0.2)', border: '1px solid #f59e0b', color: '#f59e0b', fontSize: '0.75rem', fontWeight: 700 }}>
                    {selectedPlaybook.id}
                  </span>
                  <span style={{ padding: '0.15rem 0.5rem', borderRadius: '4px', background: 'rgba(124, 58, 237, 0.2)', border: '1px solid #7c3aed', color: '#d8b4fe', fontSize: '0.75rem', fontWeight: 600 }}>
                    {selectedPlaybook.category}
                  </span>
                </div>
                <h2 style={{ fontSize: '1.15rem', fontWeight: 700, color: '#f8fafc', margin: 0, lineHeight: 1.3 }}>
                  {selectedPlaybook.title}
                </h2>
              </div>

              <button
                onClick={() => setSelectedPlaybook(null)}
                style={{
                  background: 'transparent',
                  border: 'none',
                  color: '#94a3b8',
                  cursor: 'pointer',
                  padding: '0.4rem',
                  borderRadius: '6px',
                }}
                onMouseEnter={(e) => (e.currentTarget.style.color = '#ef4444')}
                onMouseLeave={(e) => (e.currentTarget.style.color = '#94a3b8')}
              >
                <X size={20} />
              </button>
            </div>

            {/* Drawer Scrollable Body */}
            <div
              style={{
                flex: 1,
                overflowY: 'auto',
                padding: '1.5rem',
                display: 'flex',
                flexDirection: 'column',
                gap: '1.25rem',
                scrollbarWidth: 'thin',
              }}
            >
              {/* Overview & Metadata Card */}
              <div className="soc-card" style={{ padding: '1rem', background: '#0f172a', border: '1px solid rgba(255, 255, 255, 0.08)' }}>
                <p style={{ fontSize: '0.8125rem', color: '#cbd5e1', margin: 0, lineHeight: 1.5 }}>
                  {selectedPlaybook.description}
                </p>
                <div style={{ marginTop: '0.75rem', display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '0.5rem', fontSize: '0.75rem' }}>
                  <div>
                    <span style={{ color: '#64748b' }}>MITRE ATT&CK: </span>
                    <span style={{ color: '#38bdf8', fontFamily: 'monospace' }}>{selectedPlaybook.mitre_technique}</span>
                  </div>
                  <div>
                    <span style={{ color: '#64748b' }}>Response SLA: </span>
                    <span style={{ color: '#f59e0b', fontWeight: 600 }}>≤ {selectedPlaybook.sla_minutes} Minutes</span>
                  </div>
                  <div style={{ gridColumn: 'span 2' }}>
                    <span style={{ color: '#64748b' }}>Protect Surfaces: </span>
                    <span style={{ color: '#f8fafc' }}>{selectedPlaybook.protect_surfaces.join(', ')}</span>
                  </div>
                </div>
              </div>

              {/* 6-Stage Incident Response Lifecycle Steps */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.875rem' }}>
                <h3 style={{ fontSize: '0.875rem', fontWeight: 700, color: '#f8fafc', textTransform: 'uppercase', letterSpacing: '0.05em', margin: 0, display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                  <Layers size={16} color="#f59e0b" />
                  6-Stage Mission-Critical Response Lifecycle
                </h3>

                {selectedPlaybook.steps.map((st) => (
                  <div
                    key={st.step_number}
                    className="soc-card"
                    style={{
                      padding: '1rem',
                      background: '#0f172a',
                      borderLeft: `4px solid ${
                        st.stage === 'Identification'
                          ? '#38bdf8'
                          : st.stage === 'Classification'
                          ? '#f59e0b'
                          : st.stage === 'Containment'
                          ? '#ef4444'
                          : st.stage === 'Eradication'
                          ? '#a855f7'
                          : st.stage === 'Recovery'
                          ? '#10b981'
                          : '#64748b'
                      }`,
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '0.5rem', marginBottom: '0.35rem' }}>
                      <span style={{ fontSize: '0.75rem', fontWeight: 700, textTransform: 'uppercase', color: '#94a3b8' }}>
                        Stage {st.step_number}: {st.stage}
                      </span>
                      {st.automated && (
                        <span style={{ fontSize: '0.6875rem', padding: '0.1rem 0.4rem', borderRadius: '4px', background: 'rgba(16, 185, 129, 0.15)', color: '#10b981', border: '1px solid rgba(16, 185, 129, 0.3)', fontWeight: 600 }}>
                          ⚡ Automated
                        </span>
                      )}
                    </div>

                    <h4 style={{ fontSize: '0.875rem', fontWeight: 600, color: '#f8fafc', margin: '0 0 0.35rem 0' }}>
                      {st.title}
                    </h4>
                    <p style={{ fontSize: '0.78125rem', color: '#94a3b8', margin: '0 0 0.5rem 0', lineHeight: 1.45 }}>
                      {st.description}
                    </p>

                    {/* Action Items List */}
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem', marginTop: '0.5rem' }}>
                      {st.actions.map((act, aIdx) => (
                        <div key={aIdx} style={{ display: 'flex', alignItems: 'flex-start', gap: '0.35rem', fontSize: '0.75rem', color: '#cbd5e1' }}>
                          <CheckCircle2 size={13} color="#10b981" style={{ marginTop: '0.15rem', flexShrink: 0 }} />
                          <span>{act}</span>
                        </div>
                      ))}
                    </div>

                    {/* Copyable CLI Commands (if present) */}
                    {st.cli_commands && st.cli_commands.length > 0 && (
                      <div style={{ marginTop: '0.75rem', display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                        {st.cli_commands.map((cmd, cIdx) => {
                          const copyKey = `${st.step_number}-${cIdx}`;
                          return (
                            <div
                              key={cIdx}
                              style={{
                                background: '#090d16',
                                border: '1px solid #1e293b',
                                borderRadius: '6px',
                                padding: '0.5rem 0.75rem',
                                position: 'relative',
                              }}
                            >
                              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.25rem' }}>
                                <span style={{ fontSize: '0.6875rem', color: '#64748b', fontFamily: 'monospace' }}>
                                  Terminal Command
                                </span>
                                <button
                                  onClick={() => handleCopyCommand(cmd, copyKey)}
                                  style={{
                                    background: 'transparent',
                                    border: 'none',
                                    color: copiedIndex === copyKey ? '#10b981' : '#94a3b8',
                                    fontSize: '0.6875rem',
                                    cursor: 'pointer',
                                    display: 'flex',
                                    alignItems: 'center',
                                    gap: '0.2rem',
                                  }}
                                >
                                  {copiedIndex === copyKey ? <Check size={12} /> : <Copy size={12} />}
                                  {copiedIndex === copyKey ? 'Copied' : 'Copy'}
                                </button>
                              </div>
                              <pre style={{ margin: 0, fontSize: '0.75rem', color: '#38bdf8', fontFamily: 'monospace', whiteSpace: 'pre-wrap', lineHeight: 1.4 }}>
                                {cmd}
                              </pre>
                            </div>
                          );
                        })}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>

            {/* Drawer Footer Actions */}
            <div
              style={{
                padding: '1rem 1.5rem',
                background: '#0b1120',
                borderTop: '1px solid rgba(255, 255, 255, 0.1)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
              }}
            >
              <button
                onClick={() => setSelectedPlaybook(null)}
                style={{
                  padding: '0.5rem 1rem',
                  background: '#1e293b',
                  color: '#cbd5e1',
                  border: '1px solid #334155',
                  borderRadius: '6px',
                  fontSize: '0.8125rem',
                  cursor: 'pointer',
                }}
              >
                Close Playbook
              </button>

              <button
                onClick={() => {
                  setSelectedPlaybook(null);
                  navigate('/response');
                }}
                style={{
                  padding: '0.5rem 1.25rem',
                  background: 'linear-gradient(135deg, #7c3aed 0%, #a855f7 100%)',
                  color: '#ffffff',
                  border: 'none',
                  borderRadius: '6px',
                  fontSize: '0.8125rem',
                  fontWeight: 600,
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.35rem',
                  boxShadow: '0 0 12px rgba(168, 85, 247, 0.4)',
                }}
              >
                <Zap size={14} />
                Stage in Response Console
              </button>
            </div>
          </div>
        </div>
      )}

      {/* =================================================================== */}
      {/* TAB 2: ZERO TRUST ARCHITECTURE FRAMEWORK                            */}
      {/* =================================================================== */}
      {activeTab === 'zerotrust' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
          <div className="soc-card" style={{ padding: '1.25rem', background: '#0f172a', border: '1px solid rgba(16, 185, 129, 0.3)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '0.5rem' }}>
              <Shield size={22} color="#10b981" />
              <h2 style={{ fontSize: '1.15rem', fontWeight: 700, color: '#f8fafc', margin: 0 }}>
                Zero Trust Architecture Implementation Guide
              </h2>
            </div>
            <p style={{ fontSize: '0.8125rem', color: '#cbd5e1', lineHeight: 1.5, margin: 0 }}>
              Based on the core philosophy <strong>"Never Trust, Always Verify"</strong> — assuming threats exist both inside and outside the perimeter.
              Requires continuous multi-attribute identity verification, software-defined microsegmentation, and real-time SIEM inspection.
            </p>
          </div>

          {/* 5 Technology Pillars Cards */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '1rem' }}>
            {ZTA_PILLARS.map((p, idx) => (
              <div
                key={idx}
                className="soc-card"
                style={{
                  padding: '1.25rem',
                  background: '#0f172a',
                  borderTop: `4px solid ${p.statusColor}`,
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '0.75rem',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <h3 style={{ fontSize: '1rem', fontWeight: 700, color: '#f8fafc', margin: 0 }}>
                    {p.pillar}
                  </h3>
                  <span style={{ fontSize: '0.6875rem', fontWeight: 700, color: p.statusColor, background: `${p.statusColor}20`, padding: '0.15rem 0.45rem', borderRadius: '4px', border: `1px solid ${p.statusColor}40` }}>
                    {p.status}
                  </span>
                </div>

                <p style={{ fontSize: '0.78125rem', color: '#94a3b8', margin: 0, lineHeight: 1.45 }}>
                  {p.focus}
                </p>

                <div style={{ fontSize: '0.75rem', display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
                  <span style={{ color: '#64748b', fontWeight: 600 }}>Monitored Controls:</span>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.25rem' }}>
                    {p.monitored_controls.map((c, cIdx) => (
                      <span key={cIdx} style={{ fontSize: '0.6875rem', padding: '0.1rem 0.35rem', background: '#1e293b', color: '#cbd5e1', borderRadius: '3px' }}>
                        {c}
                      </span>
                    ))}
                  </div>
                </div>

                <div style={{ borderTop: '1px solid rgba(255, 255, 255, 0.06)', paddingTop: '0.5rem', fontSize: '0.71875rem', color: '#94a3b8' }}>
                  <div><strong style={{ color: '#cbd5e1' }}>Integrated Tooling:</strong> {p.tools.join(', ')}</div>
                  <div style={{ marginTop: '0.25rem' }}><strong style={{ color: '#cbd5e1' }}>Success Metric:</strong> {p.metrics}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* =================================================================== */}
      {/* TAB 3: INCIDENT RESPONSE (IR) TEMPLATE GENERATOR                     */}
      {/* =================================================================== */}
      {activeTab === 'generator' && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(440px, 1fr))', gap: '1.25rem' }}>
          {/* Left Form: Field Inputs */}
          <div className="soc-card" style={{ padding: '1.25rem', background: '#0f172a', display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', borderBottom: '1px solid rgba(255, 255, 255, 0.08)', paddingBottom: '0.75rem' }}>
              <div>
                <h3 style={{ fontSize: '1rem', fontWeight: 700, color: '#f8fafc', margin: 0 }}>
                  Incident Response (IR) Report Builder
                </h3>
                <span style={{ fontSize: '0.75rem', color: '#94a3b8' }}>
                  Military Standard IR Template with Live Telemetry Ingestion
                </span>
              </div>

              {/* Prepopulate from Active Incident */}
              {incidents.length > 0 && (
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                  <span style={{ fontSize: '0.75rem', color: '#94a3b8' }}>Auto-Fill:</span>
                  <select
                    value={selectedIncidentForIR}
                    onChange={(e) => {
                      const inc = incidents.find((i) => i.incident_id === e.target.value);
                      if (inc) handleSelectIncidentToPrepopulate(inc);
                    }}
                    style={{
                      padding: '0.3rem 0.5rem',
                      background: '#1e293b',
                      color: '#f8fafc',
                      border: '1px solid #334155',
                      borderRadius: '4px',
                      fontSize: '0.75rem',
                      outline: 'none',
                    }}
                  >
                    {incidents.map((inc) => (
                      <option key={inc.incident_id} value={inc.incident_id}>
                        {inc.incident_id} ({inc.severity})
                      </option>
                    ))}
                  </select>
                </div>
              )}
            </div>

            {/* Form Fields */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', fontSize: '0.78125rem' }}>
              <div>
                <label style={{ display: 'block', color: '#94a3b8', marginBottom: '0.25rem' }}>Incident Title:</label>
                <input
                  type="text"
                  value={irFormData.title}
                  onChange={(e) => setIrFormData({ ...irFormData, title: e.target.value })}
                  style={{ width: '100%', padding: '0.4rem 0.6rem', background: '#1e293b', color: '#f8fafc', border: '1px solid #334155', borderRadius: '4px' }}
                />
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '0.5rem' }}>
                <div>
                  <label style={{ display: 'block', color: '#94a3b8', marginBottom: '0.25rem' }}>Severity Level:</label>
                  <select
                    value={irFormData.severityLevel}
                    onChange={(e) => setIrFormData({ ...irFormData, severityLevel: e.target.value })}
                    style={{ width: '100%', padding: '0.4rem 0.6rem', background: '#1e293b', color: '#f8fafc', border: '1px solid #334155', borderRadius: '4px' }}
                  >
                    <option value="CRITICAL">CRITICAL</option>
                    <option value="HIGH">HIGH</option>
                    <option value="MEDIUM">MEDIUM</option>
                    <option value="LOW">LOW</option>
                  </select>
                </div>
                <div>
                  <label style={{ display: 'block', color: '#94a3b8', marginBottom: '0.25rem' }}>Threat Type:</label>
                  <input
                    type="text"
                    value={irFormData.incidentType}
                    onChange={(e) => setIrFormData({ ...irFormData, incidentType: e.target.value })}
                    style={{ width: '100%', padding: '0.4rem 0.6rem', background: '#1e293b', color: '#f8fafc', border: '1px solid #334155', borderRadius: '4px' }}
                  />
                </div>
              </div>

              <div>
                <label style={{ display: 'block', color: '#94a3b8', marginBottom: '0.25rem' }}>Systems & Assets Affected:</label>
                <input
                  type="text"
                  value={irFormData.systemsAffected}
                  onChange={(e) => setIrFormData({ ...irFormData, systemsAffected: e.target.value })}
                  style={{ width: '100%', padding: '0.4rem 0.6rem', background: '#1e293b', color: '#f8fafc', border: '1px solid #334155', borderRadius: '4px' }}
                />
              </div>

              <div>
                <label style={{ display: 'block', color: '#94a3b8', marginBottom: '0.25rem' }}>Immediate Containment Strategy:</label>
                <textarea
                  rows={2}
                  value={irFormData.containmentShortTerm}
                  onChange={(e) => setIrFormData({ ...irFormData, containmentShortTerm: e.target.value })}
                  style={{ width: '100%', padding: '0.4rem 0.6rem', background: '#1e293b', color: '#f8fafc', border: '1px solid #334155', borderRadius: '4px', resize: 'vertical' }}
                />
              </div>

              <div>
                <label style={{ display: 'block', color: '#94a3b8', marginBottom: '0.25rem' }}>Root Cause Description:</label>
                <textarea
                  rows={2}
                  value={irFormData.rootCause}
                  onChange={(e) => setIrFormData({ ...irFormData, rootCause: e.target.value })}
                  style={{ width: '100%', padding: '0.4rem 0.6rem', background: '#1e293b', color: '#f8fafc', border: '1px solid #334155', borderRadius: '4px', resize: 'vertical' }}
                />
              </div>

              <div>
                <label style={{ display: 'block', color: '#94a3b8', marginBottom: '0.25rem' }}>Lessons Learned & Future Safeguards:</label>
                <textarea
                  rows={2}
                  value={irFormData.lessonsLearned}
                  onChange={(e) => setIrFormData({ ...irFormData, lessonsLearned: e.target.value })}
                  style={{ width: '100%', padding: '0.4rem 0.6rem', background: '#1e293b', color: '#f8fafc', border: '1px solid #334155', borderRadius: '4px', resize: 'vertical' }}
                />
              </div>
            </div>
          </div>

          {/* Right Column: Live Markdown Document Preview */}
          <div className="soc-card" style={{ padding: '1.25rem', background: '#090d16', display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', borderBottom: '1px solid rgba(255, 255, 255, 0.08)', paddingBottom: '0.5rem' }}>
              <span style={{ fontSize: '0.8125rem', fontWeight: 600, color: '#cbd5e1' }}>
                📄 Live Markdown Report Preview
              </span>

              <div style={{ display: 'flex', gap: '0.35rem' }}>
                <button
                  onClick={handleCopyMarkdown}
                  style={{
                    padding: '0.3rem 0.65rem',
                    background: copiedIR ? '#10b981' : '#1e293b',
                    color: '#ffffff',
                    border: '1px solid rgba(255, 255, 255, 0.1)',
                    borderRadius: '4px',
                    fontSize: '0.75rem',
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.25rem',
                  }}
                >
                  {copiedIR ? <Check size={13} /> : <Copy size={13} />}
                  {copiedIR ? 'Copied Markdown' : 'Copy'}
                </button>

                <button
                  onClick={handleDownloadMarkdown}
                  style={{
                    padding: '0.3rem 0.65rem',
                    background: 'linear-gradient(135deg, #7c3aed 0%, #a855f7 100%)',
                    color: '#ffffff',
                    border: 'none',
                    borderRadius: '4px',
                    fontSize: '0.75rem',
                    fontWeight: 600,
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.25rem',
                  }}
                >
                  <Download size={13} />
                  Download .md
                </button>
              </div>
            </div>

            <pre
              style={{
                flex: 1,
                maxHeight: '440px',
                overflowY: 'auto',
                background: '#040711',
                padding: '0.875rem',
                borderRadius: '6px',
                fontSize: '0.71875rem',
                color: '#38bdf8',
                fontFamily: 'monospace',
                whiteSpace: 'pre-wrap',
                margin: 0,
                lineHeight: 1.45,
                border: '1px solid rgba(255, 255, 255, 0.04)',
                scrollbarWidth: 'thin',
              }}
            >
              {generateMarkdownReport()}
            </pre>
          </div>
        </div>
      )}

      {/* =================================================================== */}
      {/* TAB 4: ENTERPRISE RISK GOVERNANCE MATRIX                            */}
      {/* =================================================================== */}
      {activeTab === 'risk' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          <div className="soc-card" style={{ padding: '1.25rem', background: '#0f172a', borderLeft: '4px solid #38bdf8' }}>
            <h3 style={{ fontSize: '1rem', fontWeight: 700, color: '#f8fafc', margin: '0 0 0.35rem 0' }}>
              Enterprise Cyber Risk Scoring & Threat Governance
            </h3>
            <p style={{ fontSize: '0.8125rem', color: '#94a3b8', margin: 0, lineHeight: 1.5 }}>
              Calculated via standardized matrix: <strong>Risk Score = Likelihood (1 - 5) × Impact (1 - 5)</strong>.
              Categorizes operational exposures, enforces containment SLAs, and binds executive ownership.
            </p>
          </div>

          {/* Risk Table */}
          <div className="soc-card" style={{ padding: '0', background: '#0f172a', overflow: 'hidden' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.78125rem', textAlign: 'left' }}>
              <thead>
                <tr style={{ background: '#0b1120', borderBottom: '1px solid rgba(255, 255, 255, 0.08)', color: '#94a3b8' }}>
                  <th style={{ padding: '0.75rem 1rem' }}>Risk ID</th>
                  <th style={{ padding: '0.75rem 1rem' }}>Threat Scenario</th>
                  <th style={{ padding: '0.75rem 1rem' }}>Likelihood</th>
                  <th style={{ padding: '0.75rem 1rem' }}>Impact</th>
                  <th style={{ padding: '0.75rem 1rem' }}>Risk Score</th>
                  <th style={{ padding: '0.75rem 1rem' }}>Risk Owner</th>
                  <th style={{ padding: '0.75rem 1rem' }}>Mitigation SLA</th>
                </tr>
              </thead>
              <tbody>
                {[
                  { id: 'RSK-001', scenario: 'Sustained Public-Facing SSH Brute Force', l: 5, i: 4, score: 20, tier: 'Critical', owner: 'SOC Lead', sla: '1 Hour' },
                  { id: 'RSK-002', scenario: 'Credential Stuffing with Successful Auth', l: 4, i: 5, score: 20, tier: 'Critical', owner: 'CISO / IR Lead', sla: '1 Hour' },
                  { id: 'RSK-003', scenario: 'Distributed Password Spraying on Executive Identity', l: 4, i: 4, score: 16, tier: 'High', owner: 'IAM Team Lead', sla: '4 Hours' },
                  { id: 'RSK-004', scenario: 'Unprivileged User Execution of SUID Binaries', l: 3, i: 5, score: 15, tier: 'High', owner: 'Infrastructure Lead', sla: '4 Hours' },
                  { id: 'RSK-005', scenario: 'Account Discovery & User Enumeration Reconnaissance', l: 4, i: 2, score: 8, tier: 'Medium', owner: 'Network Security', sla: '24 Hours' },
                  { id: 'RSK-006', scenario: 'Lack of Centralized Multi-Factor Authentication', l: 3, i: 4, score: 12, tier: 'Medium', owner: 'Enterprise Architect', sla: '24 Hours' },
                ].map((row, rIdx) => {
                  const scoreColor = row.score >= 18 ? '#ef4444' : row.score >= 14 ? '#f97316' : '#38bdf8';
                  return (
                    <tr
                      key={row.id}
                      style={{
                        borderBottom: '1px solid rgba(255, 255, 255, 0.04)',
                        background: rIdx % 2 === 0 ? 'transparent' : 'rgba(255, 255, 255, 0.01)',
                      }}
                    >
                      <td style={{ padding: '0.75rem 1rem', fontFamily: 'monospace', color: '#f59e0b', fontWeight: 600 }}>{row.id}</td>
                      <td style={{ padding: '0.75rem 1rem', color: '#f8fafc', fontWeight: 500 }}>{row.scenario}</td>
                      <td style={{ padding: '0.75rem 1rem', color: '#cbd5e1' }}>{row.l} / 5</td>
                      <td style={{ padding: '0.75rem 1rem', color: '#cbd5e1' }}>{row.i} / 5</td>
                      <td style={{ padding: '0.75rem 1rem' }}>
                        <span style={{ padding: '0.15rem 0.45rem', borderRadius: '4px', background: `${scoreColor}20`, color: scoreColor, fontWeight: 700 }}>
                          {row.score} ({row.tier})
                        </span>
                      </td>
                      <td style={{ padding: '0.75rem 1rem', color: '#cbd5e1' }}>{row.owner}</td>
                      <td style={{ padding: '0.75rem 1rem', color: '#94a3b8' }}>{row.sla}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};

export default PlaybooksPage;
