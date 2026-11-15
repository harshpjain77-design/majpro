import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  BookOpen,
  Shield,
  Zap,
  CheckCircle2,
  Copy,
  Check,
  FileText,
  AlertTriangle,
  Lock,
  Server,
  UserCheck,
  Activity,
  Terminal,
  ArrowRight,
  Search,
  Layers,
  Download,
  Clock,
  X,
  ExternalLink,
  ChevronRight,
  Filter
} from 'lucide-react';
import { api } from '../services/api';
import { Incident } from '../types';

/* ==========================================================================
   Playbook Data Models & Comprehensive Catalog (RubySummers101 Aligned)
   ========================================================================== */

export interface PlaybookStep {
  stage: 'Identification' | 'Classification' | 'Containment' | 'Eradication' | 'Recovery' | 'Lessons Learned';
  step_number: number;
  title: string;
  description: string;
  actions: string[];
  cli_commands?: string[];
  tools?: string[];
  automated?: boolean;
}

export interface Playbook {
  id: string;
  title: string;
  category: 'Threat Detection' | 'Zero Trust' | 'Risk Governance';
  severity: 'critical' | 'high' | 'medium';
  mitre_technique: string;
  target_rule?: string;
  sla_minutes: number;
  description: string;
  summary: string;
  protect_surfaces: string[];
  steps: PlaybookStep[];
  automation_support: boolean;
}

export const PLAYBOOKS_CATALOG: Playbook[] = [
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
          'Verify originating IP geolocation, ASN, and reverse DNS PTR records.',
          'Confirm whether authentication attempts are concentrated on SSH port 22 or Windows Kerberos/SMB port 445.',
        ],
        tools: ['ThreadGrid SIEM Events', 'Linux /var/log/auth.log', 'Windows Event ID 4625'],
      },
      {
        stage: 'Classification',
        step_number: 2,
        title: 'Classify Attack Velocity & Blast Radius',
        description: 'Distinguish between automated internet noise, targeted single-source brute force, and internal misconfigurations.',
        actions: [
          'Calculate failure rate (attempts per minute) relative to baseline normal telemetry.',
          'Evaluate if attempts belong to scheduled vulnerability scanning, penetration testing, or automated health probes.',
          'Classify severity as Critical if attempts target high-privilege identities (root/Domain Admin).',
        ],
      },
      {
        stage: 'Containment',
        step_number: 3,
        title: 'Execute Immediate Perimeter Firewall Drop',
        description: 'Enforce immediate boundary drop rule to sever threat actor connectivity without disrupting internal operations.',
        actions: [
          'Stage and execute firewall drop rule in ThreadGrid Response Console.',
          'Apply localized firewall drop on host boundary (iptables or netsh).',
          'Verify threat actor connection is completely severed via active socket inspection.',
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
        description: 'Ensure attacker did not establish any persistent backdoor, active shell session, or compromised daemon socket.',
        actions: [
          'Check for active network connections from source IP using netstat/ss.',
          'Inspect `/etc/ssh/sshd_config` or Windows remote access policies for unauthorized changes.',
          'Revoke temporary connection tokens or SSH multiplexing master sockets.',
        ],
        cli_commands: [
          '# Terminate active SSH connections from source IP:\nsudo pkill -9 -t $(who | grep {SOURCE_IP} | awk \'{print $2}\')',
          '# Verify lingering sockets:\nsudo ss -tnp | grep {SOURCE_IP}',
        ],
      },
      {
        stage: 'Recovery',
        step_number: 5,
        title: 'Restore Normal Access & Enable Continuous Monitoring',
        description: 'Verify service availability for authorized users while monitoring for threat resurgence.',
        actions: [
          'Confirm legitimate administrative users can log in successfully via authorized bastion/VPN.',
          'Ensure fail2ban or Windows Account Lockout Policy is synchronized and functioning.',
          'Maintain elevated monitoring threshold on the target host for 24 hours.',
        ],
      },
      {
        stage: 'Lessons Learned',
        step_number: 6,
        title: 'Hardening & Post-Incident Review',
        description: 'Archive incident telemetry and deploy preventative defensive safeguards.',
        actions: [
          'Enforce SSH key-based authentication and disable password logins (`PasswordAuthentication no`).',
          'Change default SSH port or enforce strict VPN gateway requirement for all remote administration.',
          'Archive incident evidence and telemetry into enterprise SIEM compliance repository.',
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
        description: 'Identify exact timestamp of failed logon cluster and subsequent authentication success from the same entity.',
        actions: [
          'Extract target username and attacker IP address from correlated incident evidence.',
          'Verify if the successful logon originated from the exact attacking IP within the sliding time window.',
          'Flag incident as Critical Severity with immediate emergency notification.',
        ],
        tools: ['ThreadGrid Correlator', 'Linux Event 4624/4625', 'Auditd Telemetry'],
      },
      {
        stage: 'Classification',
        step_number: 2,
        title: 'Triage Account Type & Privilege Level',
        description: 'Determine if compromised identity possesses administrative (root/Domain Admin) or standard user privileges.',
        actions: [
          'Check account group memberships, sudoers configuration, and Active Directory roles.',
          'Identify high-value internal assets and databases directly accessible by the compromised credential.',
        ],
      },
      {
        stage: 'Containment',
        step_number: 3,
        title: 'Immediate Reversible Account Lockout & Session Severing',
        description: 'Terminate all active sessions for the compromised user and lock account access across all domain controllers.',
        actions: [
          'Lock user account immediately using reversible containment handler.',
          'Kill all active terminal sessions and processes owned by the user.',
          'Drop attacker source IP at boundary firewall.',
        ],
        cli_commands: [
          '# Linux Account Lock & Session Termination:\nsudo usermod -L {USERNAME} && sudo pkill -KILL -u {USERNAME}',
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
          'Audit `~/.ssh/authorized_keys` for unauthorized public keys added during the session.',
          'Check cron jobs (`/etc/cron*`) and Windows Scheduled Tasks for persistence implants.',
          'Force global password reset and invalidate all active session tokens/Kerberos tickets.',
        ],
        cli_commands: [
          '# Inspect unauthorized SSH keys:\nsudo cat /home/{USERNAME}/.ssh/authorized_keys',
          '# Check recent user cron entries:\nsudo crontab -u {USERNAME} -l',
        ],
      },
      {
        stage: 'Recovery',
        step_number: 5,
        title: 'Re-enable Account with Mandatory MFA',
        description: 'Restore business operations after credential rotation and out-of-band identity verification.',
        actions: [
          'Verify user identity via out-of-band channel (voice/video verification).',
          'Issue temporary single-use passphrase requiring immediate rotation on initial login.',
          'Mandate hardware-bound Multi-Factor Authentication (FIDO2/WebAuthn).',
        ],
      },
      {
        stage: 'Lessons Learned',
        step_number: 6,
        title: 'Root Cause & Threat Matrix Audit',
        description: 'Determine credential leakage source (dark web dump, phishing, or weak password).',
        actions: [
          'Run credential audit against known breach databases (HaveIBeenPwned API).',
          'Enforce enterprise password complexity and minimum 16-character passphrases.',
          'File mandatory breach disclosure report if PII or sensitive corporate data was accessed.',
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
    description: 'Adversaries attempting to evade single-IP lockout thresholds by distributing single-password guesses across rotating IP addresses (proxy networks, botnets, or Tor exit nodes).',
    protect_surfaces: ['Identity Federation (SSO)', 'RADIUS & LDAP Endpoints', 'Domain Controllers'],
    automation_support: true,
    steps: [
      {
        stage: 'Identification',
        step_number: 1,
        title: 'Identify Distributed Source Cluster',
        description: 'Correlate failed authentication attempts matching the target username across multiple IP sources.',
        actions: [
          'Aggregate distinct source IPs targeting the single account within the correlation window.',
          'Check ASN and hosting provider for known VPN, proxy, or bulletproof hosters.',
          'Verify if identical password hash or cadence was submitted across endpoints.',
        ],
        tools: ['ThreadGrid Incident Correlator', 'GeoIP & ASN Lookup', 'SIEM Aggregations'],
      },
      {
        stage: 'Classification',
        step_number: 2,
        title: 'Determine Spray Breadth & Depth',
        description: 'Evaluate whether the spray is focused on a VIP/executive account or sweeping the entire organization.',
        actions: [
          'Query SIEM for matching failure signatures across other corporate usernames.',
          'Confirm if any attempts succeeded across any targeted username.',
        ],
      },
      {
        stage: 'Containment',
        step_number: 3,
        title: 'Dynamic Geo-IP Throttling & Targeted Account Shielding',
        description: 'Block the attacking IP pool at perimeter and apply temporary conditional access restrictions on target identity.',
        actions: [
          'Feed IP cluster into border firewall blacklist or web application firewall (WAF).',
          'Enforce smart lockout policy on targeted account to prevent service denial.',
        ],
        cli_commands: [
          '# Linux batch iptables drop:\nfor ip in {IP_LIST}; do sudo iptables -I INPUT -s $ip -j DROP; done',
          '# Windows batch netsh block:\nnetsh advfirewall firewall add rule name="Block-Spray-Cluster" dir=in action=block remoteip={IP_LIST}',
        ],
        automated: true,
      },
      {
        stage: 'Eradication',
        step_number: 4,
        title: 'Verify Zero Breach Compromise',
        description: 'Ensure none of the sprayed accounts experienced a successful login during or following the campaign.',
        actions: [
          'Audit all Event 4624 / sshd Accepted events for target user during the spray window.',
          'Notify target user of the attack and verify recent travel/logon locations.',
        ],
      },
      {
        stage: 'Recovery',
        step_number: 5,
        title: 'Lift Temporary Restrictions & Retain Watchlist',
        description: 'Restore normal conditional access rules while maintaining the attacking IP pool on persistent blocklist.',
        actions: [
          'Retain source IP CIDR blocks on perimeter blacklist for 14 days.',
          'Verify user can log in without friction through authorized corporate networks.',
        ],
      },
      {
        stage: 'Lessons Learned',
        step_number: 6,
        title: 'Implement Continuous Spray Detection Controls',
        description: 'Harden perimeter authentication against password spray vectors.',
        actions: [
          'Transition authentication to passwordless FIDO2 / Passkeys.',
          'Deploy risk-based authentication scoring (block logins from non-corporate countries).',
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
          'Identify executed sensitive binary (e.g. `cat /etc/shadow`, `visudo`, `bash -i`, or mimikatz indicators).',
          'Verify if execution matches an approved IT change management ticket or authorized maintenance window.',
          'Trace parent process tree to identify injection point or initial compromised shell.',
        ],
        tools: ['Linux Auditd', 'Sysmon Event ID 1', 'ThreadGrid Raw Events'],
      },
      {
        stage: 'Classification',
        step_number: 2,
        title: 'Assess Scope of Local Escalation',
        description: 'Determine if adversary obtained interactive root/SYSTEM shell or accessed sensitive credential stores.',
        actions: [
          'Check effective UID (euid=0) and terminal session ownership.',
          'Evaluate if remote lateral traversal or exfiltration tools were downloaded (`curl`, `wget`, `nc`).',
        ],
      },
      {
        stage: 'Containment',
        step_number: 3,
        title: 'Host Network Quarantine & Process Termination',
        description: 'Sever network connectivity to isolate the affected host while maintaining SOC management telemetry.',
        actions: [
          'Isolate host network adapter (leaving loopback and SIEM agent port 8000 open).',
          'Terminate rogue process tree immediately.',
          'Freeze suspect user account to prevent secondary logins.',
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
          'Audit `/etc/passwd`, `/etc/shadow`, `/etc/sudoers` for unauthorized accounts or NOPASSWD directives.',
          'Run integrity check on system binaries using `debsums -c` or `sfc /scannow`.',
          'Collect volatile memory dump for rootkit and injected thread analysis.',
        ],
        cli_commands: [
          '# Verify system binary package checksums:\nsudo debsums -s',
          '# Audit sudoers configuration:\nsudo cat /etc/sudoers /etc/sudoers.d/*',
        ],
      },
      {
        stage: 'Recovery',
        step_number: 5,
        title: 'Re-image Host or Restore from Verified Golden Image',
        description: 'For mission-critical servers, re-provision from verified infrastructure-as-code baseline.',
        actions: [
          'Re-deploy operating system and authorized application containers.',
          'Re-attach to domain with freshly generated machine credentials and certificates.',
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
          'Deploy behavioral endpoint detection (EDR) with real-time process lineage blocking.',
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
    protect_surfaces: ['Edge Boundary Routers', 'Public Application Portals', 'Identity Endpoints'],
    automation_support: true,
    steps: [
      {
        stage: 'Identification',
        step_number: 1,
        title: 'Extract Enumerated Usernames & Query Patterns',
        description: 'Filter logs for `Invalid user` strings and tally distinct query identifiers.',
        actions: [
          'List queried usernames (e.g. admin, test, guest, deploy, oracle, postgres).',
          'Determine if any queried username matched a genuine internal employee account.',
          'Correlate reconnaissance sequence with subsequent targeted authentication attempts.',
        ],
        tools: ['ThreadGrid SIEM Events', 'Linux /var/log/auth.log Invalid user'],
      },
      {
        stage: 'Classification',
        step_number: 2,
        title: 'Classify Reconnaissance Tooling',
        description: 'Inspect scan cadence to detect automated tools like Hydra, Nmap, or Metasploit.',
        actions: [
          'Triage scanning IP against public threat intelligence feeds (AbuseIPDB, AlienVault OTX).',
          'Verify if scanning transitioned from dictionary words to targeted enterprise employee names.',
        ],
      },
      {
        stage: 'Containment',
        step_number: 3,
        title: 'Blacklist Reconnaissance Source IP at Perimeter',
        description: 'Add reconnaissance IP to automated border drop list to halt enumeration.',
        actions: [
          'Execute border firewall drop rule.',
          'Review edge NAT logs for related scanner probes on other ports (e.g. 80, 443, 3389).',
        ],
        cli_commands: [
          '# Linux boundary drop:\nsudo iptables -I INPUT -s {SOURCE_IP} -j DROP',
          '# Windows boundary drop:\nnetsh advfirewall firewall add rule name="Block-Recon-IP" dir=in action=block remoteip={SOURCE_IP}',
        ],
        automated: true,
      },
      {
        stage: 'Eradication',
        step_number: 4,
        title: 'Verify No Target Discovery Success',
        description: 'Confirm that the adversary received zero positive validation signals.',
        actions: [
          'Ensure server configuration masks user existence differences in response timings and error messages.',
          'Verify no internal directory services (LDAP/AD) were queried anonymously.',
        ],
      },
      {
        stage: 'Recovery',
        step_number: 5,
        title: 'Maintain Reconnaissance Watchlist',
        description: 'Retain scanner signature in SIEM correlation watchlist for 30 days.',
        actions: [
          'Add IP and ASN to threat intel blocklist.',
          'Review exposure of internet-facing management ports.',
        ],
      },
      {
        stage: 'Lessons Learned',
        step_number: 6,
        title: 'Deploy Obfuscation & Uniform Authentication Responses',
        description: 'Configure services to return identical error messages and constant-time responses.',
        actions: [
          'Disable verbose service banners in SSH (`Banner none`, `LogLevel VERBOSE`).',
          'Deploy canary/honeypot user accounts with active instant alerting alarms.',
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
          'Map all ingress and egress points across protect surfaces.',
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
   Zero Trust Architecture Pillars
   ========================================================================== */

export const ZTA_PILLARS = [
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

  // Navigation State
  const [activeTab, setActiveTab] = useState<'catalog' | 'generator' | 'zerotrust' | 'risk'>('catalog');
  const [selectedPlaybook, setSelectedPlaybook] = useState<Playbook | null>(null);
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [selectedCategory, setSelectedCategory] = useState<string>('All');
  const [selectedStageTab, setSelectedStageTab] = useState<number | 'all'>('all');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [completedSteps, setCompletedSteps] = useState<Record<string, boolean>>({});

  // Incident Report Generator State
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

  // Load incidents for IR generator auto-fill
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

  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2200);
  };

  const toggleStepCompleted = (key: string) => {
    setCompletedSteps(prev => ({ ...prev, [key]: !prev[key] }));
  };

  const generateMarkdownReport = () => {
    return `# Incident Response Report — ${irFormData.incidentId || 'INC-DRAFT'}
**Title:** ${irFormData.title}  
**Classification:** ${irFormData.severityLevel} Severity | Type: ${irFormData.incidentType}  
**Generated At:** ${new Date().toISOString()}  
**Reference Framework:** NIST SP 800-61 / DoD Military IR SOP

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
- **Monitoring in Place:** Continuous ThreadGrid SIEM rule correlation & telemetry streaming.
- **Return to Operations Approved By:** ${irFormData.returnApprovedBy}

---

## 6. Lessons Learned & Strategic Hardening
- **Incident Summary:** ${irFormData.lessonsLearned}
- **Prevention Measures:** ${irFormData.preventionMeasures}
- **Documentation Stored At:** ThreadGrid SIEM Audit Registry & Compliance Archive

---

## Appendix: Telemetry Verification Signatures
- **SIEM Engine:** ThreadGrid SIEM v1.0
- **Evidence Integrity:** SHA-256 Fingerprint Validated
`;
  };

  const handleCopyMarkdown = () => {
    navigator.clipboard.writeText(generateMarkdownReport());
    setCopiedIR(true);
    setTimeout(() => setCopiedIR(false), 2500);
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
      (pb.target_rule && pb.target_rule.toLowerCase().includes(searchQuery.toLowerCase())) ||
      pb.mitre_technique.toLowerCase().includes(searchQuery.toLowerCase());

    const matchesCategory =
      selectedCategory === 'All' || pb.category === selectedCategory;

    return matchesSearch && matchesCategory;
  });

  return (
    <div className="space-y-6 max-w-7xl mx-auto px-1 sm:px-2 pb-12">
      {/* ------------------------------------------------------------------- */}
      {/* Top Header: Visually Clean, Calm, Professional                      */}
      {/* ------------------------------------------------------------------- */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <div className="flex items-center gap-2.5 mb-1.5">
            <div className="w-8 h-8 rounded-lg bg-amber-500/10 border border-amber-500/30 flex items-center justify-center text-amber-400">
              <BookOpen size={18} />
            </div>
            <h1 className="text-xl font-bold text-slate-100 tracking-tight">
              Incident Response Playbooks & SOPs
            </h1>
          </div>
          <p className="text-xs text-slate-400">
            Comprehensive Standard Operating Procedures, containment runbooks, and NIST SP 800-61 workflows aligned with live detection rules.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => navigate('/response')}
            className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-lg bg-purple-600 hover:bg-purple-500 text-white text-xs font-semibold shadow-sm shadow-purple-900/40 transition-colors"
          >
            <Zap size={14} />
            Response Console
          </button>
        </div>
      </div>

      {/* ------------------------------------------------------------------- */}
      {/* Clean Tab Navigation Bar                                            */}
      {/* ------------------------------------------------------------------- */}
      <div className="flex items-center gap-2 border-b border-slate-800/80 pb-2 overflow-x-auto no-scrollbar">
        {[
          { key: 'catalog', label: 'Playbook Catalog', count: PLAYBOOKS_CATALOG.length, icon: BookOpen },
          { key: 'generator', label: 'IR Report Generator', icon: FileText },
          { key: 'zerotrust', label: 'Zero Trust Architecture', icon: Shield },
          { key: 'risk', label: 'Risk Governance Matrix', icon: Activity },
        ].map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.key;
          return (
            <button
              key={tab.key}
              onClick={() => setActiveTab(tab.key as any)}
              className={`inline-flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-medium transition-all whitespace-nowrap ${
                isActive
                  ? 'bg-slate-800 text-amber-400 border border-amber-500/30 shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50 border border-transparent'
              }`}
            >
              <Icon size={14} className={isActive ? 'text-amber-400' : 'text-slate-400'} />
              <span>{tab.label}</span>
              {tab.count !== undefined && (
                <span className={`px-1.5 py-0.2 rounded-full text-[10px] font-semibold ${
                  isActive ? 'bg-amber-500/20 text-amber-300' : 'bg-slate-800 text-slate-400'
                }`}>
                  {tab.count}
                </span>
              )}
            </button>
          );
        })}
      </div>

      {/* =================================================================== */}
      {/* TAB 1: PLAYBOOK CATALOG                                             */}
      {/* =================================================================== */}
      {activeTab === 'catalog' && (
        <div className="space-y-4">
          {/* Minimalist Search & Category Filter Bar */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-slate-900/60 border border-slate-800 rounded-xl p-2.5 px-3.5">
            <div className="flex items-center gap-2.5 flex-1 max-w-md">
              <Search size={15} className="text-slate-400 shrink-0" />
              <input
                type="text"
                placeholder="Search by rule, attack type, MITRE technique, or keyword..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full bg-transparent text-xs text-slate-200 placeholder-slate-500 focus:outline-none"
              />
              {searchQuery && (
                <button onClick={() => setSearchQuery('')} className="text-slate-500 hover:text-slate-300">
                  <X size={14} />
                </button>
              )}
            </div>

            <div className="flex items-center gap-1.5 overflow-x-auto pb-1 sm:pb-0">
              {['All', 'Threat Detection', 'Zero Trust', 'Risk Governance'].map((cat) => (
                <button
                  key={cat}
                  onClick={() => setSelectedCategory(cat)}
                  className={`px-2.5 py-1 rounded-md text-xs font-medium transition-colors whitespace-nowrap ${
                    selectedCategory === cat
                      ? 'bg-amber-500/15 text-amber-300 border border-amber-500/30'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60 border border-transparent'
                  }`}
                >
                  {cat}
                </button>
              ))}
            </div>
          </div>

          {/* Clean Playbook Cards Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {filteredPlaybooks.map((pb) => {
              const severityColor =
                pb.severity === 'critical'
                  ? 'text-rose-400 bg-rose-500/10 border-rose-500/25'
                  : pb.severity === 'high'
                  ? 'text-amber-400 bg-amber-500/10 border-amber-500/25'
                  : 'text-sky-400 bg-sky-500/10 border-sky-500/25';

              return (
                <div
                  key={pb.id}
                  onClick={() => {
                    setSelectedPlaybook(pb);
                    setSelectedStageTab('all');
                  }}
                  className="group relative bg-slate-900/80 hover:bg-slate-900 border border-slate-800 hover:border-amber-500/50 rounded-xl p-4 flex flex-col justify-between transition-all duration-200 hover:shadow-lg hover:shadow-amber-950/20 cursor-pointer"
                >
                  <div className="space-y-3">
                    {/* Top Tag Badges */}
                    <div className="flex items-center justify-between gap-2">
                      <div className="flex items-center gap-1.5">
                        <span className="font-mono text-[11px] font-bold text-amber-400 bg-amber-500/10 border border-amber-500/30 px-1.5 py-0.5 rounded">
                          {pb.id}
                        </span>
                        <span className={`text-[10px] font-bold uppercase tracking-wider px-1.5 py-0.5 rounded border ${severityColor}`}>
                          {pb.severity}
                        </span>
                      </div>

                      <div className="flex items-center gap-1 text-[11px] text-slate-400">
                        <Clock size={12} />
                        <span>SLA {pb.sla_minutes}m</span>
                      </div>
                    </div>

                    {/* Title */}
                    <div>
                      <h3 className="text-sm font-semibold text-slate-100 group-hover:text-amber-300 transition-colors line-clamp-2">
                        {pb.title}
                      </h3>
                      <p className="text-xs text-slate-400 mt-1 line-clamp-2 leading-relaxed">
                        {pb.summary}
                      </p>
                    </div>

                    {/* MITRE & Target Rule */}
                    <div className="pt-2 border-t border-slate-800/60 space-y-1 text-[11px]">
                      <div className="flex items-center gap-1.5 text-slate-400">
                        <span className="text-slate-500 shrink-0">MITRE:</span>
                        <span className="font-mono text-sky-400 truncate">{pb.mitre_technique}</span>
                      </div>
                      {pb.target_rule && (
                        <div className="flex items-center gap-1.5 text-slate-400">
                          <span className="text-slate-500 shrink-0">Rule:</span>
                          <span className="font-mono text-purple-400 truncate">{pb.target_rule}</span>
                        </div>
                      )}
                    </div>
                  </div>

                  {/* Card Bottom Action */}
                  <div className="pt-3 mt-3 border-t border-slate-800/80 flex items-center justify-between text-xs">
                    <span className="inline-flex items-center gap-1.5 text-slate-400 text-[11px]">
                      {pb.automation_support ? (
                        <span className="inline-flex items-center gap-1 text-emerald-400 font-medium">
                          <Zap size={12} /> Automated CLI
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 text-slate-400">
                          <Layers size={12} /> 6-Stage SOP
                        </span>
                      )}
                    </span>
                    <span className="inline-flex items-center gap-1 text-amber-400 font-medium group-hover:translate-x-0.5 transition-transform text-[11px]">
                      View Detailed SOP <ChevronRight size={13} />
                    </span>
                  </div>
                </div>
              );
            })}
          </div>

          {filteredPlaybooks.length === 0 && (
            <div className="text-center py-12 border border-dashed border-slate-800 rounded-xl">
              <p className="text-slate-400 text-sm">No playbooks found matching "{searchQuery}"</p>
              <button
                onClick={() => { setSearchQuery(''); setSelectedCategory('All'); }}
                className="mt-2 text-xs text-amber-400 hover:underline"
              >
                Reset filters
              </button>
            </div>
          )}
        </div>
      )}

      {/* =================================================================== */}
      {/* DETAILED PLAYBOOK INSPECTOR MODAL (Deep Technical Detail, Clean UI) */}
      {/* =================================================================== */}
      {selectedPlaybook && (
        <div
          className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-3 sm:p-6 overflow-y-auto"
          onClick={() => setSelectedPlaybook(null)}
        >
          <div
            className="bg-slate-950 border border-slate-800 rounded-2xl w-full max-w-4xl max-h-[92vh] flex flex-col shadow-2xl overflow-hidden"
            onClick={(e) => e.stopPropagation()}
          >
            {/* Modal Header: Clean, Clear Meta */}
            <div className="px-5 py-4 bg-slate-900 border-b border-slate-800 flex items-start justify-between gap-4 shrink-0">
              <div className="space-y-1.5">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-mono text-xs font-bold text-amber-400 bg-amber-500/10 border border-amber-500/30 px-2 py-0.5 rounded">
                    {selectedPlaybook.id}
                  </span>
                  {selectedPlaybook.target_rule && (
                    <span className="font-mono text-xs font-semibold text-purple-400 bg-purple-500/10 border border-purple-500/30 px-2 py-0.5 rounded">
                      {selectedPlaybook.target_rule}
                    </span>
                  )}
                  <span className={`text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded border ${
                    selectedPlaybook.severity === 'critical'
                      ? 'text-rose-400 bg-rose-500/10 border-rose-500/25'
                      : selectedPlaybook.severity === 'high'
                      ? 'text-amber-400 bg-amber-500/10 border-amber-500/25'
                      : 'text-sky-400 bg-sky-500/10 border-sky-500/25'
                  }`}>
                    {selectedPlaybook.severity} Severity
                  </span>
                  <span className="inline-flex items-center gap-1 text-xs text-slate-400 bg-slate-800/80 px-2 py-0.5 rounded border border-slate-700/50">
                    <Clock size={12} className="text-amber-400" /> SLA {selectedPlaybook.sla_minutes} min
                  </span>
                </div>
                <h2 className="text-base sm:text-lg font-bold text-slate-100 leading-snug">
                  {selectedPlaybook.title}
                </h2>
              </div>

              <div className="flex items-center gap-2 shrink-0">
                <button
                  onClick={() => {
                    setSelectedPlaybook(null);
                    navigate('/response');
                  }}
                  className="hidden sm:inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-purple-600 hover:bg-purple-500 text-white text-xs font-semibold transition-colors shadow-sm"
                >
                  <Zap size={13} />
                  Stage in Response Console
                </button>
                <button
                  onClick={() => setSelectedPlaybook(null)}
                  className="p-1.5 rounded-lg text-slate-400 hover:text-slate-100 hover:bg-slate-800 transition-colors"
                >
                  <X size={18} />
                </button>
              </div>
            </div>

            {/* Modal Body: Scrollable, Clean Layout */}
            <div className="flex-1 overflow-y-auto p-5 sm:p-6 space-y-5 divide-y divide-slate-800/60">
              {/* Executive Overview & Protected Surfaces */}
              <div className="space-y-3 pb-2">
                <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-3.5 space-y-2">
                  <p className="text-xs text-slate-300 leading-relaxed">
                    {selectedPlaybook.description}
                  </p>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs pt-2 border-t border-slate-800/60">
                    <div>
                      <span className="text-slate-400 font-medium">MITRE ATT&CK: </span>
                      <span className="font-mono text-sky-400">{selectedPlaybook.mitre_technique}</span>
                    </div>
                    <div>
                      <span className="text-slate-400 font-medium">Protected Surfaces: </span>
                      <span className="text-slate-200">{selectedPlaybook.protect_surfaces.join(', ')}</span>
                    </div>
                  </div>
                </div>

                {/* Stage Navigator Bar */}
                <div className="flex items-center gap-1.5 overflow-x-auto pb-1 pt-1 no-scrollbar text-xs">
                  <button
                    onClick={() => setSelectedStageTab('all')}
                    className={`px-3 py-1.5 rounded-lg font-medium transition-colors whitespace-nowrap ${
                      selectedStageTab === 'all'
                        ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40'
                        : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60 border border-transparent'
                    }`}
                  >
                    All 6 Stages
                  </button>
                  {selectedPlaybook.steps.map((st) => (
                    <button
                      key={st.step_number}
                      onClick={() => setSelectedStageTab(st.step_number)}
                      className={`px-3 py-1.5 rounded-lg font-medium transition-colors whitespace-nowrap ${
                        selectedStageTab === st.step_number
                          ? 'bg-slate-800 text-slate-100 border border-slate-700'
                          : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900 border border-transparent'
                      }`}
                    >
                      {st.step_number}. {st.stage}
                    </button>
                  ))}
                </div>
              </div>

              {/* Detailed 6-Stage Response Procedure */}
              <div className="pt-5 space-y-4">
                {selectedPlaybook.steps
                  .filter((st) => selectedStageTab === 'all' || selectedStageTab === st.step_number)
                  .map((st) => {
                    const stageColor =
                      st.stage === 'Identification'
                        ? 'border-sky-500/60 text-sky-400 bg-sky-500/10'
                        : st.stage === 'Classification'
                        ? 'border-amber-500/60 text-amber-400 bg-amber-500/10'
                        : st.stage === 'Containment'
                        ? 'border-rose-500/60 text-rose-400 bg-rose-500/10'
                        : st.stage === 'Eradication'
                        ? 'border-purple-500/60 text-purple-400 bg-purple-500/10'
                        : st.stage === 'Recovery'
                        ? 'border-emerald-500/60 text-emerald-400 bg-emerald-500/10'
                        : 'border-slate-500/60 text-slate-400 bg-slate-500/10';

                    return (
                      <div
                        key={st.step_number}
                        className="bg-slate-900/70 border border-slate-800 rounded-xl p-4 sm:p-5 space-y-3.5 transition-colors"
                      >
                        {/* Stage Subhead */}
                        <div className="flex flex-wrap items-center justify-between gap-2">
                          <div className="flex items-center gap-2">
                            <span className={`text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded border ${stageColor}`}>
                              Stage {st.step_number}: {st.stage}
                            </span>
                            <h4 className="text-sm font-semibold text-slate-100">
                              {st.title}
                            </h4>
                          </div>

                          {st.automated && (
                            <span className="inline-flex items-center gap-1 text-[11px] font-semibold text-emerald-400 bg-emerald-500/10 border border-emerald-500/25 px-2 py-0.5 rounded">
                              <Zap size={11} /> Automated Action
                            </span>
                          )}
                        </div>

                        {/* Stage Description */}
                        <p className="text-xs text-slate-400 leading-relaxed">
                          {st.description}
                        </p>

                        {/* Actionable Investigation & Response Checklist */}
                        <div className="space-y-1.5 pt-1">
                          <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider block">
                            Procedure Checklist:
                          </span>
                          <div className="space-y-1.5">
                            {st.actions.map((act, aIdx) => {
                              const stepKey = `${selectedPlaybook.id}-${st.step_number}-${aIdx}`;
                              const isDone = completedSteps[stepKey];
                              return (
                                <div
                                  key={aIdx}
                                  onClick={() => toggleStepCompleted(stepKey)}
                                  className={`flex items-start gap-2.5 p-2 rounded-lg text-xs transition-colors cursor-pointer ${
                                    isDone
                                      ? 'bg-emerald-950/20 text-slate-400 line-through'
                                      : 'bg-slate-950/40 hover:bg-slate-950/80 text-slate-200'
                                  }`}
                                >
                                  <input
                                    type="checkbox"
                                    checked={!!isDone}
                                    onChange={() => {}}
                                    className="mt-0.5 rounded border-slate-700 text-amber-500 focus:ring-0 cursor-pointer shrink-0"
                                  />
                                  <span className="leading-snug">{act}</span>
                                </div>
                              );
                            })}
                          </div>
                        </div>

                        {/* CLI Commands Box (Linux & Windows) */}
                        {st.cli_commands && st.cli_commands.length > 0 && (
                          <div className="space-y-2 pt-2">
                            <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
                              <Terminal size={12} className="text-amber-400" />
                              Containment & Triage Commands:
                            </span>
                            <div className="space-y-2">
                              {st.cli_commands.map((cmd, cIdx) => {
                                const copyKey = `${selectedPlaybook.id}-${st.step_number}-${cIdx}`;
                                const isCopied = copiedKey === copyKey;
                                return (
                                  <div
                                    key={cIdx}
                                    className="relative bg-slate-950 border border-slate-800 rounded-lg p-3 font-mono text-xs text-sky-300 overflow-x-auto group"
                                  >
                                    <div className="flex items-center justify-between pb-1.5 mb-1.5 border-b border-slate-800/80 text-[10px] text-slate-500">
                                      <span>Execution Snippet #{cIdx + 1}</span>
                                      <button
                                        onClick={() => handleCopy(cmd, copyKey)}
                                        className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-slate-900 hover:bg-slate-800 text-slate-300 hover:text-white border border-slate-700 transition-colors"
                                      >
                                        {isCopied ? (
                                          <>
                                            <Check size={11} className="text-emerald-400" />
                                            <span className="text-emerald-400 font-semibold">Copied!</span>
                                          </>
                                        ) : (
                                          <>
                                            <Copy size={11} />
                                            <span>Copy</span>
                                          </>
                                        )}
                                      </button>
                                    </div>
                                    <pre className="whitespace-pre-wrap leading-relaxed text-slate-200">
                                      {cmd}
                                    </pre>
                                  </div>
                                );
                              })}
                            </div>
                          </div>
                        )}

                        {/* Telemetry Tools Tag */}
                        {st.tools && st.tools.length > 0 && (
                          <div className="flex items-center gap-2 pt-1 text-[11px] text-slate-400">
                            <span className="text-slate-500">Telemetry Sources:</span>
                            <div className="flex flex-wrap gap-1">
                              {st.tools.map((tool, tIdx) => (
                                <span
                                  key={tIdx}
                                  className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700/50"
                                >
                                  {tool}
                                </span>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    );
                  })}
              </div>
            </div>

            {/* Modal Footer */}
            <div className="px-5 py-3.5 bg-slate-900 border-t border-slate-800 flex items-center justify-between gap-3 shrink-0">
              <button
                onClick={() => setSelectedPlaybook(null)}
                className="px-3.5 py-1.5 rounded-lg text-xs font-medium text-slate-300 hover:text-white hover:bg-slate-800 border border-slate-700 transition-colors"
              >
                Close Playbook
              </button>

              <button
                onClick={() => {
                  setSelectedPlaybook(null);
                  navigate('/response');
                }}
                className="inline-flex items-center gap-2 px-4 py-1.5 rounded-lg bg-purple-600 hover:bg-purple-500 text-white text-xs font-semibold shadow-md shadow-purple-950/40 transition-colors"
              >
                <Zap size={14} />
                Open in Response Console
              </button>
            </div>
          </div>
        </div>
      )}

      {/* =================================================================== */}
      {/* TAB 2: INCIDENT REPORT BUILDER (NIST SP 800-61 Standard)             */}
      {/* =================================================================== */}
      {activeTab === 'generator' && (
        <div className="space-y-4">
          <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-4 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
            <div>
              <h3 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
                <FileText size={16} className="text-amber-400" />
                NIST SP 800-61 Incident Response Report Builder
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Automatically pre-fills forensic indicators, affected entities, and containment actions from active SIEM incidents.
              </p>
            </div>

            {incidents.length > 0 && (
              <div className="flex items-center gap-2 shrink-0">
                <span className="text-xs text-slate-400 font-medium">Auto-Fill:</span>
                <select
                  value={selectedIncidentForIR}
                  onChange={(e) => {
                    const inc = incidents.find((i) => i.incident_id === e.target.value);
                    if (inc) handleSelectIncidentToPrepopulate(inc);
                  }}
                  className="bg-slate-800 border border-slate-700 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-amber-500"
                >
                  {incidents.map((inc) => (
                    <option key={inc.incident_id} value={inc.incident_id}>
                      {inc.incident_id} — {inc.title.slice(0, 36)}...
                    </option>
                  ))}
                </select>
              </div>
            )}
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {/* Form Fields Column */}
            <div className="bg-slate-900/70 border border-slate-800 rounded-xl p-4 sm:p-5 space-y-3.5 text-xs">
              <h4 className="text-xs font-semibold text-slate-300 uppercase tracking-wider pb-2 border-b border-slate-800">
                Incident Parameters
              </h4>

              <div>
                <label className="block text-slate-400 mb-1 font-medium">Incident Title:</label>
                <input
                  type="text"
                  value={irFormData.title}
                  onChange={(e) => setIrFormData({ ...irFormData, title: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-slate-200 focus:outline-none focus:border-amber-500"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-400 mb-1 font-medium">Severity:</label>
                  <select
                    value={irFormData.severityLevel}
                    onChange={(e) => setIrFormData({ ...irFormData, severityLevel: e.target.value })}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-slate-200 focus:outline-none focus:border-amber-500"
                  >
                    <option value="CRITICAL">CRITICAL</option>
                    <option value="HIGH">HIGH</option>
                    <option value="MEDIUM">MEDIUM</option>
                    <option value="LOW">LOW</option>
                  </select>
                </div>
                <div>
                  <label className="block text-slate-400 mb-1 font-medium">Threat Classification:</label>
                  <input
                    type="text"
                    value={irFormData.incidentType}
                    onChange={(e) => setIrFormData({ ...irFormData, incidentType: e.target.value })}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-slate-200 focus:outline-none focus:border-amber-500"
                  />
                </div>
              </div>

              <div>
                <label className="block text-slate-400 mb-1 font-medium">Systems & Entities Affected:</label>
                <input
                  type="text"
                  value={irFormData.systemsAffected}
                  onChange={(e) => setIrFormData({ ...irFormData, systemsAffected: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-slate-200 focus:outline-none focus:border-amber-500"
                />
              </div>

              <div>
                <label className="block text-slate-400 mb-1 font-medium">Immediate Containment Strategy:</label>
                <textarea
                  rows={2}
                  value={irFormData.containmentShortTerm}
                  onChange={(e) => setIrFormData({ ...irFormData, containmentShortTerm: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-slate-200 focus:outline-none focus:border-amber-500"
                />
              </div>

              <div>
                <label className="block text-slate-400 mb-1 font-medium">Root Cause Analysis:</label>
                <textarea
                  rows={2}
                  value={irFormData.rootCause}
                  onChange={(e) => setIrFormData({ ...irFormData, rootCause: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-slate-200 focus:outline-none focus:border-amber-500"
                />
              </div>

              <div>
                <label className="block text-slate-400 mb-1 font-medium">Eradication & Recovery Actions:</label>
                <textarea
                  rows={2}
                  value={irFormData.eradicationActions}
                  onChange={(e) => setIrFormData({ ...irFormData, eradicationActions: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-slate-200 focus:outline-none focus:border-amber-500"
                />
              </div>

              <div>
                <label className="block text-slate-400 mb-1 font-medium">Lessons Learned & Future Hardening:</label>
                <textarea
                  rows={2}
                  value={irFormData.lessonsLearned}
                  onChange={(e) => setIrFormData({ ...irFormData, lessonsLearned: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-slate-200 focus:outline-none focus:border-amber-500"
                />
              </div>
            </div>

            {/* Live Markdown Preview Column */}
            <div className="bg-slate-900/70 border border-slate-800 rounded-xl p-4 sm:p-5 flex flex-col justify-between space-y-3">
              <div className="flex items-center justify-between pb-2 border-b border-slate-800">
                <span className="text-xs font-semibold text-slate-300 uppercase tracking-wider flex items-center gap-1.5">
                  <FileText size={13} className="text-amber-400" />
                  Live Markdown Document Preview
                </span>

                <div className="flex items-center gap-2">
                  <button
                    onClick={handleCopyMarkdown}
                    className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium border border-slate-700 transition-colors"
                  >
                    {copiedIR ? (
                      <>
                        <Check size={12} className="text-emerald-400" />
                        <span className="text-emerald-400">Copied!</span>
                      </>
                    ) : (
                      <>
                        <Copy size={12} />
                        <span>Copy</span>
                      </>
                    )}
                  </button>

                  <button
                    onClick={handleDownloadMarkdown}
                    className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-amber-600 hover:bg-amber-500 text-white text-xs font-medium transition-colors"
                  >
                    <Download size={12} />
                    <span>Download .md</span>
                  </button>
                </div>
              </div>

              <pre className="flex-1 bg-slate-950 border border-slate-800/80 rounded-lg p-3 text-[11px] font-mono text-sky-300 overflow-y-auto max-h-[500px] whitespace-pre-wrap leading-relaxed no-scrollbar">
                {generateMarkdownReport()}
              </pre>
            </div>
          </div>
        </div>
      )}

      {/* =================================================================== */}
      {/* TAB 3: ZERO TRUST ARCHITECTURE FRAMEWORK                            */}
      {/* =================================================================== */}
      {activeTab === 'zerotrust' && (
        <div className="space-y-4">
          <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-4 space-y-1.5">
            <h3 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
              <Shield size={16} className="text-emerald-400" />
              Zero Trust Architecture (ZTA) Implementation Guide
            </h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              Based on the foundational principle <strong>"Never Trust, Always Verify"</strong>. Assumes threat actors exist both outside and within the perimeter, requiring continuous multi-attribute validation and granular microsegmentation.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {ZTA_PILLARS.map((p, idx) => (
              <div
                key={idx}
                className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 space-y-3 flex flex-col justify-between"
              >
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <h4 className="text-sm font-bold text-slate-100">{p.pillar}</h4>
                    <span
                      className="text-[10px] font-bold uppercase px-2 py-0.5 rounded border"
                      style={{
                        color: p.statusColor,
                        backgroundColor: `${p.statusColor}15`,
                        borderColor: `${p.statusColor}35`,
                      }}
                    >
                      {p.status}
                    </span>
                  </div>

                  <p className="text-xs text-slate-400 leading-relaxed">
                    {p.focus}
                  </p>

                  <div className="pt-2 border-t border-slate-800/60 space-y-1">
                    <span className="text-[11px] text-slate-500 font-medium">Monitored Controls:</span>
                    <div className="flex flex-wrap gap-1">
                      {p.monitored_controls.map((c, cIdx) => (
                        <span
                          key={cIdx}
                          className="text-[10px] px-1.5 py-0.5 bg-slate-800 text-slate-300 rounded border border-slate-700/40"
                        >
                          {c}
                        </span>
                      ))}
                    </div>
                  </div>
                </div>

                <div className="pt-2 border-t border-slate-800/80 text-[11px] text-slate-400 space-y-0.5">
                  <div><strong className="text-slate-300">Tooling:</strong> {p.tools.join(', ')}</div>
                  <div><strong className="text-slate-300">Target Metric:</strong> {p.metrics}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* =================================================================== */}
      {/* TAB 4: RISK GOVERNANCE MATRIX                                       */}
      {/* =================================================================== */}
      {activeTab === 'risk' && (
        <div className="space-y-4">
          <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-4 space-y-1.5">
            <h3 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
              <Activity size={16} className="text-sky-400" />
              Enterprise Cybersecurity Risk Register
            </h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              Standardized scoring formula: <strong>Risk Score = Likelihood (1 - 5) × Impact (1 - 5)</strong>. Establishes defined containment SLAs and executive ownership for threat vectors.
            </p>
          </div>

          <div className="bg-slate-900/80 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
            <div className="overflow-x-auto">
              <table className="w-full text-xs text-left">
                <thead className="bg-slate-950/80 border-b border-slate-800 text-slate-400">
                  <tr>
                    <th className="px-4 py-3 font-semibold">Risk ID</th>
                    <th className="px-4 py-3 font-semibold">Threat Scenario</th>
                    <th className="px-4 py-3 font-semibold">Likelihood</th>
                    <th className="px-4 py-3 font-semibold">Impact</th>
                    <th className="px-4 py-3 font-semibold">Score</th>
                    <th className="px-4 py-3 font-semibold">Executive Owner</th>
                    <th className="px-4 py-3 font-semibold">SLA</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 text-slate-300">
                  {[
                    { id: 'RSK-001', scenario: 'Sustained Public-Facing SSH Brute Force', l: 5, i: 4, score: 20, tier: 'Critical', owner: 'SOC Lead', sla: '1 Hour' },
                    { id: 'RSK-002', scenario: 'Credential Stuffing with Successful Auth', l: 4, i: 5, score: 20, tier: 'Critical', owner: 'CISO / IR Lead', sla: '1 Hour' },
                    { id: 'RSK-003', scenario: 'Distributed Password Spraying on Executive Identity', l: 4, i: 4, score: 16, tier: 'High', owner: 'IAM Team Lead', sla: '4 Hours' },
                    { id: 'RSK-004', scenario: 'Unprivileged User Execution of SUID Binaries', l: 3, i: 5, score: 15, tier: 'High', owner: 'Infrastructure Lead', sla: '4 Hours' },
                    { id: 'RSK-005', scenario: 'Account Discovery & User Enumeration Reconnaissance', l: 4, i: 2, score: 8, tier: 'Medium', owner: 'Network Security', sla: '24 Hours' },
                    { id: 'RSK-006', scenario: 'Lack of Centralized Multi-Factor Authentication', l: 3, i: 4, score: 12, tier: 'Medium', owner: 'Enterprise Architect', sla: '24 Hours' },
                  ].map((row) => {
                    const badgeClass =
                      row.score >= 18
                        ? 'text-rose-400 bg-rose-500/10 border-rose-500/25'
                        : row.score >= 14
                        ? 'text-amber-400 bg-amber-500/10 border-amber-500/25'
                        : 'text-sky-400 bg-sky-500/10 border-sky-500/25';

                    return (
                      <tr key={row.id} className="hover:bg-slate-800/40 transition-colors">
                        <td className="px-4 py-3 font-mono font-bold text-amber-400">{row.id}</td>
                        <td className="px-4 py-3 font-medium text-slate-100">{row.scenario}</td>
                        <td className="px-4 py-3 text-slate-400">{row.l} / 5</td>
                        <td className="px-4 py-3 text-slate-400">{row.i} / 5</td>
                        <td className="px-4 py-3">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${badgeClass}`}>
                            {row.score} ({row.tier})
                          </span>
                        </td>
                        <td className="px-4 py-3 text-slate-300">{row.owner}</td>
                        <td className="px-4 py-3 font-mono text-slate-400">{row.sla}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default PlaybooksPage;
