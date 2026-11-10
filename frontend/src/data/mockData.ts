import type {
  SecurityEvent,
  Alert,
  Incident,
  Entity,
  Asset,
  DetectionRule,
  SystemHealth,
  AnomalyScore,
  KPIMetric,
  TimeSeriesDataPoint
} from '../types';

/**
 * Helper to compute recent relative ISO timestamps
 */
const getRelativeISO = (minutesAgo: number): string => {
  return new Date(Date.now() - minutesAgo * 60 * 1000).toISOString();
};

/* ==========================================================================
   1. KPI Metrics
   ========================================================================== */
export const mockKPIs: KPIMetric[] = [
  {
    label: 'Total Events',
    value: '47,832',
    change: 12.4,
    changeLabel: 'vs yesterday',
    trend: 'up',
    icon: 'Activity'
  },
  {
    label: 'Alerts (24h)',
    value: 156,
    change: -4.2,
    changeLabel: 'vs yesterday',
    trend: 'down',
    icon: 'AlertTriangle'
  },
  {
    label: 'Critical Alerts',
    value: 12,
    change: 2,
    changeLabel: 'last 4 hours',
    trend: 'up',
    icon: 'Flame'
  },
  {
    label: 'Active Incidents',
    value: 8,
    change: 0,
    changeLabel: 'unchanged',
    trend: 'stable',
    icon: 'ShieldAlert'
  },
  {
    label: 'Assets Monitored',
    value: 342,
    change: 3,
    changeLabel: 'newly enrolled',
    trend: 'up',
    icon: 'Server'
  }
];

/* ==========================================================================
   2. Events Time Series (24 Hourly Data Points)
   ========================================================================== */
export const mockEventsTimeSeries: TimeSeriesDataPoint[] = [
  { timestamp: '00:00', value: 1240, label: '00:00 UTC' },
  { timestamp: '01:00', value: 1110, label: '01:00 UTC' },
  { timestamp: '02:00', value: 980, label: '02:00 UTC' },
  { timestamp: '03:00', value: 890, label: '03:00 UTC' },
  { timestamp: '04:00', value: 1020, label: '04:00 UTC' },
  { timestamp: '05:00', value: 1350, label: '05:00 UTC' },
  { timestamp: '06:00', value: 1720, label: '06:00 UTC' },
  { timestamp: '07:00', value: 2150, label: '07:00 UTC' },
  { timestamp: '08:00', value: 2840, label: '08:00 UTC' },
  { timestamp: '09:00', value: 3210, label: '09:00 UTC' },
  { timestamp: '10:00', value: 3450, label: '10:00 UTC' },
  { timestamp: '11:00', value: 3120, label: '11:00 UTC' },
  { timestamp: '12:00', value: 2980, label: '12:00 UTC' },
  { timestamp: '13:00', value: 3340, label: '13:00 UTC' },
  { timestamp: '14:00', value: 3620, label: '14:00 UTC' },
  { timestamp: '15:00', value: 3410, label: '15:00 UTC' },
  { timestamp: '16:00', value: 2950, label: '16:00 UTC' },
  { timestamp: '17:00', value: 2710, label: '17:00 UTC' },
  { timestamp: '18:00', value: 2340, label: '18:00 UTC' },
  { timestamp: '19:00', value: 2050, label: '19:00 UTC' },
  { timestamp: '20:00', value: 1890, label: '20:00 UTC' },
  { timestamp: '21:00', value: 1740, label: '21:00 UTC' },
  { timestamp: '22:00', value: 1530, label: '22:00 UTC' },
  { timestamp: '23:00', value: 1380, label: '23:00 UTC' }
];

/* ==========================================================================
   3. Alerts Distribution by Severity
   ========================================================================== */
export const mockAlertsBySeverity = [
  { severity: 'critical', label: 'Critical', count: 12, percentage: 7.7, color: '#ef4444' },
  { severity: 'high', label: 'High', count: 38, percentage: 24.4, color: '#f97316' },
  { severity: 'medium', label: 'Medium', count: 64, percentage: 41.0, color: '#eab308' },
  { severity: 'low', label: 'Low', count: 42, percentage: 26.9, color: '#06b6d4' }
];

/* ==========================================================================
   4. Recent Alerts (8 Realistic SOC Alerts)
   ========================================================================== */
export const mockRecentAlerts: Alert[] = [
  {
    alert_id: 'ALT-2026-9041',
    rule_id: 'RULE-001',
    rule_name: 'Brute Force Authentication Attempt',
    severity: 'high',
    timestamp: getRelativeISO(8),
    source_ip: '185.220.101.5',
    destination_ip: '10.0.1.15',
    username: 'svc-backup',
    source_host: 'dc01.corp.internal',
    description: '14 consecutive failed Kerberos pre-authentications within 45s originating from external Tor exit node.',
    evidence_event_ids: ['EVT-9001', 'EVT-9002', 'EVT-9003'],
    status: 'open',
    assignee: 'Alice Chen',
    created_at: getRelativeISO(8),
    updated_at: getRelativeISO(6)
  },
  {
    alert_id: 'ALT-2026-9040',
    rule_id: 'RULE-005',
    rule_name: 'Credential Dumping via LSASS Injection',
    severity: 'critical',
    timestamp: getRelativeISO(15),
    source_ip: '10.0.4.88',
    destination_ip: null,
    username: 'dsmith_admin',
    source_host: 'ws-finance-08.corp',
    description: 'Non-system binary mimikatz_x64.exe requested PROCESS_VM_READ access to lsass.exe process handle.',
    evidence_event_ids: ['EVT-9010', 'EVT-9011'],
    status: 'open',
    assignee: 'Bob Vance',
    created_at: getRelativeISO(15),
    updated_at: getRelativeISO(12)
  },
  {
    alert_id: 'ALT-2026-9039',
    rule_id: 'RULE-004',
    rule_name: 'Obfuscated PowerShell Script Execution',
    severity: 'high',
    timestamp: getRelativeISO(28),
    source_ip: '10.0.4.88',
    destination_ip: '194.26.29.112',
    username: 'dsmith_admin',
    source_host: 'ws-finance-08.corp',
    description: 'PowerShell invoked with base64 encoded payload and -ExecutionPolicy Bypass targeting remote C2 server.',
    evidence_event_ids: ['EVT-9015', 'EVT-9016'],
    status: 'acknowledged',
    assignee: 'Alice Chen',
    created_at: getRelativeISO(28),
    updated_at: getRelativeISO(20)
  },
  {
    alert_id: 'ALT-2026-9038',
    rule_id: 'ML-ANOMALY-001',
    rule_name: 'Unsupervised High-Velocity Anomaly Detection',
    severity: 'high',
    timestamp: getRelativeISO(42),
    source_ip: '194.26.29.112',
    destination_ip: '10.0.2.4',
    username: 'svc-deploy',
    source_host: 'web-prod-edge-01',
    description: 'Isolation Forest detected anomalous outbound connection volume and low jitter beaconing (anomaly score: 0.94).',
    evidence_event_ids: ['EVT-9022', 'EVT-9023', 'EVT-9024'],
    status: 'open',
    assignee: null,
    created_at: getRelativeISO(42),
    updated_at: getRelativeISO(42)
  },
  {
    alert_id: 'ALT-2026-9037',
    rule_id: 'RULE-002',
    rule_name: 'Lateral Movement via SMB/RPC',
    severity: 'critical',
    timestamp: getRelativeISO(65),
    source_ip: '10.0.4.88',
    destination_ip: '10.0.1.15',
    username: 'svc-backup',
    source_host: 'dc01.corp.internal',
    description: 'Administrative share IPC$ and ADMIN$ connected remotely followed by remote service registration.',
    evidence_event_ids: ['EVT-9031', 'EVT-9032'],
    status: 'acknowledged',
    assignee: 'Carol Danvers',
    created_at: getRelativeISO(65),
    updated_at: getRelativeISO(50)
  },
  {
    alert_id: 'ALT-2026-9036',
    rule_id: 'RULE-003',
    rule_name: 'Network Port & Vulnerability Sweep',
    severity: 'medium',
    timestamp: getRelativeISO(90),
    source_ip: '45.154.255.89',
    destination_ip: '10.0.2.1',
    username: null,
    source_host: 'vpn-gw-external.corp',
    description: 'Rapid TCP SYN sweep across 450 ports within 12 seconds targeting external perimeter gateway.',
    evidence_event_ids: ['EVT-9040', 'EVT-9041', 'EVT-9042'],
    status: 'open',
    assignee: null,
    created_at: getRelativeISO(90),
    updated_at: getRelativeISO(90)
  },
  {
    alert_id: 'ALT-2026-9035',
    rule_id: 'RULE-001',
    rule_name: 'Multiple Failed Logins Followed by Sudo Privilege Grant',
    severity: 'medium',
    timestamp: getRelativeISO(130),
    source_ip: '91.240.118.172',
    destination_ip: '10.0.3.10',
    username: 'deployer',
    source_host: 'db-cluster-node1.internal',
    description: '8 failed SSH login attempts followed by successful key auth and subsequent elevation to sudo root.',
    evidence_event_ids: ['EVT-9051', 'EVT-9052'],
    status: 'resolved',
    assignee: 'Alice Chen',
    created_at: getRelativeISO(130),
    updated_at: getRelativeISO(110)
  },
  {
    alert_id: 'ALT-2026-9034',
    rule_id: 'RULE-003',
    rule_name: 'Outbound Data Staging to Known Bulletproof Host',
    severity: 'low',
    timestamp: getRelativeISO(180),
    source_ip: '10.0.4.12',
    destination_ip: '103.145.13.20',
    username: 'jdoe',
    source_host: 'ws-eng-macbook-14',
    description: 'High-entropy compressed stream upload via HTTP POST to suspicious foreign hosting provider.',
    evidence_event_ids: ['EVT-9060'],
    status: 'false_positive',
    assignee: 'Bob Vance',
    created_at: getRelativeISO(180),
    updated_at: getRelativeISO(160)
  }
];

/* ==========================================================================
   5. Active Incidents (6 Realistic Incidents with Correlated Entities)
   ========================================================================== */
export const mockActiveIncidents: Incident[] = [
  {
    incident_id: 'INC-2026-0891',
    title: 'Active Directory Compromise & LSASS Credential Harvesting',
    severity: 'critical',
    status: 'INVESTIGATING',
    risk_score: 94,
    first_seen: getRelativeISO(75),
    last_seen: getRelativeISO(8),
    entities: {
      source_ips: ['185.220.101.5', '10.0.4.88'],
      usernames: ['svc-backup', 'dsmith_admin'],
      hosts: ['dc01.corp.internal', 'ws-finance-08.corp']
    },
    related_alert_ids: ['ALT-2026-9041', 'ALT-2026-9040', 'ALT-2026-9037'],
    related_event_ids: ['EVT-9001', 'EVT-9002', 'EVT-9010', 'EVT-9031'],
    distinct_rules: ['RULE-001', 'RULE-002', 'RULE-005'],
    timeline: [
      {
        entry_id: 'TL-001',
        timestamp: getRelativeISO(75),
        entry_type: 'event',
        description: 'Failed password spray detected on domain controller dc01.corp.internal',
        severity: 'medium',
        entities: { host: 'dc01.corp.internal', ip: '185.220.101.5' }
      },
      {
        entry_id: 'TL-002',
        timestamp: getRelativeISO(65),
        entry_type: 'alert',
        description: 'Alert ALT-2026-9037 triggered: Lateral Movement via SMB/RPC',
        severity: 'critical',
        entities: { host: 'dc01.corp.internal', user: 'svc-backup' }
      },
      {
        entry_id: 'TL-003',
        timestamp: getRelativeISO(50),
        entry_type: 'status_change',
        description: 'Status changed from NEW to INVESTIGATING by Alice Chen',
        severity: 'info',
        entities: { user: 'Alice Chen' }
      },
      {
        entry_id: 'TL-004',
        timestamp: getRelativeISO(15),
        entry_type: 'alert',
        description: 'Alert ALT-2026-9040 triggered: Credential Dumping via LSASS Injection',
        severity: 'critical',
        entities: { host: 'ws-finance-08.corp', user: 'dsmith_admin' }
      },
      {
        entry_id: 'TL-005',
        timestamp: getRelativeISO(10),
        entry_type: 'note',
        description: 'Host ws-finance-08.corp isolated via automated network quarantine rule.',
        severity: 'low',
        entities: { host: 'ws-finance-08.corp' }
      }
    ],
    analyst_notes: [
      {
        note_id: 'NOTE-101',
        author: 'Alice Chen',
        created_at: getRelativeISO(45),
        content: 'Correlated Tor IP with malicious credential spraying. Compromised account svc-backup used for lateral SMB hop.'
      },
      {
        note_id: 'NOTE-102',
        author: 'Bob Vance',
        created_at: getRelativeISO(12),
        content: 'Mimikatz binary detected in %TEMP% directory. Initiated host memory dump and revoked Kerberos TGT tickets.'
      }
    ],
    created_at: getRelativeISO(75),
    updated_at: getRelativeISO(8)
  },
  {
    incident_id: 'INC-2026-0889',
    title: 'Cobalt Strike C2 Beaconing from Finance Workstation',
    severity: 'critical',
    status: 'INVESTIGATING',
    risk_score: 89,
    first_seen: getRelativeISO(120),
    last_seen: getRelativeISO(28),
    entities: {
      source_ips: ['194.26.29.112', '10.0.4.88'],
      usernames: ['dsmith_admin'],
      hosts: ['ws-finance-08.corp']
    },
    related_alert_ids: ['ALT-2026-9039', 'ALT-2026-9038'],
    related_event_ids: ['EVT-9015', 'EVT-9022'],
    distinct_rules: ['RULE-004', 'ML-ANOMALY-001'],
    timeline: [
      {
        entry_id: 'TL-101',
        timestamp: getRelativeISO(120),
        entry_type: 'event',
        description: 'Outbound HTTPS connection to unclassified IP 194.26.29.112:8443 established',
        severity: 'medium',
        entities: { ip: '194.26.29.112' }
      },
      {
        entry_id: 'TL-102',
        timestamp: getRelativeISO(28),
        entry_type: 'alert',
        description: 'Alert ALT-2026-9039: Obfuscated PowerShell Script Execution',
        severity: 'high',
        entities: { host: 'ws-finance-08.corp' }
      }
    ],
    analyst_notes: [
      {
        note_id: 'NOTE-103',
        author: 'Carol Danvers',
        created_at: getRelativeISO(22),
        content: 'C2 communication pattern exhibits 60-second jitter interval characteristic of Cobalt Strike malleable C2 profiles.'
      }
    ],
    created_at: getRelativeISO(120),
    updated_at: getRelativeISO(28)
  },
  {
    incident_id: 'INC-2026-0885',
    title: 'Distributed Perimeter Reconnaissance & SYN Flood Sweep',
    severity: 'high',
    status: 'NEW',
    risk_score: 76,
    first_seen: getRelativeISO(150),
    last_seen: getRelativeISO(90),
    entities: {
      source_ips: ['45.154.255.89', '91.240.118.172'],
      usernames: [],
      hosts: ['vpn-gw-external.corp']
    },
    related_alert_ids: ['ALT-2026-9036'],
    related_event_ids: ['EVT-9040', 'EVT-9041'],
    distinct_rules: ['RULE-003'],
    timeline: [
      {
        entry_id: 'TL-201',
        timestamp: getRelativeISO(150),
        entry_type: 'event',
        description: 'Initial TCP handshake probe detected on port 443',
        severity: 'low',
        entities: { ip: '45.154.255.89' }
      },
      {
        entry_id: 'TL-202',
        timestamp: getRelativeISO(90),
        entry_type: 'alert',
        description: 'Port sweep triggered across 450 ports on vpn-gw-external.corp',
        severity: 'medium',
        entities: { host: 'vpn-gw-external.corp' }
      }
    ],
    analyst_notes: [],
    created_at: getRelativeISO(150),
    updated_at: getRelativeISO(90)
  },
  {
    incident_id: 'INC-2026-0882',
    title: 'Privileged Account Brute Force & Lateral SSH Elevation',
    severity: 'high',
    status: 'INVESTIGATING',
    risk_score: 72,
    first_seen: getRelativeISO(180),
    last_seen: getRelativeISO(110),
    entities: {
      source_ips: ['91.240.118.172', '10.0.3.10'],
      usernames: ['deployer', 'root'],
      hosts: ['db-cluster-node1.internal']
    },
    related_alert_ids: ['ALT-2026-9035'],
    related_event_ids: ['EVT-9051', 'EVT-9052'],
    distinct_rules: ['RULE-001'],
    timeline: [
      {
        entry_id: 'TL-301',
        timestamp: getRelativeISO(180),
        entry_type: 'event',
        description: 'Failed password authentication for user deployer',
        severity: 'medium',
        entities: { user: 'deployer' }
      },
      {
        entry_id: 'TL-302',
        timestamp: getRelativeISO(130),
        entry_type: 'alert',
        description: 'Multiple failed logins followed by sudo privilege grant',
        severity: 'high',
        entities: { host: 'db-cluster-node1.internal' }
      }
    ],
    analyst_notes: [
      {
        note_id: 'NOTE-104',
        author: 'Alice Chen',
        created_at: getRelativeISO(115),
        content: 'Attacker gained access via compromised deployer SSH key, attempted sudo elevation to root. Host session terminated.'
      }
    ],
    created_at: getRelativeISO(180),
    updated_at: getRelativeISO(110)
  },
  {
    incident_id: 'INC-2026-0879',
    title: 'Suspicious Data Staging & Exfiltration Attempt to External Cloud',
    severity: 'medium',
    status: 'NEW',
    risk_score: 58,
    first_seen: getRelativeISO(240),
    last_seen: getRelativeISO(160),
    entities: {
      source_ips: ['10.0.4.12', '103.145.13.20'],
      usernames: ['jdoe'],
      hosts: ['ws-eng-macbook-14']
    },
    related_alert_ids: ['ALT-2026-9034'],
    related_event_ids: ['EVT-9060'],
    distinct_rules: ['RULE-003'],
    timeline: [
      {
        entry_id: 'TL-401',
        timestamp: getRelativeISO(240),
        entry_type: 'event',
        description: 'Archive created in /tmp/staging.tar.gz containing source repository clones',
        severity: 'low',
        entities: { user: 'jdoe' }
      },
      {
        entry_id: 'TL-402',
        timestamp: getRelativeISO(180),
        entry_type: 'alert',
        description: 'Alert ALT-2026-9034 triggered: Outbound Data Staging',
        severity: 'low',
        entities: { ip: '103.145.13.20' }
      }
    ],
    analyst_notes: [],
    created_at: getRelativeISO(240),
    updated_at: getRelativeISO(160)
  },
  {
    incident_id: 'INC-2026-0870',
    title: 'Scheduled Vulnerability Assessment Scanner Sweep',
    severity: 'low',
    status: 'RESOLVED',
    risk_score: 24,
    first_seen: getRelativeISO(360),
    last_seen: getRelativeISO(300),
    entities: {
      source_ips: ['198.51.100.45'],
      usernames: ['sec-scanner'],
      hosts: ['web-prod-edge-01']
    },
    related_alert_ids: [],
    related_event_ids: [],
    distinct_rules: ['RULE-003'],
    timeline: [
      {
        entry_id: 'TL-501',
        timestamp: getRelativeISO(360),
        entry_type: 'event',
        description: 'Nessus authorized security scanner probe started',
        severity: 'low',
        entities: { user: 'sec-scanner' }
      },
      {
        entry_id: 'TL-502',
        timestamp: getRelativeISO(300),
        entry_type: 'status_change',
        description: 'Incident verified against scheduled maintenance change CR-8812 and resolved.',
        severity: 'info',
        entities: {}
      }
    ],
    analyst_notes: [
      {
        note_id: 'NOTE-105',
        author: 'Bob Vance',
        created_at: getRelativeISO(295),
        content: 'Verified legitimate scanning window authorized by InfoSec RFC-4192. Closed as authorized activity.'
      }
    ],
    created_at: getRelativeISO(360),
    updated_at: getRelativeISO(300)
  }
];

/* ==========================================================================
   6. Top Attack Types
   ========================================================================== */
export const mockTopAttackTypes = [
  { type: 'Brute Force / Password Spray', count: 58, percentage: 37.2 },
  { type: 'Lateral Movement (SMB/RPC)', count: 32, percentage: 20.5 },
  { type: 'C2 Beaconing / High Entropy', count: 24, percentage: 15.4 },
  { type: 'Port Sweep / Perimeter Recon', count: 22, percentage: 14.1 },
  { type: 'LSASS Injection & Dump', count: 12, percentage: 7.7 },
  { type: 'Data Exfiltration Staging', count: 8, percentage: 5.1 }
];

/* ==========================================================================
   7. Top Attacking Source IPs
   ========================================================================== */
export const mockTopSourceIPs = [
  { ip: '185.220.101.5', count: 412, country: 'Netherlands', risk_score: 98 },
  { ip: '194.26.29.112', count: 328, country: 'Russia', risk_score: 94 },
  { ip: '45.154.255.89', count: 245, country: 'Germany', risk_score: 88 },
  { ip: '91.240.118.172', count: 189, country: 'Lithuania', risk_score: 86 },
  { ip: '103.145.13.20', count: 134, country: 'Vietnam', risk_score: 74 }
];

/* ==========================================================================
   8. Anomaly Scores (Isolation Forest & Multi-Variate Detection)
   ========================================================================== */
export const mockAnomalyScores: AnomalyScore[] = [
  {
    entity: 'svc-backup',
    entity_type: 'user',
    score: 0.88,
    threshold: 0.65,
    is_anomalous: true,
    top_features: [
      { name: 'off_hours_logins', contribution: 0.42, value: 14 },
      { name: 'distinct_destinations', contribution: 0.31, value: 8 },
      { name: 'kerberos_ticket_volume', contribution: 0.15, value: 34 }
    ],
    timestamp: getRelativeISO(10)
  },
  {
    entity: 'ws-finance-08.corp',
    entity_type: 'host',
    score: 0.79,
    threshold: 0.65,
    is_anomalous: true,
    top_features: [
      { name: 'lsass_read_attempts', contribution: 0.48, value: 3 },
      { name: 'entropy_outbound_bytes', contribution: 0.22, value: 14.2 },
      { name: 'encoded_powershell_calls', contribution: 0.09, value: 5 }
    ],
    timestamp: getRelativeISO(18)
  },
  {
    entity: '194.26.29.112',
    entity_type: 'ip',
    score: 0.94,
    threshold: 0.65,
    is_anomalous: true,
    top_features: [
      { name: 'beacon_jitter_regularity', contribution: 0.55, value: 0.98 },
      { name: 'payload_randomness', contribution: 0.26, value: 0.89 },
      { name: 'non_standard_port_usage', contribution: 0.13, value: 8443 }
    ],
    timestamp: getRelativeISO(25)
  },
  {
    entity: 'admin_dsmith',
    entity_type: 'user',
    score: 0.42,
    threshold: 0.65,
    is_anomalous: false,
    top_features: [
      { name: 'privileged_elevation_count', contribution: 0.21, value: 2 },
      { name: 'admin_share_access', contribution: 0.14, value: 4 },
      { name: 'session_duration_hours', contribution: 0.07, value: 6.5 }
    ],
    timestamp: getRelativeISO(40)
  },
  {
    entity: 'dc01.corp.internal',
    entity_type: 'host',
    score: 0.31,
    threshold: 0.65,
    is_anomalous: false,
    top_features: [
      { name: 'auth_validation_rate', contribution: 0.15, value: 120 },
      { name: 'rpc_connection_density', contribution: 0.11, value: 45 },
      { name: 'dns_query_baseline', contribution: 0.05, value: 310 }
    ],
    timestamp: getRelativeISO(55)
  }
];

/* ==========================================================================
   9. System Health Components
   ========================================================================== */
export const mockSystemHealth: SystemHealth[] = [
  {
    component: 'Event Ingestion Pipeline',
    status: 'healthy',
    message: 'Kafka & Redis streaming real-time events at 2,450 eps nominal rate',
    last_check: '12s ago',
    metrics: {
      eps: 2450,
      buffer_utilization_pct: 18,
      latency_ms: 12
    }
  },
  {
    component: 'Elastic Storage Cluster',
    status: 'healthy',
    message: 'All 6 data shards report GREEN status with 64% total capacity utilization',
    last_check: '35s ago',
    metrics: {
      total_indices: 48,
      disk_used_pct: 64,
      query_latency_ms: 28
    }
  },
  {
    component: 'ML Isolation Forest & Heuristics',
    status: 'healthy',
    message: 'Model inference latency <15ms, zero distribution drift detected',
    last_check: '1m ago',
    metrics: {
      model_version: 2.1,
      inference_latency_ms: 14,
      drift_score: 0.03
    }
  },
  {
    component: 'PostgreSQL Relational DB',
    status: 'healthy',
    message: 'Connection pool 24/100 active, multi-AZ synchronous replication nominal',
    last_check: '40s ago',
    metrics: {
      pool_usage_pct: 24,
      cache_hit_ratio: 99.2,
      replication_lag_ms: 0
    }
  }
];

/* ==========================================================================
   10. Monitored Assets (8 Diverse Infrastructure Assets)
   ========================================================================== */
export const mockAssets: Asset[] = [
  {
    asset_id: 'AST-001',
    hostname: 'dc01.corp.internal',
    ip_address: '10.0.1.15',
    os: 'Windows Server 2022 Datacenter',
    asset_type: 'server',
    status: 'online',
    last_seen: getRelativeISO(2),
    risk_score: 45,
    agent_version: '3.4.1',
    tags: ['domain-controller', 'tier-0', 'critical-infra']
  },
  {
    asset_id: 'AST-002',
    hostname: 'dc02.corp.internal',
    ip_address: '10.0.1.16',
    os: 'Windows Server 2022 Datacenter',
    asset_type: 'server',
    status: 'online',
    last_seen: getRelativeISO(5),
    risk_score: 12,
    agent_version: '3.4.1',
    tags: ['backup-dc', 'tier-0', 'dns']
  },
  {
    asset_id: 'AST-003',
    hostname: 'db-cluster-node1.internal',
    ip_address: '10.0.3.10',
    os: 'Ubuntu 22.04 LTS',
    asset_type: 'server',
    status: 'online',
    last_seen: getRelativeISO(1),
    risk_score: 28,
    agent_version: '3.4.0',
    tags: ['database', 'postgres', 'tier-1']
  },
  {
    asset_id: 'AST-004',
    hostname: 'web-prod-edge-01',
    ip_address: '10.0.2.4',
    os: 'Debian 12 / Nginx',
    asset_type: 'cloud_instance',
    status: 'online',
    last_seen: getRelativeISO(3),
    risk_score: 85,
    agent_version: '3.4.1',
    tags: ['dmz', 'public-facing', 'web-gateway']
  },
  {
    asset_id: 'AST-005',
    hostname: 'vpn-gw-external.corp',
    ip_address: '10.0.2.1',
    os: 'FortiOS 7.2.5',
    asset_type: 'network_device',
    status: 'online',
    last_seen: getRelativeISO(1),
    risk_score: 62,
    agent_version: null,
    tags: ['edge', 'firewall', 'perimeter']
  },
  {
    asset_id: 'AST-006',
    hostname: 'ws-finance-08.corp',
    ip_address: '10.0.4.88',
    os: 'Windows 11 Enterprise',
    asset_type: 'workstation',
    status: 'online',
    last_seen: getRelativeISO(8),
    risk_score: 91,
    agent_version: '3.4.1',
    tags: ['finance', 'high-risk', 'quarantined']
  },
  {
    asset_id: 'AST-007',
    hostname: 'ws-eng-macbook-14',
    ip_address: '10.0.4.12',
    os: 'macOS Sonoma 14.4',
    asset_type: 'workstation',
    status: 'online',
    last_seen: getRelativeISO(15),
    risk_score: 18,
    agent_version: '3.3.9',
    tags: ['engineering', 'developer']
  },
  {
    asset_id: 'AST-008',
    hostname: 'k8s-worker-pool-c3',
    ip_address: '10.0.5.21',
    os: 'Amazon Linux 2023',
    asset_type: 'cloud_instance',
    status: 'online',
    last_seen: getRelativeISO(4),
    risk_score: 35,
    agent_version: '3.4.1',
    tags: ['kubernetes', 'production', 'cloud-worker']
  }
];

/* ==========================================================================
   11. Detection Rules (Matching RULE-001 to RULE-005 + ML-ANOMALY-001)
   ========================================================================== */
export const mockDetectionRules: DetectionRule[] = [
  {
    rule_id: 'RULE-001',
    name: 'Brute Force Authentication Attempt',
    description: 'Detects excessive failed authentication events (>10 within 60s) followed by successful validation.',
    severity: 'high',
    enabled: true,
    rule_type: 'threshold',
    mitre_techniques: ['T1110.001', 'T1110.003'],
    created_at: '2026-01-15T10:00:00Z',
    updated_at: '2026-03-20T14:30:00Z',
    hits_24h: 58,
    false_positive_rate: 0.04
  },
  {
    rule_id: 'RULE-002',
    name: 'Lateral Movement via SMB/RPC',
    description: 'Flags suspicious PsExec service installation and remote file writes to ADMIN$ or IPC$ shares.',
    severity: 'critical',
    enabled: true,
    rule_type: 'sequence',
    mitre_techniques: ['T1021.002', 'T1570'],
    created_at: '2026-01-15T10:00:00Z',
    updated_at: '2026-04-01T09:15:00Z',
    hits_24h: 32,
    false_positive_rate: 0.02
  },
  {
    rule_id: 'RULE-003',
    name: 'Network Port & Vulnerability Sweep',
    description: 'Identifies horizontal or vertical port scanning activity exceeding 100 ports/minute.',
    severity: 'medium',
    enabled: true,
    rule_type: 'threshold',
    mitre_techniques: ['T1046'],
    created_at: '2026-01-15T10:00:00Z',
    updated_at: '2026-02-18T11:20:00Z',
    hits_24h: 22,
    false_positive_rate: 0.08
  },
  {
    rule_id: 'RULE-004',
    name: 'Obfuscated PowerShell Script Execution',
    description: 'Identifies PowerShell command lines using -EncodedCommand, -WindowStyle Hidden, or download cradles.',
    severity: 'high',
    enabled: true,
    rule_type: 'sequence',
    mitre_techniques: ['T1059.001', 'T1027'],
    created_at: '2026-01-20T16:00:00Z',
    updated_at: '2026-03-12T13:40:00Z',
    hits_24h: 18,
    false_positive_rate: 0.03
  },
  {
    rule_id: 'RULE-005',
    name: 'Credential Dumping via LSASS Injection',
    description: 'Detects unauthorized process handle opening of lsass.exe with PROCESS_VM_READ access privileges.',
    severity: 'critical',
    enabled: true,
    rule_type: 'sequence',
    mitre_techniques: ['T1003.001'],
    created_at: '2026-01-22T08:00:00Z',
    updated_at: '2026-04-10T15:00:00Z',
    hits_24h: 12,
    false_positive_rate: 0.01
  },
  {
    rule_id: 'ML-ANOMALY-001',
    name: 'Unsupervised High-Velocity Anomaly Detection',
    description: 'Isolation Forest ML engine detecting multi-feature behavioral deviations in network and host telemetry.',
    severity: 'high',
    enabled: true,
    rule_type: 'ml',
    mitre_techniques: ['T1078', 'T1030'],
    created_at: '2026-02-01T12:00:00Z',
    updated_at: '2026-04-18T17:30:00Z',
    hits_24h: 14,
    false_positive_rate: 0.05
  }
];

/* ==========================================================================
   12. Threat Entities (8 Diverse Entities)
   ========================================================================== */
export const mockEntities: Entity[] = [
  {
    entity_id: 'ENT-001',
    entity_type: 'ip',
    value: '185.220.101.5',
    first_seen: getRelativeISO(720),
    last_seen: getRelativeISO(8),
    risk_score: 98,
    related_alert_count: 14,
    related_incident_count: 2,
    tags: ['tor-exit-node', 'threat-intel-match', 'brute-force-source'],
    metadata: {
      asn: 'AS208294',
      country: 'Netherlands',
      reverse_dns: 'tor-exit-05.amsterdam.nl',
      reputation: 'known-scanner'
    }
  },
  {
    entity_id: 'ENT-002',
    entity_type: 'ip',
    value: '194.26.29.112',
    first_seen: getRelativeISO(360),
    last_seen: getRelativeISO(28),
    risk_score: 94,
    related_alert_count: 9,
    related_incident_count: 1,
    tags: ['bulletproof-vps', 'known-c2', 'cobalt-strike'],
    metadata: {
      asn: 'AS44050',
      country: 'Russia',
      reverse_dns: 'srv112.vpshost-ru.net',
      reputation: 'malicious-c2'
    }
  },
  {
    entity_id: 'ENT-003',
    entity_type: 'user',
    value: 'svc-backup',
    first_seen: getRelativeISO(1440),
    last_seen: getRelativeISO(8),
    risk_score: 88,
    related_alert_count: 6,
    related_incident_count: 2,
    tags: ['service-account', 'credential-leaked', 'off-hours-activity'],
    metadata: {
      department: 'Infrastructure IT',
      delegation_enabled: true,
      privilege_level: 'Domain Backup Operator'
    }
  },
  {
    entity_id: 'ENT-004',
    entity_type: 'user',
    value: 'dsmith_admin',
    first_seen: getRelativeISO(2880),
    last_seen: getRelativeISO(15),
    risk_score: 72,
    related_alert_count: 5,
    related_incident_count: 2,
    tags: ['domain-admin', 'vip', 'compromised-token'],
    metadata: {
      department: 'Enterprise Security',
      mfa_enforced: true,
      last_password_change: '45 days ago'
    }
  },
  {
    entity_id: 'ENT-005',
    entity_type: 'host',
    value: 'ws-finance-08.corp',
    first_seen: getRelativeISO(2880),
    last_seen: getRelativeISO(15),
    risk_score: 91,
    related_alert_count: 8,
    related_incident_count: 2,
    tags: ['patient-zero', 'endpoint-isolated', 'lsass-target'],
    metadata: {
      location: 'New York HQ - Floor 4',
      os: 'Windows 11 Pro 23H2',
      primary_user: 'dsmith_admin'
    }
  },
  {
    entity_id: 'ENT-006',
    entity_type: 'host',
    value: 'dc01.corp.internal',
    first_seen: getRelativeISO(5000),
    last_seen: getRelativeISO(2),
    risk_score: 65,
    related_alert_count: 4,
    related_incident_count: 1,
    tags: ['crown-jewel', 'domain-controller', 'ldap-kerberos'],
    metadata: {
      location: 'Primary Data Center Rack A-04',
      role: 'Primary Active Directory Domain Services'
    }
  },
  {
    entity_id: 'ENT-007',
    entity_type: 'domain',
    value: 'update-service-cdn-telemetry.com',
    first_seen: getRelativeISO(480),
    last_seen: getRelativeISO(25),
    risk_score: 95,
    related_alert_count: 7,
    related_incident_count: 1,
    tags: ['c2-domain', 'dga-pattern', 'fast-flux'],
    metadata: {
      registrar: 'NameCheap',
      nameservers: ['ns1.anonymousdns.to', 'ns2.anonymousdns.to'],
      whois_created: '2026-03-28'
    }
  },
  {
    entity_id: 'ENT-008',
    entity_type: 'domain',
    value: 'pastebin-raw-staging.xyz',
    first_seen: getRelativeISO(300),
    last_seen: getRelativeISO(180),
    risk_score: 89,
    related_alert_count: 3,
    related_incident_count: 1,
    tags: ['exfil-endpoint', 'suspicious-tld'],
    metadata: {
      registrar: 'Njalla',
      category: 'Drop-Box / Exfiltration Staging'
    }
  }
];

/* ==========================================================================
   13. Threat Map Geolocation Data
   ========================================================================== */
export const mockThreatMapData = [
  { lat: 55.7558, lng: 37.6173, count: 1420, country: 'Russia' },
  { lat: 52.3676, lng: 4.9041, count: 980, country: 'Netherlands' },
  { lat: 52.5200, lng: 13.4050, count: 750, country: 'Germany' },
  { lat: 39.9042, lng: 116.4074, count: 620, country: 'China' },
  { lat: 37.7749, lng: -122.4194, count: 540, country: 'United States' },
  { lat: 21.0285, lng: 105.8542, count: 380, country: 'Vietnam' },
  { lat: -23.5505, lng: -46.6333, count: 290, country: 'Brazil' }
];
