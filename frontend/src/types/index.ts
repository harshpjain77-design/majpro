export type IncidentStatus = 'NEW' | 'INVESTIGATING' | 'RESOLVED' | 'CLOSED';
export type Severity = 'low' | 'medium' | 'high' | 'critical';

export interface SecurityEvent {
  schema_version: string;
  event_id: string;
  timestamp: string;
  observed_at: string;
  source_host: string;
  source_type: string;
  event_type: string;
  username: string | null;
  source_ip: string | null;
  destination_ip: string | null;
  windows_event_id: number | null;
  severity: Severity;
  raw_event: string;
  collector_version?: string;
  metadata_json?: string;
  metadata?: Record<string, any>;
  ingested_at?: string;
}

export interface TimelineEntry {
  entry_id: string;
  timestamp: string;
  entry_type: 'alert' | 'event' | 'status_change' | 'note' | 'mitigation';
  description: string;
  source_id?: string;
  severity: string;
  entities: Record<string, any>;
}

export interface AnalystNote {
  note_id: string;
  author: string;
  created_at: string;
  content: string;
}

export interface Incident {
  incident_id: string;
  title: string;
  severity: Severity;
  status: IncidentStatus;
  risk_score: number;
  first_seen: string;
  last_seen: string;
  entities: {
    source_ips: string[];
    usernames: string[];
    hosts: string[];
  };
  related_alert_ids: string[];
  related_event_ids: string[];
  distinct_rules: string[];
  timeline: TimelineEntry[];
  analyst_notes: AnalystNote[];
  created_at: string;
  updated_at: string;
}

export interface DeduplicationMetrics {
  total_alerts_received: number;
  deduplicated_alerts_emitted: number;
  raw_alert_reduction_count: number;
  deduplication_ratio: number;
  total_incidents_created: number;
}

export interface FactEntry {
  fact: string;
  citations: string[];
}

export interface HypothesisEntry {
  hypothesis: string;
  mitre_technique?: string;
  confidence: number;
  supporting_citations: string[];
}

export interface RecommendationEntry {
  recommendation: string;
  priority: string;
  reversible: boolean;
  action_type: string;
  parameters: Record<string, any>;
}

export interface AIAnalysisReport {
  incident_id: string;
  generated_at: string;
  model_used: string;
  executive_summary: string;
  verified_facts: FactEntry[];
  threat_hypotheses: HypothesisEntry[];
  actionable_recommendations: RecommendationEntry[];
  citations_validated: boolean;
  valid_citation_ids: string[];
  invalid_citation_ids: string[];
  sanitization_warnings: string[];
}

export interface EventExplanation {
  event_id: string;
  timestamp: string;
  summary: string;
  security_significance: string;
  forensic_details: Record<string, any>;
  recommendation: string;
}

export interface MLStatus {
  is_trained: boolean;
  contamination: number;
  n_estimators: number;
  random_state: number;
  feature_window_seconds: number;
  features_tracked: string[];
  baseline_samples_count: number;
}

export interface MLEvaluationMetrics {
  total_samples: number;
  benign_samples: number;
  anomalous_samples: number;
  true_positives: number;
  false_positives: number;
  true_negatives: number;
  false_negatives: number;
  precision: number;
  recall: number;
  f1_score: number;
  accuracy: number;
  rule_comparison: {
    rule_engine: {
      precision: number;
      recall: number;
      f1_score: number;
      slow_and_low_detected: boolean;
    };
    isolation_forest: {
      precision: number;
      recall: number;
      f1_score: number;
      slow_and_low_detected: boolean;
    };
    scientific_insight: string;
  };
}

export type ActionType = 'block_ip' | 'lock_account' | 'terminate_session' | 'review_audit' | 'notify_analyst';
export type ActionStatus = 'PROPOSED' | 'APPROVED' | 'REJECTED' | 'EXECUTED' | 'SIMULATED' | 'FAILED' | 'ROLLED_BACK';
export type ActionPriority = 'low' | 'medium' | 'high' | 'immediate';

export interface ResponseActionRecord {
  action_id: string;
  incident_id: string;
  action_type: ActionType;
  target: string;
  parameters: Record<string, any>;
  priority: ActionPriority;
  reason: string;
  status: ActionStatus;
  dry_run: boolean;
  requires_approval: boolean;
  requested_by: string;
  approved_by: string | null;
  approved_at: string | null;
  executed_at: string | null;
  execution_output: Record<string, any> | null;
  rollback_data: Record<string, any> | null;
  rolled_back_at: string | null;
  created_at: string;
  error_message: string | null;
}

export interface SafetyStatusResponse {
  dry_run: boolean;
  auto_execution_enabled: boolean;
  auto_execution_risk_threshold: number;
  protected_ips: string[];
  protected_users: string[];
  rate_limit_per_minute: number;
  total_actions_recorded: number;
}

/* ==========================================================================
   ThreatGrid Extended Dashboard Types
   ========================================================================== */

export interface Alert {
  alert_id: string;
  rule_id: string;
  rule_name: string;
  severity: Severity;
  timestamp: string;
  source_ip: string | null;
  destination_ip: string | null;
  username: string | null;
  source_host: string | null;
  description: string;
  evidence_event_ids: string[];
  status: 'open' | 'acknowledged' | 'resolved' | 'false_positive';
  assignee: string | null;
  created_at: string;
  updated_at: string;
}

export interface Entity {
  entity_id: string;
  entity_type: 'ip' | 'user' | 'host' | 'domain';
  value: string;
  first_seen: string;
  last_seen: string;
  risk_score: number;
  related_alert_count: number;
  related_incident_count: number;
  tags: string[];
  metadata: Record<string, any>;
}

export interface Asset {
  asset_id: string;
  hostname: string;
  ip_address: string;
  os: string;
  asset_type: 'server' | 'workstation' | 'network_device' | 'cloud_instance';
  status: 'online' | 'offline' | 'unknown';
  last_seen: string;
  risk_score: number;
  agent_version: string | null;
  tags: string[];
}

export interface DetectionRule {
  rule_id: string;
  name: string;
  description: string;
  severity: Severity;
  enabled: boolean;
  rule_type: 'threshold' | 'sequence' | 'anomaly' | 'ml';
  mitre_techniques: string[];
  created_at: string;
  updated_at: string;
  hits_24h: number;
  false_positive_rate: number;
}

export interface SystemHealth {
  component: string;
  status: 'healthy' | 'warning' | 'error';
  message: string;
  last_check: string;
  metrics: Record<string, number>;
}

export interface AnomalyScore {
  entity: string;
  entity_type: string;
  score: number;
  threshold: number;
  is_anomalous: boolean;
  top_features: Array<{ name: string; contribution: number; value: number }>;
  timestamp: string;
}

export interface KPIMetric {
  label: string;
  value: number | string;
  change?: number;
  changeLabel?: string;
  trend?: 'up' | 'down' | 'stable';
  icon?: string;
}

export interface TimeSeriesDataPoint {
  timestamp: string;
  value: number;
  label?: string;
}

export interface NavItem {
  id: string;
  label: string;
  path: string;
  icon: string;
  badge?: number;
  badgeType?: 'count' | 'status';
}

export interface FilterState {
  query: string;
  severity: string;
  status: string;
  dateRange: { start: string; end: string } | null;
  sourceIp: string;
  sourceHost: string;
  username: string;
  eventType: string;
}
