import React, { useState, useEffect, useCallback } from 'react';
import { api } from '../services/api';
import { SeverityBadge, SeverityLevel } from '../components/ui/SeverityBadge';
import { DataTable, Column } from '../components/ui/DataTable';
import { EmptyState } from '../components/ui/EmptyState';
import { LoadingState } from '../components/ui/LoadingState';
import { Bell, RefreshCw, Filter, ShieldAlert, CheckCircle2, AlertTriangle, ExternalLink } from 'lucide-react';

interface RealAlert {
  alert_id: string;
  rule_id: string;
  rule_version?: string;
  rule_name: string;
  severity: string;
  first_observed: string;
  last_observed: string;
  related_event_ids: string[];
  explanation: string;
  supporting_evidence: Record<string, any>;
  entities: Record<string, any>;
  confidence: number;
  risk_score: number;
  created_at: string;
  fingerprint?: string;
}

export const AlertsPage: React.FC = () => {
  const [alerts, setAlerts] = useState<RealAlert[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [refreshing, setRefreshing] = useState<boolean>(false);
  const [selectedSeverity, setSelectedSeverity] = useState<string>('ALL');
  const [selectedAlert, setSelectedAlert] = useState<RealAlert | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const fetchAlerts = useCallback(async (silent: boolean = false) => {
    try {
      if (!silent) setLoading(true);
      else setRefreshing(true);
      setErrorMessage(null);
      const res = await api.getAlerts({ severity: selectedSeverity, limit: 200 });
      setAlerts(res || []);
    } catch (err: any) {
      console.error('Failed to load live alerts:', err);
      setErrorMessage(err.message || 'Error connecting to detection engine');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [selectedSeverity]);

  useEffect(() => {
    fetchAlerts(false);
  }, [fetchAlerts]);

  const alertColumns: Column<RealAlert>[] = [
    {
      key: 'severity',
      header: 'Severity',
      width: '100px',
      render: (item) => (
        <SeverityBadge
          severity={item.severity as SeverityLevel}
          size="sm"
          withDot={item.severity.toLowerCase() === 'critical'}
        />
      ),
    },
    {
      key: 'rule_id',
      header: 'Rule',
      width: '120px',
      render: (item) => (
        <div>
          <span style={{ fontFamily: 'var(--font-mono, monospace)', fontSize: '0.75rem', color: '#93c5fd', fontWeight: 600 }}>
            {item.rule_id}
          </span>
          <div style={{ fontSize: '0.7rem', color: '#6b7280' }}>v{item.rule_version || '1.0'}</div>
        </div>
      ),
    },
    {
      key: 'rule_name',
      header: 'Alert Name & Explanation',
      render: (item) => (
        <div>
          <div style={{ fontWeight: 600, color: '#f3f4f6', fontSize: '0.8125rem' }}>{item.rule_name}</div>
          <div style={{ color: '#9ca3af', fontSize: '0.72rem', marginTop: '2px', lineHeight: 1.4 }}>
            {item.explanation}
          </div>
        </div>
      ),
    },
    {
      key: 'entities',
      header: 'Target Entities',
      width: '180px',
      render: (item) => (
        <div style={{ fontSize: '0.72rem', fontFamily: 'var(--font-mono, monospace)' }}>
          {item.entities?.source_ip && (
            <div style={{ color: '#f87171' }}>IP: {item.entities.source_ip}</div>
          )}
          {item.entities?.username && (
            <div style={{ color: '#fbbf24' }}>User: {item.entities.username}</div>
          )}
          {item.entities?.host && (
            <div style={{ color: '#a78bfa' }}>Host: {item.entities.host}</div>
          )}
          {!item.entities?.source_ip && !item.entities?.username && !item.entities?.host && (
            <span style={{ color: '#6b7280' }}>—</span>
          )}
        </div>
      ),
    },
    {
      key: 'risk_score',
      header: 'Risk Score',
      width: '100px',
      render: (item) => (
        <div style={{ width: '100%' }}>
          <span
            style={{
              fontSize: '0.75rem',
              fontWeight: 700,
              color: item.risk_score >= 80 ? '#ef4444' : item.risk_score >= 60 ? '#f97316' : '#eab308',
            }}
          >
            {Math.round(item.risk_score)}/100
          </span>
          <div style={{ height: '4px', width: '100%', backgroundColor: 'rgba(255,255,255,0.08)', borderRadius: '2px', marginTop: '3px' }}>
            <div
              style={{
                height: '100%',
                width: `${Math.min(item.risk_score, 100)}%`,
                backgroundColor: item.risk_score >= 80 ? '#ef4444' : item.risk_score >= 60 ? '#f97316' : '#eab308',
                borderRadius: '2px',
              }}
            />
          </div>
        </div>
      ),
    },
    {
      key: 'last_observed',
      header: 'Observed Time',
      width: '130px',
      render: (item) => (
        <div style={{ fontSize: '0.72rem', color: '#9ca3af' }}>
          <div>{new Date(item.last_observed).toLocaleDateString()}</div>
          <div style={{ color: '#6b7280' }}>{new Date(item.last_observed).toLocaleTimeString()}</div>
        </div>
      ),
    },
  ];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
      {/* Top Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '12px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <div style={{ width: '36px', height: '36px', borderRadius: '8px', backgroundColor: 'rgba(245, 158, 11, 0.15)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <Bell size={20} color="#f59e0b" />
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <h1 style={{ fontSize: '1.375rem', fontWeight: 700, color: '#f9fafb', margin: 0 }}>
                Live Detection Alerts
              </h1>
              <span style={{ fontSize: '0.72rem', fontWeight: 600, padding: '2px 8px', borderRadius: '10px', backgroundColor: 'rgba(16, 185, 129, 0.15)', color: '#10b981', border: '1px solid rgba(16, 185, 129, 0.3)' }}>
                DATABASE SYNCED
              </span>
            </div>
            <p style={{ color: '#9ca3af', fontSize: '0.8rem', margin: '2px 0 0 0' }}>
              Real-time threat alerts evaluated by deterministic detection rules directly from stored telemetry
            </p>
          </div>
        </div>

        {/* Severity Filter & Refresh */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <div style={{ display: 'flex', backgroundColor: '#111827', border: '1px solid rgba(255, 255, 255, 0.08)', borderRadius: '6px', padding: '2px' }}>
            {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((sev) => (
              <button
                key={sev}
                onClick={() => setSelectedSeverity(sev)}
                style={{
                  background: selectedSeverity === sev ? '#2563eb' : 'transparent',
                  color: selectedSeverity === sev ? '#ffffff' : '#9ca3af',
                  border: 'none',
                  borderRadius: '4px',
                  padding: '4px 10px',
                  fontSize: '0.72rem',
                  fontWeight: 600,
                  cursor: 'pointer',
                }}
              >
                {sev}
              </button>
            ))}
          </div>

          <button
            onClick={() => fetchAlerts(true)}
            disabled={refreshing}
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '6px',
              backgroundColor: '#1f2937',
              color: '#f9fafb',
              border: '1px solid rgba(255, 255, 255, 0.1)',
              borderRadius: '6px',
              padding: '6px 12px',
              fontSize: '0.78rem',
              fontWeight: 500,
              cursor: refreshing ? 'not-allowed' : 'pointer',
            }}
          >
            <RefreshCw size={13} className={refreshing ? 'spin' : ''} />
            <span>{refreshing ? 'Evaluating...' : 'Re-evaluate'}</span>
          </button>
        </div>
      </div>

      {/* Error notification if any */}
      {errorMessage && (
        <div style={{ padding: '0.75rem 1rem', background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.3)', borderRadius: '8px', color: '#f87171', fontSize: '0.8125rem' }}>
          {errorMessage}
        </div>
      )}

      {/* Main Alerts Content */}
      {loading ? (
        <LoadingState variant="skeleton" rows={6} message="Evaluating detection rules on stored telemetry..." />
      ) : alerts.length === 0 ? (
        <EmptyState
          icon={<CheckCircle2 size={48} color="#10b981" />}
          title="No Detection Alerts Found"
          description={
            selectedSeverity !== 'ALL'
              ? `No alerts matching severity '${selectedSeverity}' were evaluated from the stored event stream.`
              : 'No detection rules triggered against the current stored event repository. The system is operating nominally.'
          }
        />
      ) : (
        <div style={{ backgroundColor: '#1a1f2e', border: '1px solid rgba(255, 255, 255, 0.06)', borderRadius: '8px', padding: '16px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
            <span style={{ fontSize: '0.78rem', color: '#9ca3af' }}>
              Displaying <strong style={{ color: '#f3f4f6' }}>{alerts.length}</strong> real detection alert(s) evaluated from live event telemetry
            </span>
            <span style={{ fontSize: '0.72rem', color: '#6b7280' }}>
              Click any alert row to inspect forensic evidence
            </span>
          </div>

          <DataTable<RealAlert>
            columns={alertColumns}
            data={alerts}
            keyExtractor={(item) => item.alert_id}
            onRowClick={(item) => setSelectedAlert(item)}
            compact
          />
        </div>
      )}

      {/* Forensic Evidence Detail Modal */}
      {selectedAlert && (
        <div className="modal-overlay" onClick={() => setSelectedAlert(null)}>
          <div
            className="modal-content"
            onClick={(e) => e.stopPropagation()}
            style={{ maxWidth: '750px', padding: '24px', backgroundColor: '#111827', border: '1px solid rgba(255, 255, 255, 0.1)', borderRadius: '10px' }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '16px' }}>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <SeverityBadge severity={selectedAlert.severity as SeverityLevel} size="md" />
                  <span style={{ fontFamily: 'monospace', color: '#93c5fd', fontSize: '0.85rem', fontWeight: 600 }}>
                    {selectedAlert.alert_id}
                  </span>
                </div>
                <h2 style={{ fontSize: '1.25rem', fontWeight: 700, color: '#f9fafb', margin: '6px 0 2px 0' }}>
                  {selectedAlert.rule_name}
                </h2>
                <span style={{ color: '#6b7280', fontSize: '0.75rem' }}>
                  Rule ID: {selectedAlert.rule_id} • Fingerprint: {selectedAlert.fingerprint || 'N/A'}
                </span>
              </div>
              <button
                onClick={() => setSelectedAlert(null)}
                style={{ background: 'transparent', border: 'none', color: '#9ca3af', fontSize: '1.25rem', cursor: 'pointer' }}
              >
                ✕
              </button>
            </div>

            <div style={{ backgroundColor: '#1a1f2e', padding: '12px', borderRadius: '6px', marginBottom: '16px', border: '1px solid rgba(255, 255, 255, 0.05)' }}>
              <div style={{ fontSize: '0.75rem', fontWeight: 600, color: '#9ca3af', textTransform: 'uppercase', marginBottom: '4px' }}>
                Objective Forensic Explanation
              </div>
              <p style={{ color: '#e5e7eb', fontSize: '0.85rem', lineHeight: 1.5, margin: 0 }}>
                {selectedAlert.explanation}
              </p>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px', marginBottom: '16px' }}>
              <div style={{ backgroundColor: '#1a1f2e', padding: '12px', borderRadius: '6px', border: '1px solid rgba(255, 255, 255, 0.05)' }}>
                <div style={{ fontSize: '0.75rem', fontWeight: 600, color: '#9ca3af', textTransform: 'uppercase', marginBottom: '6px' }}>
                  Associated Entities
                </div>
                <div style={{ fontSize: '0.8rem', color: '#d1d5db', display: 'flex', flexDirection: 'column', gap: '4px', fontFamily: 'monospace' }}>
                  <div>Source IP: <span style={{ color: '#93c5fd' }}>{selectedAlert.entities?.source_ip || 'None'}</span></div>
                  <div>Account: <span style={{ color: '#fbbf24' }}>{selectedAlert.entities?.username || 'None'}</span></div>
                  <div>Host: <span style={{ color: '#a78bfa' }}>{selectedAlert.entities?.host || 'None'}</span></div>
                </div>
              </div>

              <div style={{ backgroundColor: '#1a1f2e', padding: '12px', borderRadius: '6px', border: '1px solid rgba(255, 255, 255, 0.05)' }}>
                <div style={{ fontSize: '0.75rem', fontWeight: 600, color: '#9ca3af', textTransform: 'uppercase', marginBottom: '6px' }}>
                  Risk & Confidence Metrics
                </div>
                <div style={{ fontSize: '0.8rem', color: '#d1d5db', display: 'flex', flexDirection: 'column', gap: '4px' }}>
                  <div>Confidence: <strong style={{ color: '#10b981' }}>{Math.round(selectedAlert.confidence * 100)}%</strong></div>
                  <div>Risk Score: <strong style={{ color: '#f87171' }}>{Math.round(selectedAlert.risk_score)}/100</strong></div>
                  <div>Contributing Events: <strong style={{ color: '#93c5fd' }}>{selectedAlert.related_event_ids.length}</strong></div>
                </div>
              </div>
            </div>

            <div style={{ marginBottom: '16px' }}>
              <div style={{ fontSize: '0.75rem', fontWeight: 600, color: '#9ca3af', textTransform: 'uppercase', marginBottom: '6px' }}>
                Forensic Evidence Event IDs
              </div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
                {selectedAlert.related_event_ids.map((id) => (
                  <span
                    key={id}
                    style={{
                      fontFamily: 'monospace',
                      fontSize: '0.72rem',
                      padding: '2px 8px',
                      backgroundColor: 'rgba(59, 130, 246, 0.15)',
                      color: '#93c5fd',
                      border: '1px solid rgba(59, 130, 246, 0.3)',
                      borderRadius: '4px',
                    }}
                  >
                    {id}
                  </span>
                ))}
              </div>
            </div>

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '8px' }}>
              <button
                onClick={() => setSelectedAlert(null)}
                style={{ padding: '8px 16px', borderRadius: '6px', backgroundColor: '#374151', color: '#f9fafb', border: 'none', cursor: 'pointer', fontSize: '0.8125rem' }}
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
export default AlertsPage;
