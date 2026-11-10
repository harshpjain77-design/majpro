import React, { useState, useEffect, useCallback } from 'react';
import { api } from '../services/api';
import { LoadingState } from '../components/ui/LoadingState';
import { Monitor, Database, Activity, RefreshCw, CheckCircle2, AlertTriangle, XCircle, HardDrive, Cpu, Terminal } from 'lucide-react';

interface SystemHealthData {
  status: string;
  version: string;
  database: string;
  events_stored: number;
  uptime_seconds: number;
}

export const SystemPage: React.FC = () => {
  const [health, setHealth] = useState<SystemHealthData | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [refreshing, setRefreshing] = useState<boolean>(false);
  const [hosts, setHosts] = useState<Record<string, number>>({});
  const [collectorLogs, setCollectorLogs] = useState<string[]>([]);

  const fetchHealth = useCallback(async (silent = false) => {
    try {
      if (!silent) setLoading(true);
      else setRefreshing(true);

      const [h, counts] = await Promise.all([
        api.getSystemHealth(),
        api.getEventSummaryCounts().catch(() => null),
      ]);

      setHealth(h);
      if (counts?.by_source_host) {
        setHosts(counts.by_source_host);
      }
    } catch (err) {
      console.error('Failed to load system health:', err);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    fetchHealth(false);
    const interval = setInterval(() => fetchHealth(true), 10000);
    return () => clearInterval(interval);
  }, [fetchHealth]);

  const formatUptime = (seconds: number) => {
    const d = Math.floor(seconds / (3600 * 24));
    const h = Math.floor((seconds % (3600 * 24)) / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    const s = Math.floor(seconds % 60);
    return `${d > 0 ? `${d}d ` : ''}${h > 0 ? `${h}h ` : ''}${m}m ${s}s`;
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
      {/* Top Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '12px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <div style={{ width: '36px', height: '36px', borderRadius: '8px', backgroundColor: 'rgba(59, 130, 246, 0.15)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <Monitor size={20} color="#3b82f6" />
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <h1 style={{ fontSize: '1.375rem', fontWeight: 700, color: '#f9fafb', margin: 0 }}>
                System & Collector Health
              </h1>
              <span style={{ fontSize: '0.72rem', fontWeight: 600, padding: '2px 8px', borderRadius: '10px', backgroundColor: health?.status === 'ok' ? 'rgba(16, 185, 129, 0.15)' : 'rgba(239, 68, 68, 0.15)', color: health?.status === 'ok' ? '#10b981' : '#ef4444', border: `1px solid ${health?.status === 'ok' ? 'rgba(16, 185, 129, 0.3)' : 'rgba(239, 68, 68, 0.3)'}` }}>
                {health?.status === 'ok' ? 'OPERATIONAL' : 'DEGRADED'}
              </span>
            </div>
            <p style={{ color: '#9ca3af', fontSize: '0.8rem', margin: '2px 0 0 0' }}>
              Real-time operational status of Central Ingestion API, SQLite database sink, and telemetry agents
            </p>
          </div>
        </div>

        <button
          onClick={() => fetchHealth(true)}
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
          <span>Refresh Status</span>
        </button>
      </div>

      {loading && !health ? (
        <LoadingState variant="skeleton" rows={4} message="Querying live system components..." />
      ) : (
        <>
          {/* Component Status Grid */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '14px' }}>
            {/* Ingestion API Component */}
            <div style={{ backgroundColor: '#1a1f2e', border: '1px solid rgba(255, 255, 255, 0.06)', borderRadius: '8px', padding: '16px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <Activity size={18} color="#3b82f6" />
                  <span style={{ fontWeight: 600, color: '#f3f4f6', fontSize: '0.875rem' }}>Central Ingestion API</span>
                </div>
                <span style={{ fontSize: '0.7rem', color: '#10b981', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '4px' }}>
                  <CheckCircle2 size={13} /> HEALTHY
                </span>
              </div>
              <div style={{ fontSize: '0.75rem', color: '#9ca3af', display: 'flex', flexDirection: 'column', gap: '4px' }}>
                <div>Endpoint: <code style={{ color: '#93c5fd' }}>http://127.0.0.1:8000/api/v1</code></div>
                <div>Version: <span style={{ color: '#f3f4f6' }}>v{health?.version || '0.1.0'}</span></div>
                <div>Process Uptime: <span style={{ color: '#f3f4f6' }}>{health ? formatUptime(health.uptime_seconds) : '—'}</span></div>
              </div>
            </div>

            {/* SQLite Storage Sink */}
            <div style={{ backgroundColor: '#1a1f2e', border: '1px solid rgba(255, 255, 255, 0.06)', borderRadius: '8px', padding: '16px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <Database size={18} color="#10b981" />
                  <span style={{ fontWeight: 600, color: '#f3f4f6', fontSize: '0.875rem' }}>SQLite Database Sink</span>
                </div>
                <span style={{ fontSize: '0.7rem', color: health?.database === 'connected' ? '#10b981' : '#ef4444', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '4px' }}>
                  {health?.database === 'connected' ? <CheckCircle2 size={13} /> : <XCircle size={13} />}
                  {health?.database === 'connected' ? 'CONNECTED' : 'DISCONNECTED'}
                </span>
              </div>
              <div style={{ fontSize: '0.75rem', color: '#9ca3af', display: 'flex', flexDirection: 'column', gap: '4px' }}>
                <div>File Path: <code style={{ color: '#93c5fd' }}>output/soc_events.sqlite</code></div>
                <div>Storage Mode: <span style={{ color: '#f3f4f6' }}>WAL (Write-Ahead Logging)</span></div>
                <div>Persisted Events: <strong style={{ color: '#10b981' }}>{health?.events_stored.toLocaleString() || '0'}</strong></div>
              </div>
            </div>

            {/* Detection & Correlation Engine */}
            <div style={{ backgroundColor: '#1a1f2e', border: '1px solid rgba(255, 255, 255, 0.06)', borderRadius: '8px', padding: '16px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <Cpu size={18} color="#8b5cf6" />
                  <span style={{ fontWeight: 600, color: '#f3f4f6', fontSize: '0.875rem' }}>Detection & Correlation</span>
                </div>
                <span style={{ fontSize: '0.7rem', color: '#10b981', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '4px' }}>
                  <CheckCircle2 size={13} /> ACTIVE
                </span>
              </div>
              <div style={{ fontSize: '0.75rem', color: '#9ca3af', display: 'flex', flexDirection: 'column', gap: '4px' }}>
                <div>Deterministic Rules: <strong style={{ color: '#f3f4f6' }}>5 Active (RULE-001..005)</strong></div>
                <div>Anomaly Engine: <span style={{ color: '#a78bfa' }}>Isolation Forest (ML-ANOMALY-001)</span></div>
                <div>Incident Deduplication: <span style={{ color: '#10b981' }}>Graph Correlation Enabled</span></div>
              </div>
            </div>
          </div>

          {/* Active Collector Hosts Table */}
          <div style={{ backgroundColor: '#1a1f2e', border: '1px solid rgba(255, 255, 255, 0.06)', borderRadius: '8px', padding: '16px' }}>
            <h3 style={{ fontSize: '0.9375rem', fontWeight: 600, color: '#f9fafb', margin: '0 0 12px 0' }}>
              Monitored Telemetry Collector Hosts
            </h3>

            {Object.keys(hosts).length === 0 ? (
              <p style={{ color: '#6b7280', fontSize: '0.8rem', margin: 0 }}>
                No collector heartbeats or host events currently registered. Start a collector to begin streaming.
              </p>
            ) : (
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(240px, 1fr))', gap: '10px' }}>
                {Object.entries(hosts).map(([hostname, eventCount]) => {
                  const isWindows = hostname.toLowerCase().includes('win') || hostname.toLowerCase().includes('soga');
                  const isLinux = hostname.toLowerCase().includes('srv') || hostname.toLowerCase().includes('harsh') || hostname.toLowerCase().includes('kali');
                  return (
                    <div
                      key={hostname}
                      style={{
                        padding: '10px',
                        borderRadius: '6px',
                        backgroundColor: 'rgba(255, 255, 255, 0.02)',
                        border: '1px solid rgba(255, 255, 255, 0.05)',
                        display: 'flex',
                        flexDirection: 'column',
                        gap: '4px',
                      }}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <span style={{ fontWeight: 600, color: '#f3f4f6', fontSize: '0.8125rem', fontFamily: 'monospace' }}>
                          {hostname}
                        </span>
                        <span style={{ fontSize: '0.68rem', color: '#10b981', fontWeight: 600 }}>ONLINE</span>
                      </div>
                      <div style={{ fontSize: '0.72rem', color: '#9ca3af' }}>
                        OS Type: <span style={{ color: isWindows ? '#60a5fa' : isLinux ? '#f97316' : '#9ca3af' }}>{isWindows ? 'Windows Server' : isLinux ? 'Linux / Kali' : 'Unknown'}</span>
                      </div>
                      <div style={{ fontSize: '0.72rem', color: '#9ca3af' }}>
                        Events Received: <strong style={{ color: '#10b981' }}>{eventCount.toLocaleString()}</strong>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
};
export default SystemPage;
