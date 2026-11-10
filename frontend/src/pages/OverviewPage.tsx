import React, { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Activity,
  AlertTriangle,
  Flame,
  ShieldAlert,
  Server,
  TrendingUp,
  Cpu,
  Bot,
  Globe,
  Radio,
  ArrowRight,
  Shield,
  Clock,
  Sparkles,
  RefreshCw,
  Database,
  CheckCircle2,
  AlertCircle
} from 'lucide-react';
import {
  AreaChart,
  Area,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Cell
} from 'recharts';

import { api } from '../services/api';
import { StatCard } from '../components/ui/StatCard';
import { SeverityBadge, SeverityLevel } from '../components/ui/SeverityBadge';
import { StatusBadge } from '../components/ui/StatusBadge';
import { ChartCard } from '../components/ui/ChartCard';
import { DataTable, Column } from '../components/ui/DataTable';
import { LoadingState } from '../components/ui/LoadingState';
import { EmptyState } from '../components/ui/EmptyState';
import type { Incident } from '../types';

interface RealAlertSummary {
  alert_id: string;
  rule_id: string;
  rule_name: string;
  severity: string;
  first_observed: string;
  last_observed: string;
  related_event_ids: string[];
  explanation: string;
  entities: Record<string, any>;
  risk_score: number;
}

export const OverviewPage: React.FC = () => {
  const navigate = useNavigate();
  const [loading, setLoading] = useState<boolean>(true);
  const [refreshing, setRefreshing] = useState<boolean>(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  // Real database metrics state
  const [totalEvents, setTotalEvents] = useState<number>(0);
  const [severityCounts, setSeverityCounts] = useState<Record<string, number>>({});
  const [eventTypeCounts, setEventTypeCounts] = useState<Record<string, number>>({});
  const [sourceHostCounts, setSourceHostCounts] = useState<Record<string, number>>({});
  const [timeSeries, setTimeSeries] = useState<Array<{ timestamp: string; value: number }>>([]);
  const [recentAlerts, setRecentAlerts] = useState<RealAlertSummary[]>([]);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [topAttackSources, setTopAttackSources] = useState<Array<{ ip: string; count: number; host: string }>>([]);
  const [databaseConnected, setDatabaseConnected] = useState<boolean>(true);

  const fetchRealOverview = useCallback(async (silent: boolean = false) => {
    try {
      if (!silent) setLoading(true);
      else setRefreshing(true);
      setErrorMessage(null);

      const [summaryRes, alertsRes, incidentsRes, healthRes, eventsListRes] = await Promise.all([
        api.getEventSummaryCounts().catch(() => null),
        api.getAlerts({ limit: 50 }).catch(() => []),
        api.getIncidents({ limit: 10 }).catch(() => ({ total: 0, incidents: [] })),
        api.getSystemHealth().catch(() => null),
        api.searchEvents({ limit: 100 }).catch(() => ({ total: 0, events: [] })),
      ]);

      if (summaryRes) {
        setTotalEvents(summaryRes.total_events || 0);
        setSeverityCounts(summaryRes.by_severity || {});
        setEventTypeCounts(summaryRes.by_event_type || {});
        setSourceHostCounts(summaryRes.by_source_host || {});

        if (summaryRes.time_series && summaryRes.time_series.length > 0) {
          setTimeSeries(
            summaryRes.time_series.map((ts) => {
              const dt = new Date(ts.bucket);
              return {
                timestamp: `${dt.getUTCHours().toString().padStart(2, '0')}:00`,
                value: ts.count,
              };
            })
          );
        } else {
          setTimeSeries([]);
        }
      }

      setRecentAlerts(alertsRes || []);
      setIncidents(incidentsRes?.incidents || []);
      setDatabaseConnected(healthRes?.database === 'connected');

      // Compute actual top malicious / active source IPs from event stream
      if (eventsListRes?.events) {
        const ipMap: Record<string, { count: number; host: string }> = {};
        for (const ev of eventsListRes.events) {
          if (ev.source_ip && ev.source_ip !== 'None') {
            if (!ipMap[ev.source_ip]) {
              ipMap[ev.source_ip] = { count: 0, host: ev.source_host || '—' };
            }
            ipMap[ev.source_ip].count += 1;
          }
        }
        const sortedIps = Object.entries(ipMap)
          .map(([ip, val]) => ({ ip, count: val.count, host: val.host }))
          .sort((a, b) => b.count - a.count)
          .slice(0, 5);
        setTopAttackSources(sortedIps);
      }
    } catch (err: any) {
      console.error('Failed to load real SOC telemetry:', err);
      setErrorMessage(err.message || 'Error connecting to ThreadGrid backend');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    fetchRealOverview(false);
    const interval = setInterval(() => fetchRealOverview(true), 10000);
    return () => clearInterval(interval);
  }, [fetchRealOverview]);

  // Derived real metric values directly from DB
  const criticalAlertsCount = recentAlerts.filter(
    (a) => a.severity.toLowerCase() === 'critical'
  ).length;

  const activeIncidentsCount = incidents.filter(
    (i) => i.status !== 'CLOSED' && i.status !== 'RESOLVED'
  ).length;

  const monitoredAssetsCount = Object.keys(sourceHostCounts).length;

  // Alerts by severity chart data from real database
  const alertsBySeverityData = [
    { severity: 'Critical', count: recentAlerts.filter((a) => a.severity.toLowerCase() === 'critical').length, fill: '#ef4444' },
    { severity: 'High', count: recentAlerts.filter((a) => a.severity.toLowerCase() === 'high').length, fill: '#f97316' },
    { severity: 'Medium', count: recentAlerts.filter((a) => a.severity.toLowerCase() === 'medium').length, fill: '#eab308' },
    { severity: 'Low', count: recentAlerts.filter((a) => a.severity.toLowerCase() === 'low').length, fill: '#06b6d4' },
  ];

  // Top event types from real database
  const topEventTypes = Object.entries(eventTypeCounts)
    .map(([type, count]) => ({
      type: type.replace(/_/g, ' '),
      count,
      percentage: totalEvents > 0 ? Math.round((count / totalEvents) * 100) : 0,
    }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 5);

  // Recent alerts table columns
  const alertColumns: Column<RealAlertSummary>[] = [
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
      key: 'rule_name',
      header: 'Alert / Rule',
      render: (item) => (
        <div>
          <div style={{ fontWeight: 600, color: '#f3f4f6', fontSize: '0.8125rem' }}>{item.rule_name}</div>
          <div style={{ color: '#9ca3af', fontSize: '0.72rem', maxWidth: '320px', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
            {item.explanation}
          </div>
        </div>
      ),
    },
    {
      key: 'entities',
      header: 'Source / Target',
      width: '160px',
      render: (item) => (
        <div style={{ fontFamily: 'var(--font-mono, monospace)', fontSize: '0.75rem' }}>
          <div style={{ color: '#93c5fd' }}>{item.entities?.source_ip || item.entities?.host || '—'}</div>
          {item.entities?.username && (
            <div style={{ color: '#fbbf24', fontSize: '0.7rem' }}>user: {item.entities.username}</div>
          )}
        </div>
      ),
    },
    {
      key: 'last_observed',
      header: 'Observed Time',
      width: '100px',
      render: (item) => {
        const d = new Date(item.last_observed);
        return (
          <span style={{ color: '#9ca3af', fontSize: '0.72rem' }}>
            {isNaN(d.getTime()) ? item.last_observed : d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
          </span>
        );
      },
    },
  ];

  // Active Incidents table columns
  const incidentColumns: Column<Incident>[] = [
    {
      key: 'severity',
      header: 'Sev',
      width: '80px',
      render: (item) => <SeverityBadge severity={item.severity as SeverityLevel} size="sm" />,
    },
    {
      key: 'title',
      header: 'Incident Title',
      render: (item) => (
        <div>
          <div style={{ fontWeight: 600, color: '#f3f4f6', fontSize: '0.8125rem' }}>{item.title}</div>
          <div style={{ display: 'flex', gap: '6px', marginTop: '2px' }}>
            {item.entities.source_ips.slice(0, 1).map((ip) => (
              <span key={ip} style={{ fontSize: '0.7rem', color: '#93c5fd', fontFamily: 'monospace' }}>{ip}</span>
            ))}
            {item.entities.hosts.slice(0, 1).map((h) => (
              <span key={h} style={{ fontSize: '0.7rem', color: '#a78bfa' }}>{h}</span>
            ))}
          </div>
        </div>
      ),
    },
    {
      key: 'risk_score',
      header: 'Risk',
      width: '100px',
      render: (item) => (
        <div style={{ width: '100%' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.7rem', marginBottom: '2px' }}>
            <span style={{ color: item.risk_score >= 80 ? '#ef4444' : item.risk_score >= 60 ? '#f97316' : '#eab308', fontWeight: 700 }}>
              {Math.round(item.risk_score)}/100
            </span>
          </div>
          <div style={{ height: '4px', width: '100%', backgroundColor: 'rgba(255,255,255,0.08)', borderRadius: '2px', overflow: 'hidden' }}>
            <div
              style={{
                height: '100%',
                width: `${Math.min(item.risk_score, 100)}%`,
                backgroundColor: item.risk_score >= 80 ? '#ef4444' : item.risk_score >= 60 ? '#f97316' : '#eab308',
              }}
            />
          </div>
        </div>
      ),
    },
    {
      key: 'status',
      header: 'Status',
      width: '100px',
      render: (item) => <StatusBadge status={item.status} />,
    },
  ];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      {/* Page Header with Real-Time Pill & Database Indicator */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '12px' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <h1 style={{ fontSize: '1.5rem', fontWeight: 700, color: '#f9fafb', margin: 0, letterSpacing: '-0.02em' }}>
              ThreadGrid SOC Command Center
            </h1>
            <div
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '6px',
                padding: '3px 9px',
                borderRadius: '12px',
                backgroundColor: databaseConnected ? 'rgba(16, 185, 129, 0.12)' : 'rgba(239, 68, 68, 0.12)',
                border: `1px solid ${databaseConnected ? 'rgba(16, 185, 129, 0.3)' : 'rgba(239, 68, 68, 0.3)'}`,
                color: databaseConnected ? '#10b981' : '#ef4444',
                fontSize: '0.72rem',
                fontWeight: 600,
              }}
            >
              <Radio size={12} className="spin" style={{ animationDuration: '3s' }} />
              <span>{databaseConnected ? 'DATABASE LIVE' : 'DISCONNECTED'}</span>
            </div>
          </div>
          <p style={{ color: '#9ca3af', fontSize: '0.8125rem', margin: '4px 0 0 0' }}>
            Production security operations telemetry query engine • All metrics computed from persistent SQLite database
          </p>
        </div>

        {/* Action Controls */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <button
            onClick={() => fetchRealOverview(true)}
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
            <span>{refreshing ? 'Querying DB...' : 'Sync Telemetry'}</span>
          </button>

          <button
            onClick={() => navigate('/incidents')}
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '6px',
              backgroundColor: '#2563eb',
              color: '#ffffff',
              border: 'none',
              borderRadius: '6px',
              padding: '6px 14px',
              fontSize: '0.78rem',
              fontWeight: 600,
              cursor: 'pointer',
            }}
          >
            <Shield size={14} />
            <span>Incident Queue</span>
          </button>
        </div>
      </div>

      {errorMessage && (
        <div style={{ padding: '0.75rem 1rem', background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.3)', borderRadius: '8px', color: '#f87171', fontSize: '0.8125rem' }}>
          {errorMessage}
        </div>
      )}

      {/* Row 1: Real Database KPI Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(210px, 1fr))', gap: '14px' }}>
        <StatCard
          title="Total Events Stored"
          value={totalEvents.toLocaleString()}
          icon={<Activity size={20} />}
          iconColor="#3b82f6"
          onClick={() => navigate('/events')}
          changeLabel="Real Database Count"
        />
        <StatCard
          title="Active Alerts"
          value={recentAlerts.length.toLocaleString()}
          icon={<AlertTriangle size={20} />}
          iconColor="#f59e0b"
          onClick={() => navigate('/alerts')}
          changeLabel="Detection Engine"
        />
        <StatCard
          title="Critical Alerts"
          value={criticalAlertsCount.toLocaleString()}
          icon={<Flame size={20} />}
          iconColor="#ef4444"
          onClick={() => navigate('/alerts')}
          changeLabel="High Priority"
        />
        <StatCard
          title="Correlated Incidents"
          value={activeIncidentsCount.toLocaleString()}
          icon={<ShieldAlert size={20} />}
          iconColor="#8b5cf6"
          onClick={() => navigate('/incidents')}
          changeLabel="Multi-Stage Clusters"
        />
        <StatCard
          title="Collector Hosts"
          value={monitoredAssetsCount.toLocaleString()}
          icon={<Server size={20} />}
          iconColor="#06b6d4"
          onClick={() => navigate('/system')}
          changeLabel="Active Ingesting Hosts"
        />
      </div>

      {/* Row 2: Real Database Velocity & Severity Distribution */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(420px, 1fr))', gap: '16px' }}>
        {/* Events Ingestion Velocity */}
        <ChartCard
          title="Events Ingestion Time Series"
          subtitle="Hourly event volume persisted in database sink"
          height={260}
          action={
            <span style={{ fontSize: '0.75rem', color: '#10b981', fontWeight: 600 }}>
              ● {totalEvents.toLocaleString()} Total Events
            </span>
          }
        >
          {timeSeries.length === 0 ? (
            <div style={{ height: '240px', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <span style={{ color: '#6b7280', fontSize: '0.8rem' }}>No time-series data buckets in database yet.</span>
            </div>
          ) : (
            <ResponsiveContainer width="100%" height={240}>
              <AreaChart data={timeSeries} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="realEventGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.35} />
                    <stop offset="95%" stopColor="#3b82f6" stopOpacity={0.0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255, 255, 255, 0.05)" vertical={false} />
                <XAxis dataKey="timestamp" stroke="#6b7280" fontSize={11} tickLine={false} />
                <YAxis stroke="#6b7280" fontSize={11} tickLine={false} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#111827',
                    borderColor: 'rgba(255, 255, 255, 0.1)',
                    borderRadius: '6px',
                    color: '#f9fafb',
                    fontSize: '0.75rem',
                  }}
                />
                <Area type="monotone" dataKey="value" stroke="#3b82f6" strokeWidth={2} fillOpacity={1} fill="url(#realEventGrad)" />
              </AreaChart>
            </ResponsiveContainer>
          )}
        </ChartCard>

        {/* Real Alerts by Severity */}
        <ChartCard
          title="Alert Volume by Severity"
          subtitle="Evaluated across deterministic detection rules (RULE-001..005)"
          height={260}
        >
          {recentAlerts.length === 0 ? (
            <div style={{ height: '240px', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <span style={{ color: '#6b7280', fontSize: '0.8rem' }}>No alerts triggered. System operating nominally.</span>
            </div>
          ) : (
            <ResponsiveContainer width="100%" height={240}>
              <BarChart data={alertsBySeverityData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255, 255, 255, 0.05)" vertical={false} />
                <XAxis dataKey="severity" stroke="#6b7280" fontSize={11} tickLine={false} textAnchor="middle" />
                <YAxis stroke="#6b7280" fontSize={11} tickLine={false} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#111827',
                    borderColor: 'rgba(255, 255, 255, 0.1)',
                    borderRadius: '6px',
                    color: '#f9fafb',
                    fontSize: '0.75rem',
                  }}
                />
                <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                  {alertsBySeverityData.map((entry) => (
                    <Cell key={entry.severity} fill={entry.fill} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          )}
        </ChartCard>
      </div>

      {/* Row 3: Real Alerts Table + Actual Event Types + Actual Source IPs */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '16px' }}>
        {/* Real Alerts Table */}
        <div style={{ backgroundColor: '#1a1f2e', border: '1px solid rgba(255, 255, 255, 0.06)', borderRadius: '8px', padding: '16px', display: 'flex', flexDirection: 'column', gap: '12px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <div>
              <h3 style={{ fontSize: '0.9375rem', fontWeight: 600, color: '#f9fafb', margin: 0 }}>
                Live Detection Alerts
              </h3>
              <p style={{ color: '#9ca3af', fontSize: '0.75rem', margin: '2px 0 0 0' }}>
                Deterministic rules evaluated on real stored telemetry
              </p>
            </div>
            <button
              onClick={() => navigate('/alerts')}
              style={{ background: 'transparent', border: 'none', color: '#3b82f6', fontSize: '0.75rem', cursor: 'pointer', display: 'inline-flex', alignItems: 'center', gap: '4px', fontWeight: 600 }}
            >
              <span>View All</span>
              <ArrowRight size={13} />
            </button>
          </div>

          {recentAlerts.length === 0 ? (
            <p style={{ color: '#6b7280', fontSize: '0.8rem', margin: '20px 0', textAlign: 'center' }}>
              No detection alerts triggered yet.
            </p>
          ) : (
            <DataTable<RealAlertSummary>
              columns={alertColumns}
              data={recentAlerts.slice(0, 5)}
              keyExtractor={(item) => item.alert_id}
              onRowClick={() => navigate('/alerts')}
              compact
            />
          )}
        </div>

        {/* Real Top Event Types */}
        <div style={{ backgroundColor: '#1a1f2e', border: '1px solid rgba(255, 255, 255, 0.06)', borderRadius: '8px', padding: '16px', display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <div>
            <h3 style={{ fontSize: '0.9375rem', fontWeight: 600, color: '#f9fafb', margin: 0 }}>
              Stored Event Classifications
            </h3>
            <p style={{ color: '#9ca3af', fontSize: '0.75rem', margin: '2px 0 14px 0' }}>
              Normalized breakdown across database events
            </p>

            {topEventTypes.length === 0 ? (
              <p style={{ color: '#6b7280', fontSize: '0.8rem' }}>No events recorded yet.</p>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                {topEventTypes.map((et) => (
                  <div key={et.type}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.75rem', marginBottom: '4px' }}>
                      <span style={{ color: '#d1d5db', textTransform: 'capitalize' }}>{et.type}</span>
                      <span style={{ color: '#9ca3af', fontWeight: 600 }}>{et.count.toLocaleString()} ({et.percentage}%)</span>
                    </div>
                    <div style={{ height: '5px', backgroundColor: 'rgba(255,255,255,0.06)', borderRadius: '3px', overflow: 'hidden' }}>
                      <div
                        style={{
                          height: '100%',
                          width: `${Math.min(et.percentage, 100)}%`,
                          backgroundColor: '#6366f1',
                          borderRadius: '3px',
                        }}
                      />
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          <div style={{ marginTop: '14px', paddingTop: '10px', borderTop: '1px solid rgba(255,255,255,0.05)', display: 'flex', justifyContent: 'space-between', fontSize: '0.72rem', color: '#6b7280' }}>
            <span>Canonical Schema</span>
            <span style={{ color: '#9ca3af' }}>v1.0 Strict UTC</span>
          </div>
        </div>

        {/* Real Top Source IPs */}
        <div style={{ backgroundColor: '#1a1f2e', border: '1px solid rgba(255, 255, 255, 0.06)', borderRadius: '8px', padding: '16px', display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <div>
            <h3 style={{ fontSize: '0.9375rem', fontWeight: 600, color: '#f9fafb', margin: 0 }}>
              Active Telemetry Source IPs
            </h3>
            <p style={{ color: '#9ca3af', fontSize: '0.75rem', margin: '2px 0 14px 0' }}>
              Extracted from raw security event stream
            </p>

            {topAttackSources.length === 0 ? (
              <p style={{ color: '#6b7280', fontSize: '0.8rem' }}>No source IP addresses logged in event telemetry.</p>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                {topAttackSources.map((src) => (
                  <div
                    key={src.ip}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      padding: '6px 8px',
                      borderRadius: '6px',
                      backgroundColor: 'rgba(255,255,255,0.02)',
                      border: '1px solid rgba(255,255,255,0.04)',
                    }}
                  >
                    <div>
                      <div style={{ fontFamily: 'var(--font-mono, monospace)', fontSize: '0.75rem', color: '#93c5fd', fontWeight: 600 }}>
                        {src.ip}
                      </div>
                      <div style={{ fontSize: '0.68rem', color: '#6b7280' }}>Host: {src.host}</div>
                    </div>
                    <div style={{ textAlign: 'right', fontSize: '0.75rem', fontWeight: 600, color: '#f9fafb' }}>
                      {src.count} events
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          <div style={{ marginTop: '14px', paddingTop: '10px', borderTop: '1px solid rgba(255,255,255,0.05)', display: 'flex', justifyContent: 'space-between', fontSize: '0.72rem', color: '#6b7280' }}>
            <span>Network Filter</span>
            <span style={{ color: '#10b981' }}>Sanitized IPv4/v6</span>
          </div>
        </div>
      </div>

      {/* Row 4: Real Correlated Incidents Table + AI Investigation Studio link */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(340px, 1fr))', gap: '16px' }}>
        {/* Real Incidents Mini Table */}
        <div style={{ backgroundColor: '#1a1f2e', border: '1px solid rgba(255, 255, 255, 0.06)', borderRadius: '8px', padding: '16px', display: 'flex', flexDirection: 'column', gap: '12px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <div>
              <h3 style={{ fontSize: '0.9375rem', fontWeight: 600, color: '#f9fafb', margin: 0 }}>
                Correlated Incidents
              </h3>
              <p style={{ color: '#9ca3af', fontSize: '0.75rem', margin: '2px 0 0 0' }}>
                Multi-stage graph correlated threat campaigns from database
              </p>
            </div>
            <button
              onClick={() => navigate('/incidents')}
              style={{ background: 'transparent', border: 'none', color: '#3b82f6', fontSize: '0.75rem', cursor: 'pointer', display: 'inline-flex', alignItems: 'center', gap: '4px', fontWeight: 600 }}
            >
              <span>Queue</span>
              <ArrowRight size={13} />
            </button>
          </div>

          {incidents.length === 0 ? (
            <p style={{ color: '#6b7280', fontSize: '0.8rem', textAlign: 'center', margin: '20px 0' }}>
              No correlated security incidents in database.
            </p>
          ) : (
            <DataTable<Incident>
              columns={incidentColumns}
              data={incidents.slice(0, 5)}
              keyExtractor={(item) => item.incident_id}
              onRowClick={() => navigate('/incidents')}
              compact
            />
          )}
        </div>

        {/* AI Assistant Studio Card */}
        <div style={{ backgroundColor: '#1a1f2e', border: '1px solid rgba(139, 92, 246, 0.25)', borderRadius: '8px', padding: '16px', display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <div style={{ width: '32px', height: '32px', borderRadius: '8px', backgroundColor: 'rgba(139, 92, 246, 0.15)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#a78bfa' }}>
                  <Bot size={18} />
                </div>
                <div>
                  <h3 style={{ fontSize: '0.9375rem', fontWeight: 600, color: '#f9fafb', margin: 0 }}>
                    ThreatGrid AI Copilot
                  </h3>
                  <span style={{ fontSize: '0.7rem', color: '#a78bfa' }}>Evidence-Grounded Local Synthesizer</span>
                </div>
              </div>
              <Sparkles size={16} color="#a78bfa" />
            </div>

            <p style={{ color: '#d1d5db', fontSize: '0.78rem', lineHeight: 1.45, margin: '8px 0 12px 0' }}>
              The offline AI copilot synthesizes verified forensic facts, maps attack chains directly to MITRE ATT&CK techniques, and generates reversible containment recommendations without sending sensitive logs to external cloud APIs.
            </p>

            <div style={{ backgroundColor: 'rgba(0, 0, 0, 0.25)', border: '1px solid rgba(255, 255, 255, 0.05)', borderRadius: '6px', padding: '10px', display: 'flex', flexDirection: 'column', gap: '6px', marginBottom: '14px' }}>
              <div style={{ fontSize: '0.72rem', color: '#9ca3af', fontWeight: 600 }}>OPERATIONAL EVIDENCE PRINCIPLES:</div>
              <div style={{ fontSize: '0.75rem', color: '#e5e7eb', display: 'flex', gap: '6px' }}>
                <span style={{ color: '#8b5cf6' }}>•</span>
                <span>Strict separation of Observed Facts, Hypotheses, and Actions</span>
              </div>
              <div style={{ fontSize: '0.75rem', color: '#e5e7eb', display: 'flex', gap: '6px' }}>
                <span style={{ color: '#8b5cf6' }}>•</span>
                <span>Zero hallucinations: every cited event ID strictly exists in DB</span>
              </div>
              <div style={{ fontSize: '0.75rem', color: '#e5e7eb', display: 'flex', gap: '6px' }}>
                <span style={{ color: '#8b5cf6' }}>•</span>
                <span>Prompt injection defense wraps all raw logs in boundary tags</span>
              </div>
            </div>
          </div>

          <button
            onClick={() => navigate('/ai-assistant')}
            style={{
              backgroundColor: '#7c3aed',
              color: '#ffffff',
              border: 'none',
              borderRadius: '6px',
              padding: '8px 14px',
              fontSize: '0.8125rem',
              fontWeight: 600,
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: '6px',
              boxShadow: '0 0 12px rgba(139, 92, 246, 0.35)',
            }}
          >
            <span>Launch AI Investigation Studio</span>
            <ArrowRight size={14} />
          </button>
        </div>
      </div>
    </div>
  );
};
export default OverviewPage;
