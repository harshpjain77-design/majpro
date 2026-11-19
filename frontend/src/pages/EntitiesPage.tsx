import React, { useState, useEffect, useCallback, useMemo } from 'react';
import {
  Users,
  Globe,
  Server,
  ShieldAlert,
  AlertTriangle,
  Search,
  RefreshCw,
  ExternalLink,
  Shield,
  Activity,
  UserCheck,
  Ban,
  Clock,
  Layers,
  CheckCircle,
  XCircle,
  X,
  Radio,
  SlidersHorizontal,
} from 'lucide-react';
import { api } from '../services/api';
import {
  EntitiesExplorerResponse,
  EntityDetailResponse,
  UserEntity,
  IPEntity,
  HostEntity,
} from '../types';
import { StatCard } from '../components/ui/StatCard';
import { DataTable, Column } from '../components/ui/DataTable';
import { SeverityBadge, SeverityLevel } from '../components/ui/SeverityBadge';
import { LoadingState } from '../components/ui/LoadingState';
import { ErrorState } from '../components/ui/ErrorState';

type TabKey = 'users' | 'ips' | 'hosts';
type RiskTierFilter = 'all' | 'critical' | 'high' | 'medium' | 'low';

export const EntitiesPage: React.FC = () => {
  // Main explorer state
  const [data, setData] = useState<EntitiesExplorerResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [refreshing, setRefreshing] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  // Filters & Tabs
  const [activeTab, setActiveTab] = useState<TabKey>('users');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [riskFilter, setRiskFilter] = useState<RiskTierFilter>('all');

  // Forensic Profile Drawer / Modal state
  const [selectedEntity, setSelectedEntity] = useState<{
    type: 'user' | 'ip' | 'host';
    identifier: string;
  } | null>(null);
  const [detailLoading, setDetailLoading] = useState<boolean>(false);
  const [entityDetail, setEntityDetail] = useState<EntityDetailResponse | null>(null);
  const [detailError, setDetailError] = useState<string | null>(null);
  const [stagingAction, setStagingAction] = useState<boolean>(false);
  const [actionSuccessMessage, setActionSuccessMessage] = useState<string | null>(null);

  // Fetch Entities Data
  const fetchEntities = useCallback(async (isBackground: boolean = false) => {
    try {
      if (!isBackground) setLoading(true);
      else setRefreshing(true);
      setError(null);

      const res = await api.getEntitiesExplorer({
        q: searchQuery,
        tier: riskFilter,
      });
      setData(res);
    } catch (err: any) {
      setError(err?.message || 'Failed to load entities data');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [searchQuery, riskFilter]);

  // Initial load and filter changes
  useEffect(() => {
    fetchEntities();
  }, [fetchEntities]);

  // Auto-refresh every 6 seconds to stay in sync with live collector ingestion
  useEffect(() => {
    const timer = setInterval(() => {
      fetchEntities(true);
    }, 6000);
    return () => clearInterval(timer);
  }, [fetchEntities]);

  // Fetch Entity Detail when drawer opens
  useEffect(() => {
    if (!selectedEntity) {
      setEntityDetail(null);
      setDetailError(null);
      setActionSuccessMessage(null);
      return;
    }

    const loadDetail = async () => {
      try {
        setDetailLoading(true);
        setDetailError(null);
        setActionSuccessMessage(null);
        const res = await api.getEntityDetail(selectedEntity.type, selectedEntity.identifier, 25);
        setEntityDetail(res);
      } catch (err: any) {
        setDetailError(err?.message || 'Failed to load entity forensic profile');
      } finally {
        setDetailLoading(false);
      }
    };

    loadDetail();
  }, [selectedEntity]);

  // Handle Containment Staging
  const handleStageAction = async (rec: { action_type: string; target: string; reason: string; parameters: any }) => {
    try {
      setStagingAction(true);
      const incId = entityDetail?.incidents?.[0]?.incident_id || 'inc_manual_containment';
      await api.proposeResponseAction({
        incident_id: incId,
        action_type: rec.action_type,
        target: rec.target,
        parameters: rec.parameters,
        priority: 'HIGH',
        reason: `[Entities Explorer] ${rec.reason}`,
      });
      setActionSuccessMessage(`Successfully staged action '${rec.action_type}' for target '${rec.target}' in Response Console.`);
      // Refresh current detail
      if (selectedEntity) {
        const refreshed = await api.getEntityDetail(selectedEntity.type, selectedEntity.identifier);
        setEntityDetail(refreshed);
      }
      fetchEntities(true);
    } catch (err: any) {
      alert(`Failed to stage action: ${err?.message || err}`);
    } finally {
      setStagingAction(false);
    }
  };

  // Helper Badge Renderers
  const renderAccountTypeBadge = (type: string) => {
    const map: Record<string, { bg: string; color: string; border: string; label: string }> = {
      privileged: { bg: 'rgba(239, 68, 68, 0.15)', color: '#ef4444', border: 'rgba(239, 68, 68, 0.35)', label: 'Privileged' },
      service: { bg: 'rgba(59, 130, 246, 0.15)', color: '#60a5fa', border: 'rgba(59, 130, 246, 0.35)', label: 'Service' },
      invalid: { bg: 'rgba(249, 115, 22, 0.15)', color: '#fb923c', border: 'rgba(249, 115, 22, 0.35)', label: 'Invalid / Fake' },
      standard: { bg: 'rgba(107, 114, 128, 0.15)', color: '#9ca3af', border: 'rgba(107, 114, 128, 0.35)', label: 'Standard' },
    };
    const c = map[type.toLowerCase()] || map.standard;
    return (
      <span
        style={{
          display: 'inline-flex',
          alignItems: 'center',
          gap: '0.25rem',
          padding: '0.15rem 0.5rem',
          borderRadius: '9999px',
          fontSize: '0.72rem',
          fontWeight: 600,
          backgroundColor: c.bg,
          color: c.color,
          border: `1px solid ${c.border}`,
          textTransform: 'uppercase',
          letterSpacing: '0.04em',
        }}
      >
        {c.label}
      </span>
    );
  };

  const renderScopeBadge = (scope: string) => {
    const map: Record<string, { bg: string; color: string; border: string; label: string }> = {
      external: { bg: 'rgba(239, 68, 68, 0.15)', color: '#ef4444', border: 'rgba(239, 68, 68, 0.35)', label: 'External Inbound' },
      internal: { bg: 'rgba(16, 185, 129, 0.15)', color: '#34d399', border: 'rgba(16, 185, 129, 0.35)', label: 'Internal LAN' },
      loopback: { bg: 'rgba(6, 182, 212, 0.15)', color: '#22d3ee', border: 'rgba(6, 182, 212, 0.35)', label: 'Loopback Host' },
    };
    const c = map[scope.toLowerCase()] || map.internal;
    return (
      <span
        style={{
          display: 'inline-flex',
          alignItems: 'center',
          padding: '0.15rem 0.5rem',
          borderRadius: '9999px',
          fontSize: '0.72rem',
          fontWeight: 600,
          backgroundColor: c.bg,
          color: c.color,
          border: `1px solid ${c.border}`,
        }}
      >
        {c.label}
      </span>
    );
  };

  const renderContainmentBadge = (status: string) => {
    if (status === 'contained') {
      return (
        <span
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '0.3rem',
            padding: '0.15rem 0.5rem',
            borderRadius: '9999px',
            fontSize: '0.72rem',
            fontWeight: 600,
            backgroundColor: 'rgba(16, 185, 129, 0.15)',
            color: '#10b981',
            border: '1px solid rgba(16, 185, 129, 0.35)',
          }}
        >
          <CheckCircle size={11} />
          Contained
        </span>
      );
    }
    if (status === 'pending') {
      return (
        <span
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '0.3rem',
            padding: '0.15rem 0.5rem',
            borderRadius: '9999px',
            fontSize: '0.72rem',
            fontWeight: 600,
            backgroundColor: 'rgba(234, 179, 8, 0.15)',
            color: '#eab308',
            border: '1px solid rgba(234, 179, 8, 0.35)',
          }}
        >
          <Clock size={11} />
          Pending Action
        </span>
      );
    }
    return (
      <span
        style={{
          display: 'inline-flex',
          alignItems: 'center',
          gap: '0.3rem',
          padding: '0.15rem 0.5rem',
          borderRadius: '9999px',
          fontSize: '0.72rem',
          fontWeight: 600,
          backgroundColor: 'rgba(107, 114, 128, 0.15)',
          color: '#9ca3af',
          border: '1px solid rgba(107, 114, 128, 0.3)',
        }}
      >
        <Radio size={11} />
        Active / Monitored
      </span>
    );
  };

  const renderStatusDot = (st: string) => {
    const isOnline = st === 'online';
    return (
      <span style={{ display: 'inline-flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.8rem', color: isOnline ? '#34d399' : '#9ca3af' }}>
        <span
          style={{
            width: '8px',
            height: '8px',
            borderRadius: '50%',
            backgroundColor: isOnline ? '#10b981' : '#6b7280',
            boxShadow: isOnline ? '0 0 8px #10b981' : 'none',
          }}
        />
        {isOnline ? 'Online (Active)' : 'Idle'}
      </span>
    );
  };

  // -------------------------------------------------------------------------
  // Column Definitions for DataTables
  // -------------------------------------------------------------------------

  const userColumns: Column<UserEntity>[] = useMemo(
    () => [
      {
        key: 'username',
        header: 'User Account',
        render: (u) => (
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
            <div
              style={{
                width: '32px',
                height: '32px',
                borderRadius: '8px',
                backgroundColor: 'rgba(59, 130, 246, 0.15)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: '#60a5fa',
              }}
            >
              <UserCheck size={16} />
            </div>
            <div>
              <div style={{ fontWeight: 600, color: 'var(--text-primary)', fontSize: '0.875rem' }}>{u.username}</div>
              <div style={{ marginTop: '0.2rem' }}>{renderAccountTypeBadge(u.account_type)}</div>
            </div>
          </div>
        ),
      },
      {
        key: 'total_events',
        header: 'Event Volume',
        render: (u) => (
          <div>
            <div style={{ fontWeight: 600, color: 'var(--text-primary)', fontSize: '0.85rem' }}>
              {u.total_events.toLocaleString()} events
            </div>
            <div style={{ fontSize: '0.72rem', color: '#94a3b8' }}>
              {u.hosts.length} {u.hosts.length === 1 ? 'host' : 'hosts'} accessed
            </div>
          </div>
        ),
      },
      {
        key: 'auth_metrics',
        header: 'Authentication Ratio',
        render: (u) => {
          const pct = Math.round(u.failure_ratio * 100);
          const barColor = pct > 60 ? '#ef4444' : pct > 20 ? '#f59e0b' : '#10b981';
          return (
            <div style={{ minWidth: '130px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.75rem', marginBottom: '0.25rem' }}>
                <span style={{ color: '#ef4444' }}>{u.failed_logins} fail</span>
                <span style={{ color: '#10b981' }}>{u.successful_logins} pass</span>
              </div>
              <div style={{ width: '100%', height: '5px', backgroundColor: '#334155', borderRadius: '3px', overflow: 'hidden' }}>
                <div style={{ width: `${pct}%`, height: '100%', backgroundColor: barColor }} />
              </div>
              <div style={{ fontSize: '0.7rem', color: '#94a3b8', marginTop: '0.2rem', textAlign: 'right' }}>
                {pct}% failure rate
              </div>
            </div>
          );
        },
      },
      {
        key: 'risk_score',
        header: 'Risk Tier',
        render: (u) => (
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <SeverityBadge severity={u.risk_tier as SeverityLevel} size="sm" />
            <span style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-primary)' }}>
              {u.risk_score}
            </span>
          </div>
        ),
      },
      {
        key: 'incidents',
        header: 'Incidents',
        render: (u) => (
          <div>
            {u.incident_count > 0 ? (
              <span
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '0.3rem',
                  padding: '0.2rem 0.5rem',
                  borderRadius: '6px',
                  backgroundColor: 'rgba(239, 68, 68, 0.15)',
                  color: '#ef4444',
                  fontSize: '0.75rem',
                  fontWeight: 600,
                  border: '1px solid rgba(239, 68, 68, 0.3)',
                }}
              >
                <ShieldAlert size={12} />
                {u.incident_count} {u.incident_count === 1 ? 'incident' : 'incidents'}
              </span>
            ) : (
              <span style={{ fontSize: '0.75rem', color: '#64748b' }}>None</span>
            )}
          </div>
        ),
      },
      {
        key: 'containment',
        header: 'Containment',
        render: (u) => renderContainmentBadge(u.containment_status),
      },
      {
        key: 'actions',
        header: 'Action',
        align: 'right',
        render: (u) => (
          <button
            onClick={(e) => {
              e.stopPropagation();
              setSelectedEntity({ type: 'user', identifier: u.username });
            }}
            style={{
              padding: '0.35rem 0.75rem',
              backgroundColor: 'var(--bg-tertiary)',
              color: 'var(--color-primary)',
              border: '1px solid var(--border-color)',
              borderRadius: '6px',
              fontSize: '0.75rem',
              fontWeight: 500,
              cursor: 'pointer',
              display: 'inline-flex',
              alignItems: 'center',
              gap: '0.3rem',
              transition: 'all 0.15s ease',
            }}
            onMouseEnter={(e) => {
              e.currentTarget.style.backgroundColor = 'var(--color-primary)';
              e.currentTarget.style.color = '#ffffff';
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.backgroundColor = 'var(--bg-tertiary)';
              e.currentTarget.style.color = 'var(--color-primary)';
            }}
          >
            Investigate
            <ExternalLink size={12} />
          </button>
        ),
      },
    ],
    []
  );

  const ipColumns: Column<IPEntity>[] = useMemo(
    () => [
      {
        key: 'ip',
        header: 'IP Address',
        render: (item) => (
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
            <div
              style={{
                width: '32px',
                height: '32px',
                borderRadius: '8px',
                backgroundColor: item.scope === 'external' ? 'rgba(239, 68, 68, 0.15)' : 'rgba(16, 185, 129, 0.15)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: item.scope === 'external' ? '#ef4444' : '#34d399',
              }}
            >
              <Globe size={16} />
            </div>
            <div>
              <div style={{ fontFamily: 'monospace', fontWeight: 600, color: 'var(--text-primary)', fontSize: '0.875rem' }}>
                {item.ip}
              </div>
              <div style={{ marginTop: '0.2rem' }}>{renderScopeBadge(item.scope)}</div>
            </div>
          </div>
        ),
      },
      {
        key: 'threat_tag',
        header: 'Threat Behavior Tag',
        render: (item) => (
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
            {item.risk_tier === 'critical' || item.risk_tier === 'high' ? (
              <AlertTriangle size={14} color="#f97316" />
            ) : (
              <Activity size={14} color="#0284c7" />
            )}
            <span style={{ fontSize: '0.8125rem', color: 'var(--text-primary)', fontWeight: 500 }}>
              {item.threat_tag}
            </span>
          </div>
        ),
      },
      {
        key: 'footprint',
        header: 'Attack Footprint',
        render: (item) => (
          <div>
            <div style={{ fontSize: '0.8125rem', color: 'var(--text-primary)' }}>
              <strong>{item.target_users_count}</strong> {item.target_users_count === 1 ? 'user' : 'users'} targeted
            </div>
            <div style={{ fontSize: '0.72rem', color: '#94a3b8' }}>
              {item.target_hosts_count} {item.target_hosts_count === 1 ? 'host' : 'hosts'} contacted
            </div>
          </div>
        ),
      },
      {
        key: 'total_events',
        header: 'Total Traffic',
        render: (item) => (
          <span style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-primary)' }}>
            {item.total_events.toLocaleString()} pkts / evts
          </span>
        ),
      },
      {
        key: 'risk_tier',
        header: 'Risk Tier',
        render: (item) => (
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <SeverityBadge severity={item.risk_tier as SeverityLevel} size="sm" />
            <span style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-primary)' }}>
              {item.risk_score}
            </span>
          </div>
        ),
      },
      {
        key: 'containment',
        header: 'Containment',
        render: (item) => renderContainmentBadge(item.containment_status),
      },
      {
        key: 'actions',
        header: 'Action',
        align: 'right',
        render: (item) => (
          <button
            onClick={(e) => {
              e.stopPropagation();
              setSelectedEntity({ type: 'ip', identifier: item.ip });
            }}
            style={{
              padding: '0.35rem 0.75rem',
              backgroundColor: 'var(--bg-tertiary)',
              color: 'var(--color-primary)',
              border: '1px solid var(--border-color)',
              borderRadius: '6px',
              fontSize: '0.75rem',
              fontWeight: 500,
              cursor: 'pointer',
              display: 'inline-flex',
              alignItems: 'center',
              gap: '0.3rem',
              transition: 'all 0.15s ease',
            }}
            onMouseEnter={(e) => {
              e.currentTarget.style.backgroundColor = 'var(--color-primary)';
              e.currentTarget.style.color = '#ffffff';
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.backgroundColor = 'var(--bg-tertiary)';
              e.currentTarget.style.color = 'var(--color-primary)';
            }}
          >
            Investigate
            <ExternalLink size={12} />
          </button>
        ),
      },
    ],
    []
  );

  const hostColumns: Column<HostEntity>[] = useMemo(
    () => [
      {
        key: 'hostname',
        header: 'Monitored Hostname',
        render: (item) => (
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
            <div
              style={{
                width: '32px',
                height: '32px',
                borderRadius: '8px',
                backgroundColor: 'rgba(168, 85, 247, 0.15)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: '#c084fc',
              }}
            >
              <Server size={16} />
            </div>
            <div>
              <div style={{ fontWeight: 600, color: 'var(--text-primary)', fontSize: '0.875rem' }}>{item.hostname}</div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', marginTop: '0.2rem' }}>
                <span
                  style={{
                    fontSize: '0.7rem',
                    textTransform: 'uppercase',
                    fontWeight: 600,
                    padding: '0.1rem 0.4rem',
                    borderRadius: '4px',
                    backgroundColor: 'var(--bg-tertiary)',
                    color: 'var(--text-secondary)',
                    border: '1px solid var(--border-color)',
                  }}
                >
                  {item.os_type}
                </span>
                <span style={{ fontSize: '0.72rem', color: '#64748b' }}>
                  {item.source_types.slice(0, 2).join(', ')}
                </span>
              </div>
            </div>
          </div>
        ),
      },
      {
        key: 'status',
        header: 'Ingestion Status',
        render: (item) => renderStatusDot(item.status),
      },
      {
        key: 'events',
        header: 'Total Events Logged',
        render: (item) => (
          <span style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-primary)' }}>
            {item.total_events.toLocaleString()}
          </span>
        ),
      },
      {
        key: 'users',
        header: 'Active Users',
        render: (item) => (
          <div>
            <div style={{ fontSize: '0.8125rem', color: 'var(--text-primary)', fontWeight: 500 }}>
              {item.users_count} {item.users_count === 1 ? 'user' : 'users'}
            </div>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', maxWidth: '180px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              {item.users.slice(0, 3).join(', ')}
            </div>
          </div>
        ),
      },
      {
        key: 'incidents',
        header: 'Incidents Active',
        render: (item) => (
          <div>
            {item.incident_count > 0 ? (
              <span
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '0.3rem',
                  padding: '0.2rem 0.5rem',
                  borderRadius: '6px',
                  backgroundColor: 'rgba(239, 68, 68, 0.15)',
                  color: '#ef4444',
                  fontSize: '0.75rem',
                  fontWeight: 600,
                  border: '1px solid rgba(239, 68, 68, 0.3)',
                }}
              >
                <ShieldAlert size={12} />
                {item.incident_count}
              </span>
            ) : (
              <span style={{ fontSize: '0.75rem', color: '#64748b' }}>0 incidents</span>
            )}
          </div>
        ),
      },
      {
        key: 'risk_tier',
        header: 'Risk Tier',
        render: (item) => (
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <SeverityBadge severity={item.risk_tier as SeverityLevel} size="sm" />
            <span style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-primary)' }}>
              {item.risk_score}
            </span>
          </div>
        ),
      },
      {
        key: 'actions',
        header: 'Action',
        align: 'right',
        render: (item) => (
          <button
            onClick={(e) => {
              e.stopPropagation();
              setSelectedEntity({ type: 'host', identifier: item.hostname });
            }}
            style={{
              padding: '0.35rem 0.75rem',
              backgroundColor: 'var(--bg-tertiary)',
              color: 'var(--color-primary)',
              border: '1px solid var(--border-color)',
              borderRadius: '6px',
              fontSize: '0.75rem',
              fontWeight: 500,
              cursor: 'pointer',
              display: 'inline-flex',
              alignItems: 'center',
              gap: '0.3rem',
              transition: 'all 0.15s ease',
            }}
            onMouseEnter={(e) => {
              e.currentTarget.style.backgroundColor = 'var(--color-primary)';
              e.currentTarget.style.color = '#ffffff';
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.backgroundColor = 'var(--bg-tertiary)';
              e.currentTarget.style.color = 'var(--color-primary)';
            }}
          >
            Investigate
            <ExternalLink size={12} />
          </button>
        ),
      },
    ],
    []
  );

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem', width: '100%' }}>
      {/* --------------------------------------------------------------------- */}
      {/* Header Bar */}
      {/* --------------------------------------------------------------------- */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '1rem',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <div
            style={{
              width: '40px',
              height: '40px',
              borderRadius: '10px',
              backgroundColor: 'rgba(6, 182, 212, 0.15)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: '#06b6d4',
            }}
          >
            <Users size={22} />
          </div>
          <div>
            <h1 style={{ fontSize: '1.5rem', fontWeight: 600, color: 'var(--text-primary)', margin: 0 }}>
              Entity Explorer & Asset Intelligence
            </h1>
            <p style={{ margin: 0, fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
              Holistic profile tracking across user accounts, network IP entities, and monitored host endpoints.
            </p>
          </div>
        </div>

        <button
          onClick={() => fetchEntities()}
          disabled={refreshing || loading}
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '0.5rem',
            padding: '0.5rem 1rem',
            backgroundColor: 'var(--bg-tertiary)',
            color: 'var(--text-primary)',
            border: '1px solid var(--border-color)',
            borderRadius: '8px',
            fontSize: '0.8125rem',
            fontWeight: 500,
            cursor: 'pointer',
            transition: 'background-color 0.2s',
          }}
        >
          <RefreshCw size={14} className={refreshing ? 'animate-spin' : ''} />
          {refreshing ? 'Refreshing...' : 'Refresh Live'}
        </button>
      </div>

      {/* --------------------------------------------------------------------- */}
      {/* Top-Level KPI Summary Cards */}
      {/* --------------------------------------------------------------------- */}
      {data && (
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
            gap: '1rem',
          }}
        >
          <StatCard
            title="Total Tracked Entities"
            value={data.summary.total_entities}
            icon={<Layers size={20} />}
            iconColor="#38bdf8"
          />
          <StatCard
            title="High / Critical Risk"
            value={data.summary.high_risk_entities}
            icon={<ShieldAlert size={20} />}
            iconColor="#ef4444"
          />
          <StatCard
            title="External / Threat IPs"
            value={data.summary.attack_ips}
            icon={<Globe size={20} />}
            iconColor="#f97316"
          />
          <StatCard
            title="Privileged Accounts"
            value={data.summary.privileged_accounts}
            icon={<Shield size={20} />}
            iconColor="#eab308"
          />
          <StatCard
            title="Monitored Hosts"
            value={data.summary.endpoint_hosts}
            icon={<Server size={20} />}
            iconColor="#a855f7"
          />
        </div>
      )}

      {/* --------------------------------------------------------------------- */}
      {/* Search & Risk Filter Toolbar */}
      {/* --------------------------------------------------------------------- */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '1rem',
          backgroundColor: 'var(--bg-surface)',
          padding: '0.75rem 1rem',
          borderRadius: '10px',
          border: '1px solid var(--border-color)',
        }}
      >
        {/* Search Input */}
        <div style={{ position: 'relative', flex: '1', minWidth: '240px', maxWidth: '420px' }}>
          <Search
            size={16}
            style={{ position: 'absolute', left: '12px', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }}
          />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search username, IP, host, or threat behavior..."
            style={{
              width: '100%',
              backgroundColor: 'var(--bg-input)',
              color: 'var(--text-primary)',
              border: '1px solid var(--border-input)',
              borderRadius: '6px',
              padding: '0.45rem 0.75rem 0.45rem 2.25rem',
              fontSize: '0.8125rem',
              outline: 'none',
            }}
          />
        </div>

        {/* Risk Tier Filter Pills */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', flexWrap: 'wrap' }}>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginRight: '0.2rem', display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
            <SlidersHorizontal size={13} />
            Risk Filter:
          </span>
          {(['all', 'critical', 'high', 'medium', 'low'] as RiskTierFilter[]).map((tier) => {
            const active = riskFilter === tier;
            return (
              <button
                key={tier}
                onClick={() => setRiskFilter(tier)}
                style={{
                  padding: '0.25rem 0.65rem',
                  borderRadius: '9999px',
                  fontSize: '0.72rem',
                  fontWeight: 600,
                  textTransform: 'uppercase',
                  border: active ? '1px solid var(--color-primary)' : '1px solid var(--border-color)',
                  backgroundColor: active ? 'var(--color-primary-bg)' : 'var(--bg-tertiary)',
                  color: active ? 'var(--color-primary)' : 'var(--text-secondary)',
                  cursor: 'pointer',
                  transition: 'all 0.15s ease',
                }}
              >
                {tier}
              </button>
            );
          })}
        </div>
      </div>

      {/* --------------------------------------------------------------------- */}
      {/* 3 Dedicated View Tabs */}
      {/* --------------------------------------------------------------------- */}
      <div style={{ display: 'flex', borderBottom: '1px solid var(--border-color)', gap: '0.5rem' }}>
        <button
          onClick={() => setActiveTab('users')}
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '0.5rem',
            padding: '0.75rem 1.25rem',
            background: 'none',
            border: 'none',
            borderBottom: activeTab === 'users' ? '2px solid var(--color-primary)' : '2px solid transparent',
            color: activeTab === 'users' ? 'var(--color-primary)' : 'var(--text-secondary)',
            fontSize: '0.875rem',
            fontWeight: 600,
            cursor: 'pointer',
          }}
        >
          <UserCheck size={16} />
          User Accounts (Identities)
          {data && (
            <span
              style={{
                padding: '0.1rem 0.45rem',
                borderRadius: '9999px',
                fontSize: '0.7rem',
                backgroundColor: activeTab === 'users' ? 'var(--color-primary-bg)' : 'var(--bg-tertiary)',
                color: activeTab === 'users' ? 'var(--color-primary)' : 'var(--text-secondary)',
              }}
            >
              {data.users.length}
            </span>
          )}
        </button>

        <button
          onClick={() => setActiveTab('ips')}
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '0.5rem',
            padding: '0.75rem 1.25rem',
            background: 'none',
            border: 'none',
            borderBottom: activeTab === 'ips' ? '2px solid var(--color-primary)' : '2px solid transparent',
            color: activeTab === 'ips' ? 'var(--color-primary)' : 'var(--text-secondary)',
            fontSize: '0.875rem',
            fontWeight: 600,
            cursor: 'pointer',
          }}
        >
          <Globe size={16} />
          Network IP Addresses
          {data && (
            <span
              style={{
                padding: '0.1rem 0.45rem',
                borderRadius: '9999px',
                fontSize: '0.7rem',
                backgroundColor: activeTab === 'ips' ? 'var(--color-primary-bg)' : 'var(--bg-tertiary)',
                color: activeTab === 'ips' ? 'var(--color-primary)' : 'var(--text-secondary)',
              }}
            >
              {data.ips.length}
            </span>
          )}
        </button>

        <button
          onClick={() => setActiveTab('hosts')}
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '0.5rem',
            padding: '0.75rem 1.25rem',
            background: 'none',
            border: 'none',
            borderBottom: activeTab === 'hosts' ? '2px solid var(--color-primary)' : '2px solid transparent',
            color: activeTab === 'hosts' ? 'var(--color-primary)' : 'var(--text-secondary)',
            fontSize: '0.875rem',
            fontWeight: 600,
            cursor: 'pointer',
          }}
        >
          <Server size={16} />
          Monitored Hosts & Endpoints
          {data && (
            <span
              style={{
                padding: '0.1rem 0.45rem',
                borderRadius: '9999px',
                fontSize: '0.7rem',
                backgroundColor: activeTab === 'hosts' ? 'var(--color-primary-bg)' : 'var(--bg-tertiary)',
                color: activeTab === 'hosts' ? 'var(--color-primary)' : 'var(--text-secondary)',
              }}
            >
              {data.hosts.length}
            </span>
          )}
        </button>
      </div>

      {/* --------------------------------------------------------------------- */}
      {/* Tab Content Display */}
      {/* --------------------------------------------------------------------- */}
      {loading ? (
        <LoadingState message="Aggregating entity metrics from SQLite database..." />
      ) : error ? (
        <ErrorState title="Error Loading Entities" message={error} onRetry={() => fetchEntities()} />
      ) : data ? (
        <div>
          {activeTab === 'users' && (
            <DataTable
              columns={userColumns}
              data={data.users}
              keyExtractor={(u) => u.username}
              onRowClick={(u) => setSelectedEntity({ type: 'user', identifier: u.username })}
              emptyMessage="No user identities match the selected filters."
            />
          )}

          {activeTab === 'ips' && (
            <DataTable
              columns={ipColumns}
              data={data.ips}
              keyExtractor={(item) => item.ip}
              onRowClick={(item) => setSelectedEntity({ type: 'ip', identifier: item.ip })}
              emptyMessage="No IP addresses match the selected filters."
            />
          )}

          {activeTab === 'hosts' && (
            <DataTable
              columns={hostColumns}
              data={data.hosts}
              keyExtractor={(h) => h.hostname}
              onRowClick={(h) => setSelectedEntity({ type: 'host', identifier: h.hostname })}
              emptyMessage="No monitored hosts match the selected filters."
            />
          )}
        </div>
      ) : null}

      {/* --------------------------------------------------------------------- */}
      {/* Entity Forensic Profile Drawer / Modal */}
      {/* --------------------------------------------------------------------- */}
      {selectedEntity && (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            backgroundColor: 'rgba(0, 0, 0, 0.75)',
            zIndex: 1000,
            display: 'flex',
            justifyContent: 'flex-end',
            backdropFilter: 'blur(3px)',
          }}
          onClick={() => setSelectedEntity(null)}
        >
          <div
            style={{
              width: '100%',
              maxWidth: '680px',
              height: '100%',
              backgroundColor: 'var(--bg-elevated)',
              borderLeft: '1px solid var(--border-color)',
              boxShadow: 'var(--shadow-xl)',
              overflowY: 'auto',
              padding: '1.75rem',
              display: 'flex',
              flexDirection: 'column',
              gap: '1.5rem',
            }}
            onClick={(e) => e.stopPropagation()}
          >
            {/* Drawer Header */}
            <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.25rem' }}>
                  <span
                    style={{
                      textTransform: 'uppercase',
                      fontSize: '0.7rem',
                      fontWeight: 700,
                      color: 'var(--color-primary)',
                      letterSpacing: '0.05em',
                    }}
                  >
                    Forensic Profile: {selectedEntity.type}
                  </span>
                </div>
                <h2 style={{ fontSize: '1.4rem', fontWeight: 700, color: 'var(--text-primary)', margin: 0, fontFamily: 'monospace' }}>
                  {selectedEntity.identifier}
                </h2>
              </div>
              <button
                onClick={() => setSelectedEntity(null)}
                style={{
                  padding: '0.4rem',
                  backgroundColor: 'var(--bg-tertiary)',
                  border: '1px solid var(--border-color)',
                  borderRadius: '6px',
                  color: 'var(--text-secondary)',
                  cursor: 'pointer',
                }}
              >
                <X size={18} />
              </button>
            </div>

            {/* Success Message Banner */}
            {actionSuccessMessage && (
              <div
                style={{
                  padding: '0.75rem 1rem',
                  backgroundColor: 'rgba(16, 185, 129, 0.15)',
                  border: '1px solid rgba(16, 185, 129, 0.4)',
                  borderRadius: '8px',
                  color: '#10b981',
                  fontSize: '0.8125rem',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.5rem',
                }}
              >
                <CheckCircle size={16} />
                {actionSuccessMessage}
              </div>
            )}

            {detailLoading ? (
              <LoadingState message="Loading deep forensic telemetry and mini-event stream..." />
            ) : detailError ? (
              <ErrorState title="Error Loading Detail" message={detailError} />
            ) : entityDetail ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
                {/* Metrics Highlights Bar */}
                <div
                  style={{
                    display: 'grid',
                    gridTemplateColumns: 'repeat(3, 1fr)',
                    gap: '0.75rem',
                    backgroundColor: 'var(--bg-tertiary)',
                    padding: '1rem',
                    borderRadius: '8px',
                    border: '1px solid rgba(255, 255, 255, 0.06)',
                  }}
                >
                  <div>
                    <div style={{ fontSize: '0.7rem', color: '#94a3b8', textTransform: 'uppercase' }}>Recent Events</div>
                    <div style={{ fontSize: '1.25rem', fontWeight: 700, color: '#38bdf8' }}>
                      {entityDetail.metrics.event_count}
                    </div>
                  </div>
                  <div>
                    <div style={{ fontSize: '0.7rem', color: '#94a3b8', textTransform: 'uppercase' }}>Correlated Incidents</div>
                    <div style={{ fontSize: '1.25rem', fontWeight: 700, color: entityDetail.incidents.length > 0 ? '#ef4444' : '#10b981' }}>
                      {entityDetail.incidents.length}
                    </div>
                  </div>
                  <div>
                    <div style={{ fontSize: '0.7rem', color: '#94a3b8', textTransform: 'uppercase' }}>Response Actions</div>
                    <div style={{ fontSize: '1.25rem', fontWeight: 700, color: '#f59e0b' }}>
                      {entityDetail.actions.length}
                    </div>
                  </div>
                </div>

                {/* 1-Click Containment / Response Action Staging */}
                {entityDetail.recommended_actions.length > 0 && (
                  <div
                    style={{
                      backgroundColor: 'var(--bg-surface)',
                      border: '1px solid rgba(239, 68, 68, 0.3)',
                      borderRadius: '8px',
                      padding: '1rem',
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', color: '#ef4444', fontWeight: 600, fontSize: '0.875rem', marginBottom: '0.5rem' }}>
                      <Ban size={16} />
                      Response Engine Containment Actions
                    </div>
                    <p style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', margin: '0 0 0.75rem 0' }}>
                      Stage protective containment action directly to the Response Console with safety checks and rollback capability.
                    </p>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                      {entityDetail.recommended_actions.map((rec, idx) => (
                        <div
                          key={idx}
                          style={{
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'space-between',
                            backgroundColor: 'var(--bg-tertiary)',
                            padding: '0.65rem 0.85rem',
                            borderRadius: '6px',
                            border: '1px solid var(--border-color)',
                          }}
                        >
                          <div>
                            <div style={{ fontWeight: 600, color: 'var(--text-primary)', fontSize: '0.8125rem', fontFamily: 'monospace' }}>
                              {rec.action_type.toUpperCase()}
                            </div>
                            <div style={{ fontSize: '0.72rem', color: 'var(--text-secondary)' }}>{rec.reason}</div>
                          </div>
                          <button
                            onClick={() => handleStageAction(rec)}
                            disabled={stagingAction}
                            style={{
                              padding: '0.4rem 0.8rem',
                              backgroundColor: '#dc2626',
                              color: '#ffffff',
                              border: 'none',
                              borderRadius: '6px',
                              fontSize: '0.75rem',
                              fontWeight: 600,
                              cursor: 'pointer',
                              display: 'inline-flex',
                              alignItems: 'center',
                              gap: '0.35rem',
                            }}
                          >
                            <Ban size={12} />
                            Stage Action
                          </button>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Correlated Incidents Section */}
                <div>
                  <h3 style={{ fontSize: '0.95rem', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '0.75rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    <ShieldAlert size={16} color="#ef4444" />
                    Correlated Security Incidents ({entityDetail.incidents.length})
                  </h3>
                  {entityDetail.incidents.length === 0 ? (
                    <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', fontStyle: 'italic', padding: '0.75rem', backgroundColor: 'var(--bg-surface)', border: '1px solid var(--border-color)', borderRadius: '6px' }}>
                      No open incidents directly linked to this entity.
                    </div>
                  ) : (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                      {entityDetail.incidents.map((inc) => (
                        <div
                          key={inc.incident_id}
                          style={{
                            backgroundColor: 'var(--bg-surface)',
                            padding: '0.75rem 1rem',
                            borderRadius: '8px',
                            border: '1px solid var(--border-color)',
                          }}
                        >
                          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.25rem' }}>
                            <span style={{ fontFamily: 'monospace', fontSize: '0.75rem', color: '#0284c7' }}>
                              {inc.incident_id}
                            </span>
                            <SeverityBadge severity={inc.severity.toLowerCase() as SeverityLevel} size="sm" />
                          </div>
                          <div style={{ fontSize: '0.8125rem', fontWeight: 600, color: 'var(--text-primary)' }}>
                            {inc.title}
                          </div>
                          <div style={{ fontSize: '0.7rem', color: 'var(--text-secondary)', marginTop: '0.25rem' }}>
                            Risk Score: {inc.risk_score} | Status: {inc.status} | Created: {inc.created_at}
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                {/* Recent Raw Evidence Stream */}
                <div>
                  <h3 style={{ fontSize: '0.95rem', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '0.75rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    <Activity size={16} color="#0284c7" />
                    Recent Forensic Evidence Stream ({entityDetail.recent_events.length} events)
                  </h3>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', maxHeight: '380px', overflowY: 'auto' }}>
                    {entityDetail.recent_events.map((ev) => (
                      <div
                        key={ev.event_id}
                        style={{
                          backgroundColor: 'var(--bg-surface)',
                          padding: '0.65rem 0.85rem',
                          borderRadius: '6px',
                          border: '1px solid var(--border-color)',
                          fontSize: '0.75rem',
                        }}
                      >
                        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.2rem' }}>
                          <span style={{ color: '#38bdf8', fontWeight: 600 }}>{ev.event_type}</span>
                          <span style={{ color: '#64748b', fontSize: '0.7rem' }}>{ev.timestamp}</span>
                        </div>
                        <div style={{ color: 'var(--text-secondary)', fontFamily: 'monospace', fontSize: '0.72rem', wordBreak: 'break-all' }}>
                          {ev.raw_event}
                        </div>
                        <div style={{ display: 'flex', gap: '0.75rem', marginTop: '0.3rem', color: '#94a3b8', fontSize: '0.68rem' }}>
                          <span>Host: <strong>{ev.source_host}</strong></span>
                          {ev.source_ip && <span>IP: <strong>{ev.source_ip}</strong></span>}
                          {ev.username && <span>User: <strong>{ev.username}</strong></span>}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            ) : null}
          </div>
        </div>
      )}
    </div>
  );
};
