import React, { useState } from 'react';
import {
  Incident,
  IncidentStatus,
  Severity
} from '../types';
import {
  AlertCircle,
  Clock,
  User,
  Globe,
  Server,
  Sparkles,
  Eye,
  Filter,
  CheckCircle2,
  AlertTriangle,
  Flame,
  ShieldCheck,
  ChevronRight
} from 'lucide-react';

interface IncidentQueueProps {
  incidents: Incident[];
  onSelectIncident: (incident: Incident) => void;
  onLaunchAI: (incidentId: string) => void;
  onUpdateStatus: (incidentId: string, status: IncidentStatus) => Promise<void>;
  loading: boolean;
}

export const IncidentQueue: React.FC<IncidentQueueProps> = ({
  incidents,
  onSelectIncident,
  onLaunchAI,
  onUpdateStatus,
  loading,
}) => {
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [updatingId, setUpdatingId] = useState<string | null>(null);

  // Filter incidents locally
  const filteredIncidents = incidents.filter((inc) => {
    if (statusFilter !== 'ALL' && inc.status !== statusFilter) return false;
    if (severityFilter !== 'ALL' && inc.severity.toLowerCase() !== severityFilter.toLowerCase()) return false;
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const matchTitle = inc.title.toLowerCase().includes(q);
      const matchId = inc.incident_id.toLowerCase().includes(q);
      const matchEntities =
        inc.entities.source_ips.some((ip) => ip.toLowerCase().includes(q)) ||
        inc.entities.usernames.some((u) => u.toLowerCase().includes(q)) ||
        inc.entities.hosts.some((h) => h.toLowerCase().includes(q));
      if (!matchTitle && !matchId && !matchEntities) return false;
    }
    return true;
  });

  const handleStatusChange = async (
    e: React.ChangeEvent<HTMLSelectElement>,
    incidentId: string
  ) => {
    e.stopPropagation();
    const newStatus = e.target.value as IncidentStatus;
    try {
      setUpdatingId(incidentId);
      await onUpdateStatus(incidentId, newStatus);
    } finally {
      setUpdatingId(null);
    }
  };

  const getSeverityBadgeClass = (severity: Severity) => {
    switch (severity.toLowerCase()) {
      case 'critical':
        return 'badge-critical';
      case 'high':
        return 'badge-high';
      case 'medium':
        return 'badge-medium';
      case 'low':
      default:
        return 'badge-low';
    }
  };

  const getStatusBadgeClass = (status: IncidentStatus) => {
    switch (status) {
      case 'NEW':
        return 'badge-critical';
      case 'INVESTIGATING':
        return 'badge-high';
      case 'RESOLVED':
        return 'badge-success';
      case 'CLOSED':
        return 'badge-neutral';
      default:
        return 'badge-neutral';
    }
  };

  const getRiskColor = (score: number) => {
    if (score >= 80) return '#f43f5e';
    if (score >= 60) return '#f97316';
    if (score >= 40) return '#eab308';
    return '#06b6d4';
  };

  const formatTimestamp = (iso: string) => {
    try {
      const d = new Date(iso);
      return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) +
        ' ' + d.toLocaleDateString([], { month: 'short', day: 'numeric' });
    } catch {
      return iso;
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      {/* Triage & Filter Bar */}
      <div className="soc-card" style={{ padding: '1rem 1.25rem' }}>
        <div style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '1rem'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', flex: 1, minWidth: '320px' }}>
            <div style={{ position: 'relative', width: '100%', maxWidth: '400px' }}>
              <input
                type="text"
                placeholder="Filter by title, ID, IP (e.g. 192.168.1.50), user, host..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                style={{ width: '100%', paddingLeft: '2.25rem' }}
              />
              <Filter
                size={16}
                color="#64748b"
                style={{ position: 'absolute', left: '0.75rem', top: '50%', transform: 'translateY(-50%)' }}
              />
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <label style={{ fontSize: '0.8rem', color: '#94a3b8', whiteSpace: 'nowrap' }}>Status:</label>
              <select
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
                style={{ cursor: 'pointer' }}
              >
                <option value="ALL">All Statuses</option>
                <option value="NEW">NEW</option>
                <option value="INVESTIGATING">INVESTIGATING</option>
                <option value="RESOLVED">RESOLVED</option>
                <option value="CLOSED">CLOSED</option>
              </select>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <label style={{ fontSize: '0.8rem', color: '#94a3b8', whiteSpace: 'nowrap' }}>Severity:</label>
              <select
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value)}
                style={{ cursor: 'pointer' }}
              >
                <option value="ALL">All Severities</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
            </div>
          </div>

          <div style={{ fontSize: '0.85rem', color: '#94a3b8' }}>
            Showing <strong>{filteredIncidents.length}</strong> of <strong>{incidents.length}</strong> Correlated Incidents
          </div>
        </div>
      </div>

      {/* Incident List */}
      {filteredIncidents.length === 0 ? (
        <div className="soc-card" style={{ padding: '3.5rem 2rem', textAlign: 'center' }}>
          <ShieldCheck size={48} color="#10b981" style={{ margin: '0 auto 1rem' }} />
          <h3 style={{ fontSize: '1.25rem', marginBottom: '0.5rem', color: '#f8fafc' }}>
            No Incidents Match Active Filters
          </h3>
          <p style={{ color: '#94a3b8', maxWidth: '500px', margin: '0 auto' }}>
            Zero incidents in this view. As the ingestion pipeline and correlation engine process alerts, correlated security incidents will appear here for analyst triage.
          </p>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.875rem' }}>
          {filteredIncidents.map((incident) => {
            const riskColor = getRiskColor(incident.risk_score);
            return (
              <div
                key={incident.incident_id}
                className="soc-card"
                onClick={() => onSelectIncident(incident)}
                style={{
                  padding: '1.15rem 1.35rem',
                  cursor: 'pointer',
                  transition: 'border-color 0.15s, transform 0.15s',
                  borderLeft: `4px solid ${riskColor}`,
                }}
                onMouseEnter={(e) => (e.currentTarget.style.borderColor = '#475569')}
                onMouseLeave={(e) => (e.currentTarget.style.borderColor = 'var(--border-color)')}
              >
                <div style={{
                  display: 'flex',
                  alignItems: 'flex-start',
                  justifyContent: 'space-between',
                  gap: '1rem',
                  marginBottom: '0.85rem'
                }}>
                  <div style={{ flex: 1 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '0.35rem' }}>
                      <span className={`badge ${getSeverityBadgeClass(incident.severity)}`}>
                        {incident.severity}
                      </span>
                      <span className="font-mono" style={{ fontSize: '0.8rem', color: '#94a3b8' }}>
                        {incident.incident_id}
                      </span>
                      <span style={{ fontSize: '0.75rem', color: '#64748b' }}>•</span>
                      <span style={{ fontSize: '0.75rem', color: '#94a3b8', display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
                        <Clock size={13} />
                        First: {formatTimestamp(incident.first_seen)}
                      </span>
                      <span style={{ fontSize: '0.75rem', color: '#64748b' }}>•</span>
                      <span style={{ fontSize: '0.75rem', color: '#94a3b8' }}>
                        Last: {formatTimestamp(incident.last_seen)}
                      </span>
                    </div>

                    <h4 style={{ fontSize: '1.05rem', fontWeight: 600, color: '#f8fafc', marginBottom: '0.4rem' }}>
                      {incident.title}
                    </h4>

                    {/* Entities pill row */}
                    <div style={{ display: 'flex', alignItems: 'center', flexWrap: 'wrap', gap: '0.6rem', marginTop: '0.5rem' }}>
                      {incident.entities.source_ips.map((ip) => (
                        <span
                          key={ip}
                          className="font-mono"
                          style={{
                            background: '#1e293b',
                            border: '1px solid #334155',
                            padding: '0.15rem 0.5rem',
                            borderRadius: '4px',
                            fontSize: '0.75rem',
                            color: '#38bdf8',
                            display: 'inline-flex',
                            alignItems: 'center',
                            gap: '0.3rem'
                          }}
                        >
                          <Globe size={11} />
                          {ip}
                        </span>
                      ))}

                      {incident.entities.usernames.map((user) => (
                        <span
                          key={user}
                          className="font-mono"
                          style={{
                            background: '#1e293b',
                            border: '1px solid #334155',
                            padding: '0.15rem 0.5rem',
                            borderRadius: '4px',
                            fontSize: '0.75rem',
                            color: '#fbbf24',
                            display: 'inline-flex',
                            alignItems: 'center',
                            gap: '0.3rem'
                          }}
                        >
                          <User size={11} />
                          {user}
                        </span>
                      ))}

                      {incident.entities.hosts.map((host) => (
                        <span
                          key={host}
                          className="font-mono"
                          style={{
                            background: '#1e293b',
                            border: '1px solid #334155',
                            padding: '0.15rem 0.5rem',
                            borderRadius: '4px',
                            fontSize: '0.75rem',
                            color: '#a78bfa',
                            display: 'inline-flex',
                            alignItems: 'center',
                            gap: '0.3rem'
                          }}
                        >
                          <Server size={11} />
                          {host}
                        </span>
                      ))}

                      {incident.distinct_rules.map((rule) => (
                        <span
                          key={rule}
                          className="font-mono"
                          style={{
                            background: 'rgba(239, 68, 68, 0.1)',
                            border: '1px solid rgba(239, 68, 68, 0.3)',
                            padding: '0.15rem 0.5rem',
                            borderRadius: '4px',
                            fontSize: '0.72rem',
                            color: '#f87171',
                          }}
                        >
                          {rule}
                        </span>
                      ))}
                    </div>
                  </div>

                  {/* Right Column: Risk Score & Action Buttons */}
                  <div style={{
                    display: 'flex',
                    flexDirection: 'column',
                    alignItems: 'flex-end',
                    gap: '0.75rem',
                    minWidth: '220px'
                  }}>
                    {/* Status Select & Risk Score */}
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', width: '100%', justifyContent: 'flex-end' }}>
                      <div style={{ textAlign: 'right' }}>
                        <div style={{ fontSize: '0.75rem', color: '#94a3b8' }}>Risk Score</div>
                        <div style={{ fontSize: '1.15rem', fontWeight: 700, color: riskColor, display: 'flex', alignItems: 'center', gap: '0.25rem', justifyContent: 'flex-end' }}>
                          <Flame size={16} />
                          {incident.risk_score} <span style={{ fontSize: '0.75rem', color: '#64748b' }}>/ 100</span>
                        </div>
                      </div>

                      {/* Status Dropdown */}
                      <div onClick={(e) => e.stopPropagation()}>
                        <select
                          value={incident.status}
                          onChange={(e) => handleStatusChange(e, incident.incident_id)}
                          disabled={updatingId === incident.incident_id}
                          className={`badge ${getStatusBadgeClass(incident.status)}`}
                          style={{
                            cursor: 'pointer',
                            fontSize: '0.75rem',
                            padding: '0.25rem 0.5rem',
                            borderRadius: '6px'
                          }}
                        >
                          <option value="NEW">NEW</option>
                          <option value="INVESTIGATING">INVESTIGATING</option>
                          <option value="RESOLVED">RESOLVED</option>
                          <option value="CLOSED">CLOSED</option>
                        </select>
                      </div>
                    </div>

                    {/* Progress Bar */}
                    <div style={{ width: '100%' }}>
                      <div className="risk-meter">
                        <div
                          className="risk-meter-fill"
                          style={{
                            width: `${Math.min(incident.risk_score, 100)}%`,
                            backgroundColor: riskColor
                          }}
                        />
                      </div>
                    </div>

                    {/* Action Buttons */}
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginTop: '0.25rem' }}>
                      <button
                        className="btn btn-ai btn-sm"
                        onClick={(e) => {
                          e.stopPropagation();
                          onLaunchAI(incident.incident_id);
                        }}
                        title="Generate evidence-grounded AI investigation report"
                      >
                        <Sparkles size={13} />
                        Investigate with AI
                      </button>

                      <button
                        className="btn btn-secondary btn-sm"
                        onClick={(e) => {
                          e.stopPropagation();
                          onSelectIncident(incident);
                        }}
                      >
                        <Eye size={13} />
                        Timeline & Notes
                      </button>
                    </div>
                  </div>
                </div>

                {/* Sub-footer stats */}
                <div style={{
                  borderTop: '1px solid #1e293b',
                  paddingTop: '0.65rem',
                  marginTop: '0.65rem',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  fontSize: '0.75rem',
                  color: '#64748b'
                }}>
                  <div style={{ display: 'flex', gap: '1rem' }}>
                    <span>Correlated Alerts: <strong style={{ color: '#e2e8f0' }}>{incident.related_alert_ids.length}</strong></span>
                    <span>Correlated Events: <strong style={{ color: '#e2e8f0' }}>{incident.related_event_ids.length}</strong></span>
                    <span>Analyst Notes: <strong style={{ color: '#e2e8f0' }}>{incident.analyst_notes?.length || 0}</strong></span>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.25rem', color: '#94a3b8' }}>
                    <span>View full dossier</span>
                    <ChevronRight size={14} />
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};
