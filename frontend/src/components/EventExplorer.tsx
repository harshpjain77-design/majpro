import React, { useState, useEffect } from 'react';
import {
  SecurityEvent,
  EventExplanation
} from '../types';
import { api } from '../services/api';
import {
  Search,
  Filter,
  Eye,
  Sparkles,
  RefreshCw,
  X,
  FileCode,
  ShieldAlert,
  ChevronLeft,
  ChevronRight,
  Copy,
  Check,
  Globe,
  User,
  Server,
  ArrowUpDown,
  ArrowUp,
  ArrowDown
} from 'lucide-react';

interface EventExplorerProps {
  initialEventId?: string | null;
  onClearInitialEvent?: () => void;
}

export const EventExplorer: React.FC<EventExplorerProps> = ({
  initialEventId,
  onClearInitialEvent,
}) => {
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [total, setTotal] = useState<number>(0);
  const [loading, setLoading] = useState<boolean>(false);
  const [page, setPage] = useState<number>(0);
  const pageSize = 20;

  // Search filters
  const [query, setQuery] = useState('');
  const [sourceIp, setSourceIp] = useState('');
  const [username, setUsername] = useState('');
  const [sourceHost, setSourceHost] = useState('');
  const [eventType, setEventType] = useState('');
  const [severity, setSeverity] = useState('ALL');

  // Sorting
  const [sortBy, setSortBy] = useState<'timestamp' | 'ingested_at' | 'source_ip' | 'severity' | 'source_host'>('ingested_at');
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('desc');

  // Discovered hosts and counts
  const [hostCounts, setHostCounts] = useState<Record<string, number>>({});

  // Selected event modal / inspection
  const [selectedEvent, setSelectedEvent] = useState<SecurityEvent | null>(null);
  const [rawEventText, setRawEventText] = useState<string | null>(null);
  const [explaining, setExplaining] = useState<boolean>(false);
  const [aiExplanation, setAiExplanation] = useState<EventExplanation | null>(null);
  const [copied, setCopied] = useState<boolean>(false);

  const fetchSummaryCounts = async () => {
    try {
      const summary = await api.getEventSummaryCounts();
      if (summary && summary.by_source_host) {
        setHostCounts(summary.by_source_host);
      }
    } catch (err) {
      console.warn('Failed to load host summary counts:', err);
    }
  };

  const fetchEvents = async (silent: boolean = false) => {
    try {
      if (!silent) setLoading(true);
      const res = await api.searchEvents({
        query: query.trim() || undefined,
        source_ip: sourceIp.trim() || undefined,
        username: username.trim() || undefined,
        source_host: sourceHost.trim() || undefined,
        event_type: eventType.trim() || undefined,
        severity: severity !== 'ALL' ? severity : undefined,
        sort_by: sortBy,
        sort_dir: sortDir,
        limit: pageSize,
        offset: page * pageSize,
      });
      setEvents(res.events || []);
      setTotal(res.total || 0);
    } catch (err) {
      console.error('Failed to search events:', err);
    } finally {
      if (!silent) setLoading(false);
    }
  };

  const handleToggleSort = (field: 'timestamp' | 'ingested_at' | 'source_ip' | 'severity' | 'source_host') => {
    if (sortBy === field) {
      setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'));
    } else {
      setSortBy(field);
      setSortDir(field === 'timestamp' || field === 'ingested_at' || field === 'severity' ? 'desc' : 'asc');
    }
    setPage(0);
  };

  useEffect(() => {
    fetchEvents(false);
    fetchSummaryCounts();
    const interval = setInterval(() => {
      fetchEvents(true);
      fetchSummaryCounts();
    }, 2000);
    return () => clearInterval(interval);
  }, [page, severity, query, sourceIp, username, sourceHost, eventType, sortBy, sortDir]);

  // When initialEventId is provided, look it up directly
  useEffect(() => {
    if (initialEventId) {
      api.getEventById(initialEventId).then((evt) => {
        if (evt) handleInspectEvent(evt);
      }).catch((err) => console.error(err));
    }
  }, [initialEventId]);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setPage(0);
    fetchEvents();
  };

  const handleInspectEvent = async (evt: SecurityEvent) => {
    setSelectedEvent(evt);
    setRawEventText(evt.raw_event || null);
    setAiExplanation(null);
  };

  const handleExplainWithAI = async () => {
    if (!selectedEvent) return;
    try {
      setExplaining(true);
      const expl = await api.explainEventWithAI(selectedEvent.event_id);
      setAiExplanation(expl);
    } catch (err) {
      console.error('Failed to explain event with AI:', err);
    } finally {
      setExplaining(false);
    }
  };

  const handleCopyRaw = () => {
    if (selectedEvent?.raw_event) {
      navigator.clipboard.writeText(selectedEvent.raw_event);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
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

  const getSeverityBadgeClass = (sev: string) => {
    switch (sev.toLowerCase()) {
      case 'critical':
        return 'badge-critical';
      case 'high':
        return 'badge-high';
      case 'medium':
        return 'badge-medium';
      default:
        return 'badge-low';
    }
  };

  const totalPages = Math.ceil(total / pageSize);

  const discoveredHosts = Object.keys(hostCounts);
  const eventHosts = events.map((e) => e.source_host).filter(Boolean) as string[];
  const allHosts = Array.from(new Set([...discoveredHosts, ...eventHosts, 'WIN-SOGAJGVF31Q', 'Harsh'])).sort();

  const getDeviceDisplayName = (h: string) => {
    if (h.toUpperCase().includes('SOGAJ') || h.toLowerCase().includes('2012')) {
      return `${h} (Windows Server 2012 VM)`;
    }
    if (h.toLowerCase() === 'harsh') {
      return `${h} (Host SIEM Machine)`;
    }
    return h;
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      {/* Search & Filter Header */}
      <div className="soc-card" style={{ padding: '1.25rem' }}>
        <form onSubmit={handleSearchSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap', alignItems: 'center' }}>
            <div style={{ flex: 2, minWidth: '220px', position: 'relative' }}>
              <input
                type="text"
                placeholder="Full-text search in raw log or canonical fields..."
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                style={{ width: '100%', paddingLeft: '2.25rem' }}
              />
              <Search size={16} color="#64748b" style={{ position: 'absolute', left: '0.75rem', top: '50%', transform: 'translateY(-50%)' }} />
            </div>

            {/* Source IP Filter */}
            <input
              type="text"
              placeholder="Source IP (e.g. 192.168.203.10)"
              value={sourceIp}
              onChange={(e) => setSourceIp(e.target.value)}
              style={{ flex: 1, minWidth: '140px' }}
            />

            {/* Device / Host Selection Dropdown */}
            <select
              value={sourceHost}
              onChange={(e) => {
                setSourceHost(e.target.value);
                setPage(0);
              }}
              style={{
                flex: 1,
                minWidth: '200px',
                cursor: 'pointer',
                background: sourceHost ? '#1e1b4b' : '#0f172a',
                borderColor: sourceHost ? '#6366f1' : '#334155',
                color: sourceHost ? '#a5b4fc' : '#f8fafc',
                fontWeight: sourceHost ? 600 : 'normal'
              }}
            >
              <option value="">🖥️ All Devices / Telemetry Sources</option>
              {allHosts.map((h) => (
                <option key={h} value={h}>
                  🖥️ {getDeviceDisplayName(h)} {hostCounts[h] !== undefined ? `(${hostCounts[h]} logs)` : ''}
                </option>
              ))}
            </select>

            {/* Username Filter */}
            <input
              type="text"
              placeholder="Username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              style={{ flex: 1, minWidth: '120px' }}
            />

            {/* Severity Filter */}
            <select
              value={severity}
              onChange={(e) => {
                setSeverity(e.target.value);
                setPage(0);
              }}
              style={{ cursor: 'pointer', minWidth: '130px' }}
            >
              <option value="ALL">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>

            {/* Sort Control Dropdown */}
            <select
              value={`${sortBy}-${sortDir}`}
              onChange={(e) => {
                const parts = e.target.value.split('-');
                setSortBy(parts[0] as any);
                setSortDir(parts[1] as any);
                setPage(0);
              }}
              style={{
                cursor: 'pointer',
                minWidth: '180px',
                background: '#0f172a',
                borderColor: '#10b981',
                color: '#34d399',
                fontWeight: 600
              }}
              title="Select sorting field and direction"
            >
              <option value="ingested_at-desc">⚡ Real-Time Received (Newest Ingested ↓)</option>
              <option value="timestamp-desc">⏱️ Event Timestamp (Newest Event ↓)</option>
              <option value="timestamp-asc">⏱️ Event Timestamp (Oldest Event ↑)</option>
              <option value="source_ip-asc">🌐 Source IP (Ascending)</option>
              <option value="source_ip-desc">🌐 Source IP (Descending)</option>
              <option value="severity-desc">⚠️ Severity (High→Low)</option>
              <option value="source_host-asc">🖥️ Device Name (A→Z)</option>
            </select>

            <button type="submit" className="btn btn-primary" disabled={loading}>
              <Search size={14} />
              Filter
            </button>

            {(query || sourceIp || username || sourceHost || severity !== 'ALL') && (
              <button
                type="button"
                className="btn btn-secondary"
                onClick={() => {
                  setQuery('');
                  setSourceIp('');
                  setUsername('');
                  setSourceHost('');
                  setSeverity('ALL');
                  setPage(0);
                }}
                title="Clear all active filters"
              >
                <X size={14} />
                Clear
              </button>
            )}
          </div>
        </form>

        <div style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          marginTop: '0.85rem',
          fontSize: '0.8rem',
          color: '#94a3b8',
          flexWrap: 'wrap',
          gap: '0.5rem'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', flexWrap: 'wrap' }}>
            <div>
              Found <strong>{total}</strong> indexed events (Page {page + 1} of {Math.max(totalPages, 1)})
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', color: '#10b981', fontSize: '0.75rem', fontWeight: 500 }}>
              <span style={{ display: 'inline-block', width: '8px', height: '8px', borderRadius: '50%', backgroundColor: '#10b981' }}></span>
              Live Auto-Refresh (3s)
            </div>
            {sourceHost && (
              <div style={{
                display: 'flex',
                alignItems: 'center',
                gap: '0.35rem',
                color: '#a78bfa',
                background: '#1e1b4b',
                padding: '0.15rem 0.5rem',
                borderRadius: '4px',
                border: '1px solid #6366f1'
              }}>
                <span>Filtered: <strong>{sourceHost}</strong></span>
                <button
                  type="button"
                  onClick={() => { setSourceHost(''); setPage(0); }}
                  style={{ background: 'none', border: 'none', color: '#a78bfa', cursor: 'pointer', padding: 0 }}
                  title="Remove device filter"
                >
                  <X size={12} />
                </button>
              </div>
            )}
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <button
              type="button"
              onClick={() => { fetchEvents(); fetchSummaryCounts(); }}
              disabled={loading}
              className="btn btn-secondary btn-sm"
              title="Refresh events immediately"
            >
              <RefreshCw size={13} />
              Refresh
            </button>
            <button
              onClick={() => setPage((p) => Math.max(p - 1, 0))}
              disabled={page === 0 || loading}
              className="btn btn-secondary btn-sm"
            >
              <ChevronLeft size={14} />
              Prev
            </button>
            <button
              onClick={() => setPage((p) => (p + 1 < totalPages ? p + 1 : p))}
              disabled={page + 1 >= totalPages || loading}
              className="btn btn-secondary btn-sm"
            >
              Next
              <ChevronRight size={14} />
            </button>
          </div>
        </div>
      </div>

      {/* Events Table */}
      <div className="soc-card" style={{ overflow: 'hidden' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.85rem' }}>
          <thead>
            <tr style={{ background: '#0f172a', borderBottom: '1px solid #1e293b', color: '#94a3b8' }}>
              <th
                onClick={() => handleToggleSort('ingested_at')}
                style={{ padding: '0.75rem 1rem', cursor: 'pointer', userSelect: 'none' }}
                title="Click to sort by Ingested Time (Real-Time)"
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
                  <span>Received / Log Time</span>
                  {sortBy === 'ingested_at' || sortBy === 'timestamp' ? (
                    sortDir === 'asc' ? <ArrowUp size={12} color="#10b981" /> : <ArrowDown size={12} color="#10b981" />
                  ) : (
                    <ArrowUpDown size={12} color="#475569" />
                  )}
                </div>
              </th>
              <th style={{ padding: '0.75rem 1rem' }}>Event Type</th>
              <th
                onClick={() => handleToggleSort('source_host')}
                style={{ padding: '0.75rem 1rem', cursor: 'pointer', userSelect: 'none' }}
                title="Click to sort by Device / Host"
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
                  <span>Host / Device</span>
                  {sortBy === 'source_host' ? (
                    sortDir === 'asc' ? <ArrowUp size={12} color="#38bdf8" /> : <ArrowDown size={12} color="#38bdf8" />
                  ) : (
                    <ArrowUpDown size={12} color="#475569" />
                  )}
                </div>
              </th>
              <th style={{ padding: '0.75rem 1rem' }}>User</th>
              <th
                onClick={() => handleToggleSort('source_ip')}
                style={{ padding: '0.75rem 1rem', cursor: 'pointer', userSelect: 'none' }}
                title="Click to sort by Source IP"
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
                  <span>Source IP</span>
                  {sortBy === 'source_ip' ? (
                    sortDir === 'asc' ? <ArrowUp size={12} color="#38bdf8" /> : <ArrowDown size={12} color="#38bdf8" />
                  ) : (
                    <ArrowUpDown size={12} color="#475569" />
                  )}
                </div>
              </th>
              <th
                onClick={() => handleToggleSort('severity')}
                style={{ padding: '0.75rem 1rem', cursor: 'pointer', userSelect: 'none' }}
                title="Click to sort by Severity"
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
                  <span>Severity</span>
                  {sortBy === 'severity' ? (
                    sortDir === 'asc' ? <ArrowUp size={12} color="#38bdf8" /> : <ArrowDown size={12} color="#38bdf8" />
                  ) : (
                    <ArrowUpDown size={12} color="#475569" />
                  )}
                </div>
              </th>
              <th style={{ padding: '0.75rem 1rem', textAlign: 'right' }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {events.length === 0 ? (
              <tr>
                <td colSpan={7} style={{ textAlign: 'center', padding: '3rem', color: '#64748b' }}>
                  {loading ? 'Querying indexed events...' : 'No security events found matching current criteria.'}
                </td>
              </tr>
            ) : (
              events.map((evt) => (
                <tr
                  key={evt.event_id}
                  style={{
                    borderBottom: '1px solid #1e293b',
                    transition: 'background 0.15s',
                    cursor: 'pointer'
                  }}
                  onClick={() => handleInspectEvent(evt)}
                  onMouseEnter={(e) => (e.currentTarget.style.backgroundColor = '#1e293b55')}
                  onMouseLeave={(e) => (e.currentTarget.style.backgroundColor = 'transparent')}
                >
                  <td className="font-mono" style={{ padding: '0.75rem 1rem', color: '#cbd5e1', fontSize: '0.75rem' }}>
                    <div style={{ color: '#f8fafc', fontWeight: 600 }}>
                      {formatTimestamp(evt.ingested_at || evt.observed_at || evt.timestamp)}
                    </div>
                    {evt.timestamp && (
                      <div style={{ color: '#64748b', fontSize: '0.68rem', marginTop: '0.15rem' }}>
                        Log: {formatTimestamp(evt.timestamp)}
                      </div>
                    )}
                  </td>
                  <td style={{ padding: '0.75rem 1rem', fontWeight: 600, color: '#f8fafc' }}>
                    {evt.event_type === 'system_heartbeat' ? (
                      <span style={{ color: '#34d399', display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                        <span style={{ display: 'inline-block', width: '6px', height: '6px', borderRadius: '50%', backgroundColor: '#10b981' }}></span>
                        Agent Heartbeat
                      </span>
                    ) : (
                      evt.event_type
                    )}
                    {evt.windows_event_id && (
                      <span className="font-mono" style={{ fontSize: '0.7rem', color: '#64748b', marginLeft: '0.4rem' }}>
                        (Win {evt.windows_event_id})
                      </span>
                    )}
                  </td>
                  <td className="font-mono" style={{ padding: '0.75rem 1rem', color: '#a78bfa', fontSize: '0.75rem' }}>
                    <div>{evt.source_host}</div>
                    {evt.metadata?.collector_id && (
                      <div style={{ color: '#64748b', fontSize: '0.68rem', marginTop: '0.1rem' }}>
                        {evt.metadata.collector_id}
                      </div>
                    )}
                  </td>
                  <td className="font-mono" style={{ padding: '0.75rem 1rem', color: '#fbbf24', fontSize: '0.75rem' }}>
                    {evt.username || '—'}
                  </td>
                  <td className="font-mono" style={{ padding: '0.75rem 1rem', color: '#38bdf8', fontSize: '0.75rem' }}>
                    {evt.source_ip || '—'}
                  </td>
                  <td style={{ padding: '0.75rem 1rem' }}>
                    <span className={`badge ${getSeverityBadgeClass(evt.severity)}`}>
                      {evt.severity}
                    </span>
                  </td>
                  <td style={{ padding: '0.75rem 1rem', textAlign: 'right' }}>
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        handleInspectEvent(evt);
                      }}
                      className="btn btn-secondary btn-sm"
                    >
                      <Eye size={12} />
                      Inspect & Explain
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Event Inspection & AI Explanation Modal */}
      {selectedEvent && (
        <div className="modal-overlay" onClick={() => setSelectedEvent(null)}>
          <div
            className="modal-content"
            onClick={(e) => e.stopPropagation()}
            style={{ maxWidth: '850px', maxHeight: '90vh' }}
          >
            {/* Modal Header */}
            <div style={{
              padding: '1.25rem 1.5rem',
              borderBottom: '1px solid #1e293b',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              background: '#0f172a'
            }}>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.25rem' }}>
                  <span className={`badge ${getSeverityBadgeClass(selectedEvent.severity)}`}>
                    {selectedEvent.severity}
                  </span>
                  <span className="font-mono" style={{ fontSize: '0.8rem', color: '#38bdf8' }}>
                    {selectedEvent.event_id}
                  </span>
                </div>
                <h3 style={{ fontSize: '1.15rem', fontWeight: 600, color: '#f8fafc' }}>
                  Event Inspection: {selectedEvent.event_type}
                </h3>
              </div>

              <button
                onClick={() => setSelectedEvent(null)}
                className="btn btn-secondary btn-sm"
                style={{ borderRadius: '50%', width: '32px', height: '32px', padding: 0 }}
              >
                <X size={18} />
              </button>
            </div>

            {/* Modal Body */}
            <div style={{ flex: 1, overflowY: 'auto', padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
              {/* Canonical Fields Grid */}
              <div className="soc-card" style={{ padding: '1rem', background: '#111827' }}>
                <h4 style={{ fontSize: '0.85rem', fontWeight: 600, color: '#94a3b8', marginBottom: '0.75rem', textTransform: 'uppercase' }}>
                  Canonical Schema v1.0 Attributes
                </h4>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '0.5rem', fontSize: '0.8rem' }}>
                  <div><span style={{ color: '#64748b' }}>Received (Ingested):</span> <strong className="font-mono" style={{ color: '#38bdf8' }}>{selectedEvent.ingested_at || selectedEvent.observed_at}</strong></div>
                  <div><span style={{ color: '#64748b' }}>Event Timestamp:</span> <strong className="font-mono" style={{ color: '#cbd5e1' }}>{selectedEvent.timestamp}</strong></div>
                  <div><span style={{ color: '#64748b' }}>Source Host:</span> <strong className="font-mono" style={{ color: '#a78bfa' }}>{selectedEvent.source_host}</strong></div>
                  <div><span style={{ color: '#64748b' }}>Source Type:</span> <strong className="font-mono" style={{ color: '#cbd5e1' }}>{selectedEvent.source_type}</strong></div>
                  <div><span style={{ color: '#64748b' }}>Username:</span> <strong className="font-mono" style={{ color: '#fbbf24' }}>{selectedEvent.username || 'null'}</strong></div>
                  <div><span style={{ color: '#64748b' }}>Source IP:</span> <strong className="font-mono" style={{ color: '#38bdf8' }}>{selectedEvent.source_ip || 'null'}</strong></div>
                  <div><span style={{ color: '#64748b' }}>Destination IP:</span> <strong className="font-mono" style={{ color: '#cbd5e1' }}>{selectedEvent.destination_ip || 'null'}</strong></div>
                  <div><span style={{ color: '#64748b' }}>Windows Event ID:</span> <strong className="font-mono" style={{ color: '#cbd5e1' }}>{selectedEvent.windows_event_id || 'null'}</strong></div>
                </div>
              </div>

              {/* Raw Event Text */}
              <div className="soc-card" style={{ padding: '1rem', background: '#0f172a' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.5rem' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: '#94a3b8', fontSize: '0.85rem' }}>
                    <FileCode size={15} />
                    <strong>Raw Original Log Entry</strong>
                  </div>
                  <button onClick={handleCopyRaw} className="btn btn-secondary btn-sm" style={{ fontSize: '0.7rem' }}>
                    {copied ? <Check size={12} color="#10b981" /> : <Copy size={12} />}
                    {copied ? 'Copied' : 'Copy'}
                  </button>
                </div>
                <pre className="font-mono" style={{
                  background: '#090d16',
                  padding: '0.75rem',
                  borderRadius: '6px',
                  border: '1px solid #1e293b',
                  fontSize: '0.78rem',
                  color: '#e2e8f0',
                  overflowX: 'auto',
                  whiteSpace: 'pre-wrap',
                  wordBreak: 'break-all'
                }}>
                  {selectedEvent.raw_event}
                </pre>
              </div>

              {/* Explain with AI Action & Card */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <h4 style={{ fontSize: '0.95rem', fontWeight: 600, color: '#f8fafc', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    <Sparkles size={16} color="#a855f7" />
                    AI Event Semantic Analysis
                  </h4>
                  <button
                    onClick={handleExplainWithAI}
                    disabled={explaining}
                    className="btn btn-ai btn-sm"
                  >
                    {explaining ? (
                      <>
                        <RefreshCw size={13} className="spin" />
                        Analyzing...
                      </>
                    ) : (
                      <>
                        <Sparkles size={13} />
                        Explain This Event
                      </>
                    )}
                  </button>
                </div>

                {aiExplanation && (
                  <div className="soc-card" style={{ padding: '1rem', background: 'rgba(139, 92, 246, 0.08)', border: '1px solid rgba(139, 92, 246, 0.3)' }}>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.65rem' }}>
                      <div>
                        <div style={{ fontSize: '0.75rem', color: '#a78bfa', fontWeight: 600 }}>Summary</div>
                        <div style={{ fontSize: '0.875rem', color: '#f8fafc' }}>{aiExplanation.summary}</div>
                      </div>

                      <div>
                        <div style={{ fontSize: '0.75rem', color: '#a78bfa', fontWeight: 600 }}>Security Significance</div>
                        <div style={{ fontSize: '0.85rem', color: '#cbd5e1' }}>{aiExplanation.security_significance}</div>
                      </div>

                      <div>
                        <div style={{ fontSize: '0.75rem', color: '#a78bfa', fontWeight: 600 }}>Forensic Recommendation</div>
                        <div style={{ fontSize: '0.85rem', color: '#38bdf8' }}>{aiExplanation.recommendation}</div>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
