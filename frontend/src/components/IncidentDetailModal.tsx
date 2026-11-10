import React, { useState } from 'react';
import {
  Incident,
  IncidentStatus,
  TimelineEntry,
  AnalystNote
} from '../types';
import {
  X,
  Clock,
  User,
  Globe,
  Server,
  Sparkles,
  MessageSquare,
  Shield,
  Activity,
  CheckCircle2,
  FileText,
  AlertTriangle,
  GitCommit,
  Plus
} from 'lucide-react';

interface IncidentDetailModalProps {
  incident: Incident;
  onClose: () => void;
  onUpdateStatus: (incidentId: string, status: IncidentStatus) => Promise<void>;
  onAddNote: (incidentId: string, author: string, content: string) => Promise<void>;
  onLaunchAI: (incidentId: string) => void;
}

export const IncidentDetailModal: React.FC<IncidentDetailModalProps> = ({
  incident,
  onClose,
  onUpdateStatus,
  onAddNote,
  onLaunchAI,
}) => {
  const [activeTab, setActiveTab] = useState<'timeline' | 'notes' | 'entities'>('timeline');
  const [newNoteContent, setNewNoteContent] = useState('');
  const [noteAuthor, setNoteAuthor] = useState('soc_analyst_1');
  const [submittingNote, setSubmittingNote] = useState(false);
  const [updatingStatus, setUpdatingStatus] = useState(false);

  const handleAddNoteSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newNoteContent.trim()) return;
    try {
      setSubmittingNote(true);
      await onAddNote(incident.incident_id, noteAuthor, newNoteContent.trim());
      setNewNoteContent('');
    } finally {
      setSubmittingNote(false);
    }
  };

  const handleStatusChange = async (status: IncidentStatus) => {
    try {
      setUpdatingStatus(true);
      await onUpdateStatus(incident.incident_id, status);
    } finally {
      setUpdatingStatus(false);
    }
  };

  const formatTimestamp = (iso: string) => {
    try {
      const d = new Date(iso);
      return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) +
        ' • ' + d.toLocaleDateString([], { month: 'short', day: 'numeric', year: 'numeric' });
    } catch {
      return iso;
    }
  };

  const getTimelineIcon = (entryType: string) => {
    switch (entryType) {
      case 'alert':
        return <AlertTriangle size={15} color="#f97316" />;
      case 'event':
        return <Activity size={15} color="#06b6d4" />;
      case 'status_change':
        return <GitCommit size={15} color="#38bdf8" />;
      case 'note':
        return <MessageSquare size={15} color="#a78bfa" />;
      case 'mitigation':
        return <Shield size={15} color="#10b981" />;
      default:
        return <Clock size={15} color="#94a3b8" />;
    }
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div
        className="modal-content"
        onClick={(e) => e.stopPropagation()}
        style={{ maxWidth: '980px', height: '88vh' }}
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
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '0.35rem' }}>
              <span className={`badge badge-${incident.severity.toLowerCase()}`}>
                {incident.severity}
              </span>
              <span className="font-mono" style={{ fontSize: '0.85rem', color: '#94a3b8' }}>
                {incident.incident_id}
              </span>
              <span className={`badge badge-neutral`}>
                STATUS: {incident.status}
              </span>
              <span style={{ fontSize: '0.8rem', color: '#64748b' }}>
                Risk Score: <strong style={{ color: '#f43f5e' }}>{incident.risk_score}/100</strong>
              </span>
            </div>
            <h3 style={{ fontSize: '1.25rem', fontWeight: 600, color: '#f8fafc' }}>
              {incident.title}
            </h3>
          </div>

          <button
            onClick={onClose}
            className="btn btn-secondary btn-sm"
            style={{ borderRadius: '50%', width: '32px', height: '32px', padding: 0 }}
          >
            <X size={18} />
          </button>
        </div>

        {/* Modal Navigation Tabs */}
        <div style={{
          display: 'flex',
          borderBottom: '1px solid #1e293b',
          padding: '0 1.5rem',
          background: '#111827',
          gap: '1rem'
        }}>
          <button
            onClick={() => setActiveTab('timeline')}
            style={{
              padding: '0.75rem 0.5rem',
              background: 'transparent',
              border: 'none',
              borderBottom: activeTab === 'timeline' ? '2px solid #38bdf8' : '2px solid transparent',
              color: activeTab === 'timeline' ? '#38bdf8' : '#94a3b8',
              fontWeight: 600,
              fontSize: '0.875rem',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '0.4rem'
            }}
          >
            <Clock size={16} />
            Forensic Timeline ({incident.timeline.length})
          </button>

          <button
            onClick={() => setActiveTab('notes')}
            style={{
              padding: '0.75rem 0.5rem',
              background: 'transparent',
              border: 'none',
              borderBottom: activeTab === 'notes' ? '2px solid #38bdf8' : '2px solid transparent',
              color: activeTab === 'notes' ? '#38bdf8' : '#94a3b8',
              fontWeight: 600,
              fontSize: '0.875rem',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '0.4rem'
            }}
          >
            <MessageSquare size={16} />
            Analyst Notes ({incident.analyst_notes?.length || 0})
          </button>

          <button
            onClick={() => setActiveTab('entities')}
            style={{
              padding: '0.75rem 0.5rem',
              background: 'transparent',
              border: 'none',
              borderBottom: activeTab === 'entities' ? '2px solid #38bdf8' : '2px solid transparent',
              color: activeTab === 'entities' ? '#38bdf8' : '#94a3b8',
              fontWeight: 600,
              fontSize: '0.875rem',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '0.4rem'
            }}
          >
            <FileText size={16} />
            Entities & Evidence
          </button>
        </div>

        {/* Modal Body Content */}
        <div style={{ flex: 1, overflowY: 'auto', padding: '1.5rem', backgroundColor: '#0b0f19' }}>
          {/* TAB 1: TIMELINE */}
          {activeTab === 'timeline' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              <div style={{ fontSize: '0.85rem', color: '#94a3b8', marginBottom: '0.5rem' }}>
                Chronological sequence of correlated alerts, authentication anomalies, and analyst interventions:
              </div>

              <div style={{ position: 'relative', paddingLeft: '1.5rem' }}>
                {/* Vertical timeline bar */}
                <div style={{
                  position: 'absolute',
                  left: '7px',
                  top: '8px',
                  bottom: '8px',
                  width: '2px',
                  backgroundColor: '#334155'
                }} />

                <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
                  {incident.timeline.map((entry, idx) => (
                    <div key={entry.entry_id || idx} style={{ position: 'relative', display: 'flex', gap: '1rem' }}>
                      {/* Timeline dot */}
                      <div style={{
                        position: 'absolute',
                        left: '-1.5rem',
                        top: '2px',
                        background: '#0f172a',
                        border: '2px solid #38bdf8',
                        borderRadius: '50%',
                        width: '18px',
                        height: '18px',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        zIndex: 2
                      }}>
                        <div style={{ width: '6px', height: '6px', borderRadius: '50%', background: '#38bdf8' }} />
                      </div>

                      <div className="soc-card" style={{ flex: 1, padding: '0.85rem 1rem', background: '#111827' }}>
                        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.35rem' }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                            {getTimelineIcon(entry.entry_type)}
                            <span style={{ fontSize: '0.75rem', fontWeight: 600, textTransform: 'uppercase', color: '#94a3b8' }}>
                              {entry.entry_type}
                            </span>
                            {entry.source_id && (
                              <span className="font-mono" style={{ fontSize: '0.72rem', color: '#64748b' }}>
                                [{entry.source_id}]
                              </span>
                            )}
                          </div>
                          <span style={{ fontSize: '0.75rem', color: '#64748b' }}>
                            {formatTimestamp(entry.timestamp)}
                          </span>
                        </div>

                        <p style={{ fontSize: '0.875rem', color: '#f1f5f9', margin: '0.25rem 0' }}>
                          {entry.description}
                        </p>

                        {entry.entities && Object.keys(entry.entities).length > 0 && (
                          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.4rem', marginTop: '0.4rem' }}>
                            {Object.entries(entry.entities).map(([k, v]) => (
                              <span
                                key={k}
                                className="font-mono"
                                style={{
                                  fontSize: '0.7rem',
                                  background: '#1e293b',
                                  padding: '0.1rem 0.4rem',
                                  borderRadius: '3px',
                                  color: '#cbd5e1'
                                }}
                              >
                                {k}: {String(v)}
                              </span>
                            ))}
                          </div>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* TAB 2: ANALYST NOTES */}
          {activeTab === 'notes' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
              {/* Add Note Form */}
              <div className="soc-card" style={{ padding: '1.25rem', background: '#111827' }}>
                <h4 style={{ fontSize: '0.95rem', fontWeight: 600, color: '#f8fafc', marginBottom: '0.75rem' }}>
                  Add Analyst Investigation Note
                </h4>
                <form onSubmit={handleAddNoteSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                  <div style={{ display: 'flex', gap: '0.75rem' }}>
                    <div style={{ width: '200px' }}>
                      <label style={{ fontSize: '0.75rem', color: '#94a3b8', display: 'block', marginBottom: '0.25rem' }}>
                        Analyst Identity
                      </label>
                      <input
                        type="text"
                        value={noteAuthor}
                        onChange={(e) => setNoteAuthor(e.target.value)}
                        placeholder="analyst_name"
                        style={{ width: '100%' }}
                        required
                      />
                    </div>
                  </div>

                  <div>
                    <label style={{ fontSize: '0.75rem', color: '#94a3b8', display: 'block', marginBottom: '0.25rem' }}>
                      Observation / Finding
                    </label>
                    <textarea
                      rows={3}
                      value={newNoteContent}
                      onChange={(e) => setNewNoteContent(e.target.value)}
                      placeholder="Enter forensic triage notes, observed MITRE tactics, or escalation details..."
                      style={{ width: '100%', resize: 'vertical' }}
                      required
                    />
                  </div>

                  <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
                    <button
                      type="submit"
                      disabled={submittingNote || !newNoteContent.trim()}
                      className="btn btn-primary btn-sm"
                    >
                      <Plus size={14} />
                      {submittingNote ? 'Saving...' : 'Add Note to Dossier'}
                    </button>
                  </div>
                </form>
              </div>

              {/* Notes List */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                {(!incident.analyst_notes || incident.analyst_notes.length === 0) ? (
                  <div style={{ textAlign: 'center', padding: '2rem', color: '#64748b' }}>
                    No analyst notes recorded yet. Add the first finding above.
                  </div>
                ) : (
                  incident.analyst_notes.map((note) => (
                    <div key={note.note_id} className="soc-card" style={{ padding: '1rem', background: '#111827' }}>
                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.4rem' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                          <User size={14} color="#38bdf8" />
                          <span style={{ fontWeight: 600, fontSize: '0.85rem', color: '#f8fafc' }}>
                            {note.author}
                          </span>
                        </div>
                        <span style={{ fontSize: '0.75rem', color: '#64748b' }}>
                          {formatTimestamp(note.created_at)}
                        </span>
                      </div>
                      <p style={{ fontSize: '0.875rem', color: '#e2e8f0', whiteSpace: 'pre-wrap' }}>
                        {note.content}
                      </p>
                    </div>
                  ))
                )}
              </div>
            </div>
          )}

          {/* TAB 3: ENTITIES & EVIDENCE */}
          {activeTab === 'entities' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
              <div className="soc-card" style={{ padding: '1.25rem', background: '#111827' }}>
                <h4 style={{ fontSize: '0.95rem', fontWeight: 600, color: '#f8fafc', marginBottom: '1rem' }}>
                  Correlated Entity Graph
                </h4>

                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))', gap: '1rem' }}>
                  {/* IPs */}
                  <div style={{ background: '#0f172a', padding: '1rem', borderRadius: '6px', border: '1px solid #1e293b' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem', color: '#38bdf8' }}>
                      <Globe size={16} />
                      <strong style={{ fontSize: '0.85rem' }}>Source IPs ({incident.entities.source_ips.length})</strong>
                    </div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
                      {incident.entities.source_ips.map((ip) => (
                        <span key={ip} className="font-mono" style={{ fontSize: '0.8rem', color: '#cbd5e1' }}>
                          • {ip}
                        </span>
                      ))}
                    </div>
                  </div>

                  {/* Users */}
                  <div style={{ background: '#0f172a', padding: '1rem', borderRadius: '6px', border: '1px solid #1e293b' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem', color: '#fbbf24' }}>
                      <User size={16} />
                      <strong style={{ fontSize: '0.85rem' }}>Target Usernames ({incident.entities.usernames.length})</strong>
                    </div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
                      {incident.entities.usernames.map((u) => (
                        <span key={u} className="font-mono" style={{ fontSize: '0.8rem', color: '#cbd5e1' }}>
                          • {u}
                        </span>
                      ))}
                    </div>
                  </div>

                  {/* Hosts */}
                  <div style={{ background: '#0f172a', padding: '1rem', borderRadius: '6px', border: '1px solid #1e293b' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem', color: '#a78bfa' }}>
                      <Server size={16} />
                      <strong style={{ fontSize: '0.85rem' }}>Affected Hosts ({incident.entities.hosts.length})</strong>
                    </div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
                      {incident.entities.hosts.map((h) => (
                        <span key={h} className="font-mono" style={{ fontSize: '0.8rem', color: '#cbd5e1' }}>
                          • {h}
                        </span>
                      ))}
                    </div>
                  </div>
                </div>
              </div>

              {/* Evidence IDs */}
              <div className="soc-card" style={{ padding: '1.25rem', background: '#111827' }}>
                <h4 style={{ fontSize: '0.95rem', fontWeight: 600, color: '#f8fafc', marginBottom: '0.75rem' }}>
                  Underlying Raw Evidence IDs
                </h4>

                <div style={{ marginBottom: '1rem' }}>
                  <div style={{ fontSize: '0.8rem', color: '#94a3b8', marginBottom: '0.35rem' }}>
                    Correlated Alert IDs ({incident.related_alert_ids.length}):
                  </div>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.4rem' }}>
                    {incident.related_alert_ids.map((aid) => (
                      <span key={aid} className="font-mono" style={{ background: '#1e293b', padding: '0.15rem 0.5rem', borderRadius: '4px', fontSize: '0.75rem', color: '#f97316' }}>
                        {aid}
                      </span>
                    ))}
                  </div>
                </div>

                <div>
                  <div style={{ fontSize: '0.8rem', color: '#94a3b8', marginBottom: '0.35rem' }}>
                    Correlated Canonical Event IDs ({incident.related_event_ids.length}):
                  </div>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.4rem', maxHeight: '180px', overflowY: 'auto' }}>
                    {incident.related_event_ids.map((eid) => (
                      <span key={eid} className="font-mono" style={{ background: '#1e293b', padding: '0.15rem 0.5rem', borderRadius: '4px', fontSize: '0.72rem', color: '#38bdf8' }}>
                        {eid}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Modal Footer: Quick Lifecycle Actions & AI Launcher */}
        <div style={{
          padding: '1rem 1.5rem',
          borderTop: '1px solid #1e293b',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          background: '#0f172a'
        }}>
          {/* Status Change Buttons */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <span style={{ fontSize: '0.8rem', color: '#94a3b8', marginRight: '0.25rem' }}>Triage State:</span>
            {(['NEW', 'INVESTIGATING', 'RESOLVED', 'CLOSED'] as IncidentStatus[]).map((st) => (
              <button
                key={st}
                onClick={() => handleStatusChange(st)}
                disabled={updatingStatus || incident.status === st}
                className="btn btn-secondary btn-sm"
                style={{
                  background: incident.status === st ? '#1e293b' : 'transparent',
                  color: incident.status === st ? '#38bdf8' : '#94a3b8',
                  borderColor: incident.status === st ? '#38bdf8' : '#334155',
                  fontSize: '0.72rem',
                }}
              >
                {st}
              </button>
            ))}
          </div>

          {/* AI Trigger */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <button
              onClick={() => {
                onClose();
                onLaunchAI(incident.incident_id);
              }}
              className="btn btn-ai"
              style={{ padding: '0.5rem 1rem' }}
            >
              <Sparkles size={16} />
              Launch Evidence-Grounded AI Investigation
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
