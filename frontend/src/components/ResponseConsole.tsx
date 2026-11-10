import React, { useState, useEffect } from 'react';
import {
  ResponseActionRecord,
  SafetyStatusResponse,
  ActionStatus,
  ActionType,
  Incident
} from '../types';
import { api } from '../services/api';
import {
  ShieldAlert,
  ShieldCheck,
  RotateCcw,
  Play,
  CheckCircle2,
  AlertTriangle,
  RefreshCw,
  Lock,
  Globe,
  User,
  Plus,
  Terminal,
  Clock,
  Check,
  X,
  FileText
} from 'lucide-react';

interface ResponseConsoleProps {
  incidents: Incident[];
  onRefreshAll: () => void;
}

export const ResponseConsole: React.FC<ResponseConsoleProps> = ({
  incidents,
  onRefreshAll,
}) => {
  const [actions, setActions] = useState<ResponseActionRecord[]>([]);
  const [total, setTotal] = useState<number>(0);
  const [safetyStatus, setSafetyStatus] = useState<SafetyStatusResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [selectedIncidentFilter, setSelectedIncidentFilter] = useState<string>('ALL');

  // Approve / Execute / Rollback modal states
  const [activeModalAction, setActiveModalAction] = useState<ResponseActionRecord | null>(null);
  const [modalMode, setModalMode] = useState<'approve' | 'execute' | 'rollback' | null>(null);
  const [analystName, setAnalystName] = useState('senior_soc_analyst');
  const [comment, setComment] = useState('');
  const [forceLive, setForceLive] = useState(false);
  const [processing, setProcessing] = useState(false);
  const [statusMessage, setStatusMessage] = useState<string | null>(null);

  // Manual Propose Modal state
  const [showProposeModal, setShowProposeModal] = useState(false);
  const [propIncidentId, setPropIncidentId] = useState('');
  const [propActionType, setPropActionType] = useState<ActionType>('block_ip');
  const [propTarget, setPropTarget] = useState('');
  const [propPriority, setPropPriority] = useState('high');
  const [propReason, setPropReason] = useState('');

  const fetchActions = async () => {
    try {
      setLoading(true);
      const [actionsRes, safetyRes] = await Promise.all([
        api.getResponseActions({
          incident_id: selectedIncidentFilter !== 'ALL' ? selectedIncidentFilter : undefined,
          status: statusFilter !== 'ALL' ? statusFilter : undefined,
          limit: 100,
        }),
        api.getSafetyStatus().catch(() => null),
      ]);
      setActions(actionsRes.actions || []);
      setTotal(actionsRes.total || 0);
      if (safetyRes) setSafetyStatus(safetyRes);
    } catch (err: any) {
      console.error('Failed to load response actions:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchActions();
  }, [statusFilter, selectedIncidentFilter]);

  const handleApprove = async () => {
    if (!activeModalAction) return;
    try {
      setProcessing(true);
      await api.approveResponseAction(activeModalAction.action_id, analystName, comment);
      setStatusMessage(`Action ${activeModalAction.action_id} approved successfully.`);
      setActiveModalAction(null);
      setModalMode(null);
      setComment('');
      await fetchActions();
    } catch (err: any) {
      alert(`Approval error: ${err.message}`);
    } finally {
      setProcessing(false);
    }
  };

  const handleExecute = async () => {
    if (!activeModalAction) return;
    try {
      setProcessing(true);
      const res = await api.executeResponseAction(activeModalAction.action_id, forceLive);
      setStatusMessage(`Action executed: ${res.message}`);
      setActiveModalAction(null);
      setModalMode(null);
      setForceLive(false);
      await fetchActions();
    } catch (err: any) {
      alert(`Execution error: ${err.message}`);
    } finally {
      setProcessing(false);
    }
  };

  const handleRollback = async () => {
    if (!activeModalAction) return;
    try {
      setProcessing(true);
      const res = await api.rollbackResponseAction(activeModalAction.action_id, analystName, comment);
      setStatusMessage(`Rollback complete: ${res.message}`);
      setActiveModalAction(null);
      setModalMode(null);
      setComment('');
      await fetchActions();
    } catch (err: any) {
      alert(`Rollback error: ${err.message}`);
    } finally {
      setProcessing(false);
    }
  };

  const handleProposeSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      setProcessing(true);
      const record = await api.proposeResponseAction({
        incident_id: propIncidentId || (incidents[0]?.incident_id ?? 'inc_general'),
        action_type: propActionType,
        target: propTarget.trim(),
        priority: propPriority,
        reason: propReason.trim() || 'Manual containment action proposed by analyst.',
      });
      if (record.status === 'REJECTED') {
        alert(`Action rejected by Safety Guard: ${record.error_message}`);
      } else {
        setStatusMessage(`Action proposed successfully (${record.action_id}).`);
      }
      setShowProposeModal(false);
      setPropTarget('');
      setPropReason('');
      await fetchActions();
    } catch (err: any) {
      alert(`Failed to propose action: ${err.message}`);
    } finally {
      setProcessing(false);
    }
  };

  const getStatusBadge = (status: ActionStatus) => {
    switch (status) {
      case 'APPROVED':
        return 'badge-ai';
      case 'EXECUTED':
      case 'SIMULATED':
        return 'badge-success';
      case 'ROLLED_BACK':
        return 'badge-neutral';
      case 'REJECTED':
      case 'FAILED':
        return 'badge-critical';
      case 'PROPOSED':
      default:
        return 'badge-high';
    }
  };

  const getPriorityBadge = (p: string) => {
    switch (p.toLowerCase()) {
      case 'immediate':
        return 'badge-critical';
      case 'high':
        return 'badge-high';
      case 'medium':
        return 'badge-medium';
      default:
        return 'badge-low';
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      {/* 1. Safety Guardrails & Status Top Banner */}
      <div className="soc-card" style={{ padding: '1.25rem', background: '#0f172a' }}>
        <div style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '1rem'
        }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.25rem' }}>
              <ShieldAlert size={20} color="#38bdf8" />
              <h3 style={{ fontSize: '1.15rem', fontWeight: 600, color: '#f8fafc' }}>
                Controlled Automated Response Engine
              </h3>
              <span className="badge badge-success" style={{ fontSize: '0.7rem' }}>
                Dry-Run Safe Mode
              </span>
            </div>
            <p style={{ fontSize: '0.78rem', color: '#94a3b8' }}>
              Approval-gated containment • Reversible firewall/account policies • Safety allowlists protecting gateways & root accounts
            </p>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <button
              onClick={() => setShowProposeModal(true)}
              className="btn btn-primary btn-sm"
            >
              <Plus size={14} />
              Propose Action
            </button>

            <button onClick={fetchActions} disabled={loading} className="btn btn-secondary btn-sm">
              <RefreshCw size={13} className={loading ? 'spin' : ''} />
              Refresh
            </button>
          </div>
        </div>

        {/* Safety Invariant Badges */}
        <div style={{
          display: 'flex',
          flexWrap: 'wrap',
          gap: '0.75rem',
          marginTop: '1rem',
          paddingTop: '0.85rem',
          borderTop: '1px solid #1e293b'
        }}>
          <div style={{
            background: 'rgba(16, 185, 129, 0.08)',
            border: '1px solid rgba(16, 185, 129, 0.3)',
            padding: '0.35rem 0.75rem',
            borderRadius: '6px',
            fontSize: '0.75rem',
            color: '#10b981',
            display: 'flex',
            alignItems: 'center',
            gap: '0.4rem'
          }}>
            <ShieldCheck size={14} />
            <span>Mode: <strong>Dry-Run (Default Simulation)</strong></span>
          </div>

          <div style={{
            background: 'rgba(56, 189, 248, 0.08)',
            border: '1px solid rgba(56, 189, 248, 0.3)',
            padding: '0.35rem 0.75rem',
            borderRadius: '6px',
            fontSize: '0.75rem',
            color: '#38bdf8',
            display: 'flex',
            alignItems: 'center',
            gap: '0.4rem'
          }}>
            <Globe size={14} />
            <span>Protected IPs: <strong>{safetyStatus?.protected_ips.length || 8} allowlisted</strong></span>
          </div>

          <div style={{
            background: 'rgba(251, 191, 36, 0.08)',
            border: '1px solid rgba(251, 191, 36, 0.3)',
            padding: '0.35rem 0.75rem',
            borderRadius: '6px',
            fontSize: '0.75rem',
            color: '#fbbf24',
            display: 'flex',
            alignItems: 'center',
            gap: '0.4rem'
          }}>
            <User size={14} />
            <span>Protected Users: <strong>{safetyStatus?.protected_users.length || 9} allowlisted</strong></span>
          </div>

          <div style={{
            background: 'rgba(168, 85, 247, 0.08)',
            border: '1px solid rgba(168, 85, 247, 0.3)',
            padding: '0.35rem 0.75rem',
            borderRadius: '6px',
            fontSize: '0.75rem',
            color: '#c084fc',
            display: 'flex',
            alignItems: 'center',
            gap: '0.4rem'
          }}>
            <Lock size={14} />
            <span>Throttling: <strong>Max 5 actions / min per target</strong></span>
          </div>
        </div>
      </div>

      {statusMessage && (
        <div style={{
          background: 'rgba(16, 185, 129, 0.1)',
          border: '1px solid rgba(16, 185, 129, 0.4)',
          padding: '0.75rem 1rem',
          borderRadius: '6px',
          color: '#10b981',
          fontSize: '0.85rem',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between'
        }}>
          <span>{statusMessage}</span>
          <button onClick={() => setStatusMessage(null)} style={{ background: 'transparent', border: 'none', color: '#10b981', cursor: 'pointer' }}>✕</button>
        </div>
      )}

      {/* 2. Filters Bar */}
      <div className="soc-card" style={{ padding: '0.85rem 1.25rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '1rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <label style={{ fontSize: '0.8rem', color: '#94a3b8' }}>Status:</label>
              <select
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
                style={{ cursor: 'pointer' }}
              >
                <option value="ALL">All Statuses</option>
                <option value="PROPOSED">PROPOSED (Pending Approval)</option>
                <option value="APPROVED">APPROVED (Ready to Execute)</option>
                <option value="SIMULATED">SIMULATED (Dry-Run)</option>
                <option value="EXECUTED">EXECUTED (Live)</option>
                <option value="ROLLED_BACK">ROLLED_BACK</option>
                <option value="REJECTED">REJECTED (Blocked by Safety)</option>
              </select>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <label style={{ fontSize: '0.8rem', color: '#94a3b8' }}>Incident:</label>
              <select
                value={selectedIncidentFilter}
                onChange={(e) => setSelectedIncidentFilter(e.target.value)}
                style={{ cursor: 'pointer', maxWidth: '300px' }}
              >
                <option value="ALL">All Incidents</option>
                {incidents.map((inc) => (
                  <option key={inc.incident_id} value={inc.incident_id}>
                    {inc.incident_id} — {inc.title.substring(0, 30)}...
                  </option>
                ))}
              </select>
            </div>
          </div>

          <div style={{ fontSize: '0.8rem', color: '#94a3b8' }}>
            Showing <strong>{actions.length}</strong> recorded containment actions
          </div>
        </div>
      </div>

      {/* 3. Actions Queue List */}
      {actions.length === 0 ? (
        <div className="soc-card" style={{ padding: '3.5rem 2rem', textAlign: 'center' }}>
          <ShieldCheck size={44} color="#10b981" style={{ margin: '0 auto 1rem' }} />
          <h4 style={{ fontSize: '1.15rem', color: '#f8fafc', marginBottom: '0.5rem' }}>
            No Response Actions in this View
          </h4>
          <p style={{ color: '#94a3b8', maxWidth: '500px', margin: '0 auto', fontSize: '0.85rem' }}>
            Response actions are proposed automatically by the AI Copilot during incident investigations, or can be proposed manually by analysts above.
          </p>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
          {actions.map((act) => (
            <div
              key={act.action_id}
              className="soc-card"
              style={{
                padding: '1.15rem 1.35rem',
                borderLeft: act.status === 'REJECTED' ? '4px solid #f43f5e' : act.status === 'APPROVED' ? '4px solid #a855f7' : act.status === 'SIMULATED' || act.status === 'EXECUTED' ? '4px solid #10b981' : '4px solid #f59e0b',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: '1rem', flexWrap: 'wrap' }}>
                <div style={{ flex: 1, minWidth: '320px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', marginBottom: '0.35rem' }}>
                    <span className={`badge ${getStatusBadge(act.status)}`}>
                      {act.status}
                    </span>
                    <span className={`badge ${getPriorityBadge(act.priority)}`}>
                      {act.priority}
                    </span>
                    <span className="font-mono" style={{ fontSize: '0.8rem', color: '#38bdf8', fontWeight: 600 }}>
                      {act.action_type.toUpperCase()}
                    </span>
                    <span className="font-mono" style={{ fontSize: '0.75rem', color: '#64748b' }}>
                      [{act.action_id}]
                    </span>
                    <span style={{ fontSize: '0.75rem', color: '#64748b' }}>•</span>
                    <span className="font-mono" style={{ fontSize: '0.75rem', color: '#94a3b8' }}>
                      Incident: {act.incident_id}
                    </span>
                  </div>

                  {/* Target & Reason */}
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', margin: '0.4rem 0' }}>
                    <span style={{ fontSize: '0.8rem', color: '#94a3b8' }}>Target:</span>
                    <span className="font-mono" style={{
                      background: '#1e293b',
                      border: '1px solid #334155',
                      padding: '0.15rem 0.5rem',
                      borderRadius: '4px',
                      fontSize: '0.85rem',
                      color: '#fbbf24',
                      fontWeight: 600
                    }}>
                      {act.target}
                    </span>
                    {act.dry_run && (
                      <span className="badge badge-neutral" style={{ fontSize: '0.65rem' }}>
                        DRY-RUN
                      </span>
                    )}
                  </div>

                  <p style={{ fontSize: '0.85rem', color: '#cbd5e1', lineHeight: 1.5, margin: '0.35rem 0' }}>
                    {act.reason}
                  </p>

                  {/* Error message if rejected */}
                  {act.error_message && (
                    <div style={{
                      background: 'rgba(239, 68, 68, 0.1)',
                      border: '1px solid rgba(239, 68, 68, 0.3)',
                      padding: '0.4rem 0.65rem',
                      borderRadius: '4px',
                      fontSize: '0.78rem',
                      color: '#f87171',
                      marginTop: '0.4rem'
                    }}>
                      <strong>Safety Guard Denial: </strong> {act.error_message}
                    </div>
                  )}

                  {/* Execution Output if executed/simulated */}
                  {act.execution_output && (
                    <div style={{
                      background: '#090d16',
                      border: '1px solid #1e293b',
                      padding: '0.5rem 0.75rem',
                      borderRadius: '4px',
                      fontSize: '0.75rem',
                      color: '#94a3b8',
                      marginTop: '0.5rem'
                    }}>
                      <div>
                        Command: <code className="font-mono" style={{ color: '#38bdf8' }}>{act.execution_output.applied_command || act.execution_output.simulated_command || 'Internal mitigation'}</code>
                      </div>
                      {act.executed_at && (
                        <div style={{ fontSize: '0.7rem', color: '#64748b', marginTop: '0.2rem' }}>
                          Executed At: {act.executed_at}
                        </div>
                      )}
                    </div>
                  )}
                </div>

                {/* Right Column: Approval / Execute / Rollback Buttons */}
                <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: '0.5rem', minWidth: '180px' }}>
                  {act.status === 'PROPOSED' && (
                    <button
                      className="btn btn-ai btn-sm"
                      onClick={() => {
                        setActiveModalAction(act);
                        setModalMode('approve');
                      }}
                    >
                      <CheckCircle2 size={13} />
                      Approve Action
                    </button>
                  )}

                  {act.status === 'APPROVED' && (
                    <button
                      className="btn btn-primary btn-sm"
                      onClick={() => {
                        setActiveModalAction(act);
                        setModalMode('execute');
                      }}
                    >
                      <Play size={13} />
                      Execute ({act.dry_run ? 'Simulate' : 'Live'})
                    </button>
                  )}

                  {(act.status === 'SIMULATED' || act.status === 'EXECUTED') && (
                    <button
                      className="btn btn-danger btn-sm"
                      onClick={() => {
                        setActiveModalAction(act);
                        setModalMode('rollback');
                      }}
                    >
                      <RotateCcw size={13} />
                      Rollback Action
                    </button>
                  )}

                  {act.status === 'ROLLED_BACK' && (
                    <span style={{ fontSize: '0.75rem', color: '#94a3b8', display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
                      <Check size={13} color="#10b981" />
                      Restoration Complete
                    </span>
                  )}
                </div>
              </div>

              {/* Sub-footer audit info */}
              <div style={{
                borderTop: '1px solid #1e293b',
                paddingTop: '0.5rem',
                marginTop: '0.75rem',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                fontSize: '0.72rem',
                color: '#64748b'
              }}>
                <div>
                  Requested by: <strong style={{ color: '#cbd5e1' }}>{act.requested_by}</strong>
                  {act.approved_by && (
                    <span> • Approved by: <strong style={{ color: '#38bdf8' }}>{act.approved_by}</strong></span>
                  )}
                </div>
                <div>Created: {act.created_at}</div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* APPROVE / EXECUTE / ROLLBACK MODAL */}
      {activeModalAction && modalMode && (
        <div className="modal-overlay" onClick={() => { setActiveModalAction(null); setModalMode(null); }}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()} style={{ maxWidth: '600px' }}>
            <div style={{
              padding: '1.25rem',
              borderBottom: '1px solid #1e293b',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              background: '#0f172a'
            }}>
              <h3 style={{ fontSize: '1.1rem', fontWeight: 600, color: '#f8fafc' }}>
                {modalMode === 'approve' && 'Approve Response Action'}
                {modalMode === 'execute' && 'Execute Response Action'}
                {modalMode === 'rollback' && 'Roll Back Response Action'}
              </h3>
              <button
                onClick={() => { setActiveModalAction(null); setModalMode(null); }}
                className="btn btn-secondary btn-sm"
                style={{ borderRadius: '50%', width: '30px', height: '30px', padding: 0 }}
              >
                ✕
              </button>
            </div>

            <div style={{ padding: '1.25rem', display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              <div style={{ background: '#090d16', padding: '0.75rem 1rem', borderRadius: '6px', border: '1px solid #1e293b', fontSize: '0.85rem' }}>
                <div>Action: <strong style={{ color: '#38bdf8' }}>{activeModalAction.action_type.toUpperCase()}</strong> on <strong className="font-mono" style={{ color: '#fbbf24' }}>{activeModalAction.target}</strong></div>
                <div style={{ fontSize: '0.78rem', color: '#94a3b8', marginTop: '0.25rem' }}>{activeModalAction.reason}</div>
              </div>

              <div>
                <label style={{ fontSize: '0.78rem', color: '#94a3b8', display: 'block', marginBottom: '0.25rem' }}>
                  SOC Analyst Sign-off Identity
                </label>
                <input
                  type="text"
                  value={analystName}
                  onChange={(e) => setAnalystName(e.target.value)}
                  style={{ width: '100%' }}
                  required
                />
              </div>

              {modalMode !== 'execute' && (
                <div>
                  <label style={{ fontSize: '0.78rem', color: '#94a3b8', display: 'block', marginBottom: '0.25rem' }}>
                    Analyst Notes / Rationale
                  </label>
                  <textarea
                    rows={2}
                    value={comment}
                    onChange={(e) => setComment(e.target.value)}
                    placeholder="Enter audit rationale for this decision..."
                    style={{ width: '100%', resize: 'vertical' }}
                  />
                </div>
              )}

              {modalMode === 'execute' && (
                <div style={{
                  background: 'rgba(56, 189, 248, 0.08)',
                  border: '1px solid rgba(56, 189, 248, 0.3)',
                  padding: '0.75rem',
                  borderRadius: '6px',
                  fontSize: '0.8rem',
                  color: '#cbd5e1'
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.4rem' }}>
                    <ShieldCheck size={16} color="#10b981" />
                    <strong style={{ color: '#38bdf8' }}>Execution Safety Guarantee:</strong>
                  </div>
                  <div>
                    This action will run in <strong>Dry-Run simulation mode</strong> by default. It constructs and logs the exact firewall/lockout commands and creates a verified rollback recipe without disrupting your host network.
                  </div>
                </div>
              )}
            </div>

            <div style={{
              padding: '1rem 1.25rem',
              borderTop: '1px solid #1e293b',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'flex-end',
              gap: '0.75rem',
              background: '#0f172a'
            }}>
              <button
                onClick={() => { setActiveModalAction(null); setModalMode(null); }}
                className="btn btn-secondary btn-sm"
              >
                Cancel
              </button>

              {modalMode === 'approve' && (
                <button
                  onClick={handleApprove}
                  disabled={processing}
                  className="btn btn-ai btn-sm"
                >
                  <CheckCircle2 size={14} />
                  {processing ? 'Approving...' : 'Confirm Approval'}
                </button>
              )}

              {modalMode === 'execute' && (
                <button
                  onClick={handleExecute}
                  disabled={processing}
                  className="btn btn-primary btn-sm"
                >
                  <Play size={14} />
                  {processing ? 'Executing...' : 'Execute Simulation'}
                </button>
              )}

              {modalMode === 'rollback' && (
                <button
                  onClick={handleRollback}
                  disabled={processing}
                  className="btn btn-danger btn-sm"
                >
                  <RotateCcw size={14} />
                  {processing ? 'Rolling Back...' : 'Confirm Rollback'}
                </button>
              )}
            </div>
          </div>
        </div>
      )}

      {/* PROPOSE ACTION MODAL */}
      {showProposeModal && (
        <div className="modal-overlay" onClick={() => setShowProposeModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()} style={{ maxWidth: '600px' }}>
            <div style={{
              padding: '1.25rem',
              borderBottom: '1px solid #1e293b',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              background: '#0f172a'
            }}>
              <h3 style={{ fontSize: '1.1rem', fontWeight: 600, color: '#f8fafc' }}>
                Propose Containment Response Action
              </h3>
              <button
                onClick={() => setShowProposeModal(false)}
                className="btn btn-secondary btn-sm"
                style={{ borderRadius: '50%', width: '30px', height: '30px', padding: 0 }}
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleProposeSubmit} style={{ padding: '1.25rem', display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              <div>
                <label style={{ fontSize: '0.78rem', color: '#94a3b8', display: 'block', marginBottom: '0.25rem' }}>
                  Target Correlated Incident
                </label>
                <select
                  value={propIncidentId}
                  onChange={(e) => setPropIncidentId(e.target.value)}
                  style={{ width: '100%', cursor: 'pointer' }}
                >
                  {incidents.map((inc) => (
                    <option key={inc.incident_id} value={inc.incident_id}>
                      [{inc.incident_id}] {inc.title}
                    </option>
                  ))}
                </select>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
                <div>
                  <label style={{ fontSize: '0.78rem', color: '#94a3b8', display: 'block', marginBottom: '0.25rem' }}>
                    Action Type
                  </label>
                  <select
                    value={propActionType}
                    onChange={(e) => setPropActionType(e.target.value as ActionType)}
                    style={{ width: '100%', cursor: 'pointer' }}
                  >
                    <option value="block_ip">block_ip (Firewall Rule)</option>
                    <option value="lock_account">lock_account (User Lockout)</option>
                    <option value="terminate_session">terminate_session</option>
                    <option value="review_audit">review_audit (Non-disruptive)</option>
                    <option value="notify_analyst">notify_analyst</option>
                  </select>
                </div>

                <div>
                  <label style={{ fontSize: '0.78rem', color: '#94a3b8', display: 'block', marginBottom: '0.25rem' }}>
                    Priority Urgency
                  </label>
                  <select
                    value={propPriority}
                    onChange={(e) => setPropPriority(e.target.value)}
                    style={{ width: '100%', cursor: 'pointer' }}
                  >
                    <option value="immediate">Immediate</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                  </select>
                </div>
              </div>

              <div>
                <label style={{ fontSize: '0.78rem', color: '#94a3b8', display: 'block', marginBottom: '0.25rem' }}>
                  Target IP / Username / Session
                </label>
                <input
                  type="text"
                  placeholder="e.g. 203.0.113.88 or test_attacker"
                  value={propTarget}
                  onChange={(e) => setPropTarget(e.target.value)}
                  style={{ width: '100%' }}
                  required
                />
                <span style={{ fontSize: '0.7rem', color: '#64748b', marginTop: '0.2rem', display: 'block' }}>
                  Safety check active: 127.0.0.1, default gateways, and root/administrator are blocked from targeting.
                </span>
              </div>

              <div>
                <label style={{ fontSize: '0.78rem', color: '#94a3b8', display: 'block', marginBottom: '0.25rem' }}>
                  Forensic Justification / Reason
                </label>
                <textarea
                  rows={2}
                  placeholder="Reason for proposing containment..."
                  value={propReason}
                  onChange={(e) => setPropReason(e.target.value)}
                  style={{ width: '100%', resize: 'vertical' }}
                  required
                />
              </div>

              <div style={{
                paddingTop: '0.75rem',
                borderTop: '1px solid #1e293b',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'flex-end',
                gap: '0.75rem'
              }}>
                <button
                  type="button"
                  onClick={() => setShowProposeModal(false)}
                  className="btn btn-secondary btn-sm"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={processing || !propTarget.trim()}
                  className="btn btn-primary btn-sm"
                >
                  {processing ? 'Submitting...' : 'Submit Proposal'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
