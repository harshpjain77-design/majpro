import React, { useState } from 'react';
import {
  AIAnalysisReport,
  Incident
} from '../types';
import { api } from '../services/api';
import {
  Sparkles,
  ShieldCheck,
  AlertTriangle,
  CheckCircle2,
  ExternalLink,
  ShieldAlert,
  ArrowRight,
  Cpu,
  Layers,
  Lock,
  RotateCcw,
  RefreshCw,
  Terminal,
  Zap
} from 'lucide-react';

interface AICopilotPanelProps {
  incidents: Incident[];
  selectedIncidentId: string | null;
  onSelectIncidentId: (id: string) => void;
  report: AIAnalysisReport | null;
  loading: boolean;
  onGenerateReport: (incidentId: string) => Promise<void>;
  onInspectEvent?: (eventId: string) => void;
  onNavigateToResponse?: () => void;
}

export const AICopilotPanel: React.FC<AICopilotPanelProps> = ({
  incidents,
  selectedIncidentId,
  onSelectIncidentId,
  report,
  loading,
  onGenerateReport,
  onInspectEvent,
  onNavigateToResponse,
}) => {
  const [selectedCitation, setSelectedCitation] = useState<string | null>(null);
  const [staging, setStaging] = useState<boolean>(false);
  const [stagingMessage, setStagingMessage] = useState<string | null>(null);

  const currentIncident = incidents.find((i) => i.incident_id === selectedIncidentId);

  const handleRunInvestigation = () => {
    if (selectedIncidentId) {
      onGenerateReport(selectedIncidentId);
    }
  };

  const getPriorityBadgeClass = (priority: string) => {
    switch (priority.toLowerCase()) {
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
      {/* Copilot Header & Selection Toolbar */}
      <div className="soc-card" style={{ padding: '1.25rem', background: '#0f172a' }}>
        <div style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '1rem'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <div style={{
              background: 'linear-gradient(135deg, #7c3aed 0%, #a855f7 100%)',
              padding: '0.5rem',
              borderRadius: '8px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              boxShadow: '0 0 16px rgba(168, 85, 247, 0.4)'
            }}>
              <Sparkles size={22} color="#ffffff" />
            </div>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <h3 style={{ fontSize: '1.15rem', fontWeight: 600, color: '#f8fafc' }}>
                  Evidence-Grounded AI Copilot
                </h3>
                <span className="badge badge-ai">Active Defense</span>
              </div>
              <p style={{ fontSize: '0.75rem', color: '#94a3b8' }}>
                Strict citation validation • Zero synthetic hallucinations • Input prompt injection defanging
              </p>
            </div>
          </div>

          {/* Incident Selector & Trigger Button */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <select
              value={selectedIncidentId || ''}
              onChange={(e) => onSelectIncidentId(e.target.value)}
              style={{ minWidth: '320px', cursor: 'pointer' }}
            >
              <option value="" disabled>Select Incident for AI Investigation...</option>
              {incidents.map((inc) => (
                <option key={inc.incident_id} value={inc.incident_id}>
                  [{inc.incident_id}] {inc.title.substring(0, 40)}... ({inc.severity.toUpperCase()}, Score: {inc.risk_score})
                </option>
              ))}
            </select>

            <button
              onClick={handleRunInvestigation}
              disabled={loading || !selectedIncidentId}
              className="btn btn-ai"
              style={{ minWidth: '180px' }}
            >
              {loading ? (
                <>
                  <RefreshCw size={15} className="spin" />
                  Synthesizing Report...
                </>
              ) : (
                <>
                  <Sparkles size={15} />
                  Run AI Investigation
                </>
              )}
            </button>
          </div>
        </div>
      </div>

      {/* Loading state indicator */}
      {loading && (
        <div className="soc-card" style={{ padding: '3rem', textAlign: 'center' }}>
          <Sparkles size={40} color="#a855f7" className="spin" style={{ margin: '0 auto 1rem' }} />
          <h4 style={{ fontSize: '1.1rem', color: '#f8fafc', marginBottom: '0.5rem' }}>
            Synthesizing Grounded Forensic Report...
          </h4>
          <div style={{ maxWidth: '480px', margin: '0 auto', fontSize: '0.8rem', color: '#94a3b8', display: 'flex', flexDirection: 'column', gap: '0.4rem', textAlign: 'left' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <CheckCircle2 size={14} color="#10b981" />
              <span>Scanning incident logs with PromptInjectionSanitizer</span>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <CheckCircle2 size={14} color="#10b981" />
              <span>Bounding untrusted evidence within XML envelopes</span>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <CheckCircle2 size={14} color="#10b981" />
              <span>Synthesizing Facts, MITRE ATT&CK Hypotheses & Mitigations</span>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <CheckCircle2 size={14} color="#10b981" />
              <span>Validating all citations against authorized evidence IDs</span>
            </div>
          </div>
        </div>
      )}

      {/* No Report Selected State */}
      {!loading && !report && (
        <div className="soc-card" style={{ padding: '3.5rem 2rem', textAlign: 'center' }}>
          <Layers size={44} color="#64748b" style={{ margin: '0 auto 1rem' }} />
          <h4 style={{ fontSize: '1.15rem', color: '#f8fafc', marginBottom: '0.5rem' }}>
            No AI Report Generated Yet
          </h4>
          <p style={{ color: '#94a3b8', maxWidth: '500px', margin: '0 auto 1.5rem', fontSize: '0.875rem' }}>
            Select an incident above and click <strong>"Run AI Investigation"</strong>. The AI Copilot will construct a comprehensive, citation-grounded forensic dossier mapping observed behavior to verified log evidence and MITRE ATT&CK techniques.
          </p>
          {incidents.length > 0 && !selectedIncidentId && (
            <button
              onClick={() => onSelectIncidentId(incidents[0].incident_id)}
              className="btn btn-secondary"
            >
              Select First Incident ({incidents[0].incident_id})
            </button>
          )}
        </div>
      )}

      {/* Report Rendered */}
      {!loading && report && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
          {/* Top Banner: Citation Validation Status */}
          <div
            className="soc-card"
            style={{
              padding: '1rem 1.25rem',
              background: report.citations_validated ? 'rgba(16, 185, 129, 0.08)' : 'rgba(239, 68, 68, 0.08)',
              border: report.citations_validated ? '1px solid rgba(16, 185, 129, 0.3)' : '1px solid rgba(239, 68, 68, 0.3)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              flexWrap: 'wrap',
              gap: '1rem'
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
              {report.citations_validated ? (
                <ShieldCheck size={26} color="#10b981" />
              ) : (
                <AlertTriangle size={26} color="#f43f5e" />
              )}
              <div>
                <div style={{ fontWeight: 600, fontSize: '0.95rem', color: report.citations_validated ? '#10b981' : '#f43f5e' }}>
                  {report.citations_validated
                    ? '100% Evidence Grounding Verified (Zero Hallucinations)'
                    : 'Citation Validation Anomaly Detected'}
                </div>
                <div style={{ fontSize: '0.75rem', color: '#94a3b8' }}>
                  Every cited fact and hypothesis strictly exists within authorized incident evidence ({report.valid_citation_ids.length} verified citation IDs).
                </div>
              </div>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', fontSize: '0.75rem', color: '#94a3b8' }}>
              <span>Model: <strong className="font-mono" style={{ color: '#c084fc' }}>{report.model_used}</strong></span>
              <span>•</span>
              <span>Incident: <strong className="font-mono" style={{ color: '#38bdf8' }}>{report.incident_id}</strong></span>
            </div>
          </div>

          {/* Prompt Injection Warnings (if any) */}
          {report.sanitization_warnings && report.sanitization_warnings.length > 0 && (
            <div
              className="soc-card"
              style={{
                padding: '1rem 1.25rem',
                background: 'rgba(245, 158, 11, 0.08)',
                border: '1px solid rgba(245, 158, 11, 0.3)',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: '#f59e0b', marginBottom: '0.5rem' }}>
                <ShieldAlert size={18} />
                <strong style={{ fontSize: '0.85rem' }}>Active Prompt Injection Defense Triggered:</strong>
              </div>
              <ul style={{ paddingLeft: '1.5rem', fontSize: '0.8rem', color: '#fcd34d' }}>
                {report.sanitization_warnings.map((warn, i) => (
                  <li key={i}>{warn}</li>
                ))}
              </ul>
            </div>
          )}

          {/* Executive Summary */}
          <div className="soc-card" style={{ padding: '1.25rem' }}>
            <h4 style={{ fontSize: '1rem', fontWeight: 600, color: '#f8fafc', marginBottom: '0.5rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <Terminal size={16} color="#38bdf8" />
              Executive Summary
            </h4>
            <p style={{ fontSize: '0.9rem', color: '#cbd5e1', lineHeight: 1.6 }}>
              {report.executive_summary}
            </p>
          </div>

          {/* Section 1: Verified Facts (Grounded) */}
          <div className="soc-card" style={{ padding: '1.25rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.85rem' }}>
              <h4 style={{ fontSize: '1rem', fontWeight: 600, color: '#f8fafc', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <ShieldCheck size={16} color="#10b981" />
                Verified Forensic Facts ({report.verified_facts.length})
              </h4>
              <span style={{ fontSize: '0.75rem', color: '#64748b' }}>
                Strict log ID citations required
              </span>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
              {report.verified_facts.map((fact, idx) => (
                <div
                  key={idx}
                  style={{
                    background: '#0f172a',
                    padding: '0.85rem 1rem',
                    borderRadius: '6px',
                    border: '1px solid #1e293b',
                    display: 'flex',
                    alignItems: 'flex-start',
                    justifyContent: 'space-between',
                    gap: '1rem'
                  }}
                >
                  <div style={{ flex: 1 }}>
                    <div style={{ display: 'flex', alignItems: 'flex-start', gap: '0.5rem' }}>
                      <span style={{ color: '#10b981', fontWeight: 700, fontSize: '0.85rem' }}>{idx + 1}.</span>
                      <span style={{ fontSize: '0.875rem', color: '#e2e8f0', lineHeight: 1.5 }}>{fact.fact}</span>
                    </div>
                  </div>

                  {/* Citation pills */}
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.35rem', justifyContent: 'flex-end', minWidth: '180px' }}>
                    {fact.citations.map((cite) => (
                      <button
                        key={cite}
                        onClick={() => {
                          setSelectedCitation(cite);
                          if (onInspectEvent) onInspectEvent(cite);
                        }}
                        className="font-mono"
                        style={{
                          background: 'rgba(56, 189, 248, 0.1)',
                          border: '1px solid rgba(56, 189, 248, 0.3)',
                          padding: '0.15rem 0.45rem',
                          borderRadius: '4px',
                          fontSize: '0.7rem',
                          color: '#38bdf8',
                          cursor: 'pointer',
                          display: 'inline-flex',
                          alignItems: 'center',
                          gap: '0.2rem'
                        }}
                        title={`Verified Evidence Citation: ${cite}. Click to inspect log.`}
                      >
                        [{cite}]
                        <ExternalLink size={10} />
                      </button>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Section 2: Threat Hypotheses & MITRE ATT&CK */}
          <div className="soc-card" style={{ padding: '1.25rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.85rem' }}>
              <h4 style={{ fontSize: '1rem', fontWeight: 600, color: '#f8fafc', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <Cpu size={16} color="#a855f7" />
                Threat Hypotheses & MITRE ATT&CK Mapping ({report.threat_hypotheses.length})
              </h4>
              <span style={{ fontSize: '0.75rem', color: '#64748b' }}>
                Confidence-weighted analytical deductions
              </span>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
              {report.threat_hypotheses.map((hyp, idx) => (
                <div
                  key={idx}
                  style={{
                    background: '#0f172a',
                    padding: '1rem',
                    borderRadius: '6px',
                    border: '1px solid #1e293b',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.5rem' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                      {hyp.mitre_technique && (
                        <span className="badge badge-ai font-mono" style={{ fontSize: '0.75rem' }}>
                          MITRE {hyp.mitre_technique}
                        </span>
                      )}
                      <strong style={{ fontSize: '0.9rem', color: '#f8fafc' }}>
                        Hypothesis {idx + 1}
                      </strong>
                    </div>

                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                      <span style={{ fontSize: '0.75rem', color: '#94a3b8' }}>Confidence:</span>
                      <strong style={{ fontSize: '0.85rem', color: '#a855f7' }}>
                        {Math.round(hyp.confidence * 100)}%
                      </strong>
                    </div>
                  </div>

                  <p style={{ fontSize: '0.875rem', color: '#cbd5e1', marginBottom: '0.65rem' }}>
                    {hyp.hypothesis}
                  </p>

                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    <span style={{ fontSize: '0.72rem', color: '#64748b' }}>Supporting Evidence:</span>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.35rem' }}>
                      {hyp.supporting_citations.map((cite) => (
                        <span
                          key={cite}
                          className="font-mono"
                          style={{
                            background: '#1e293b',
                            padding: '0.1rem 0.4rem',
                            borderRadius: '3px',
                            fontSize: '0.7rem',
                            color: '#94a3b8'
                          }}
                        >
                          [{cite}]
                        </span>
                      ))}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Section 3: Actionable Recommendations */}
          <div className="soc-card" style={{ padding: '1.25rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.85rem' }}>
              <h4 style={{ fontSize: '1rem', fontWeight: 600, color: '#f8fafc', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <Lock size={16} color="#38bdf8" />
                Actionable Defense Recommendations ({report.actionable_recommendations.length})
              </h4>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <button
                  disabled={staging}
                  className="btn btn-ai btn-sm"
                  onClick={async () => {
                    try {
                      setStaging(true);
                      setStagingMessage(null);
                      const res = await api.stageIncidentActions(report.incident_id);
                      setStagingMessage(`Successfully staged ${res.length} recommendations into the Response Queue!`);
                      if (onNavigateToResponse) {
                        setTimeout(onNavigateToResponse, 1500);
                      }
                    } catch (err: any) {
                      setStagingMessage(`Staging failed: ${err.message}`);
                    } finally {
                      setStaging(false);
                    }
                  }}
                >
                  <Zap size={13} />
                  {staging ? 'Staging...' : 'Stage All for Containment'}
                </button>
                <span className="badge badge-ai" style={{ fontSize: '0.7rem' }}>
                  Phase 8 Response Engine Interface
                </span>
              </div>
            </div>

            {stagingMessage && (
              <div style={{
                background: 'rgba(16, 185, 129, 0.1)',
                border: '1px solid rgba(16, 185, 129, 0.4)',
                padding: '0.5rem 0.75rem',
                borderRadius: '4px',
                color: '#10b981',
                fontSize: '0.8rem',
                marginBottom: '0.75rem'
              }}>
                {stagingMessage}
              </div>
            )}

            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
              {report.actionable_recommendations.map((rec, idx) => (
                <div
                  key={idx}
                  style={{
                    background: '#0f172a',
                    padding: '1rem',
                    borderRadius: '6px',
                    border: '1px solid #1e293b',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    gap: '1rem'
                  }}
                >
                  <div style={{ flex: 1 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.35rem' }}>
                      <span className={`badge ${getPriorityBadgeClass(rec.priority)}`}>
                        {rec.priority}
                      </span>
                      <span className="font-mono" style={{ fontSize: '0.8rem', color: '#38bdf8', fontWeight: 600 }}>
                        {rec.action_type}
                      </span>
                      {rec.reversible && (
                        <span className="badge badge-neutral" style={{ fontSize: '0.65rem', display: 'flex', alignItems: 'center', gap: '0.2rem' }}>
                          <RotateCcw size={10} />
                          Reversible
                        </span>
                      )}
                    </div>

                    <p style={{ fontSize: '0.875rem', color: '#f1f5f9', margin: '0.25rem 0' }}>
                      {rec.recommendation}
                    </p>

                    {rec.parameters && Object.keys(rec.parameters).length > 0 && (
                      <div style={{ fontSize: '0.75rem', color: '#64748b', marginTop: '0.35rem' }}>
                        Params: <span className="font-mono" style={{ color: '#94a3b8' }}>{JSON.stringify(rec.parameters)}</span>
                      </div>
                    )}
                  </div>

                  {/* Stage Response Button */}
                  <div>
                    <button
                      className="btn btn-secondary btn-sm"
                      title="Propose this action to the Phase 8 Response Engine with safety allowlists and approval gating."
                      onClick={async () => {
                        try {
                          const target = rec.parameters?.ip || rec.parameters?.username || rec.parameters?.target || 'unknown_target';
                          const res = await api.proposeResponseAction({
                            incident_id: report.incident_id,
                            action_type: rec.action_type,
                            target: String(target),
                            parameters: rec.parameters,
                            priority: rec.priority,
                            reason: rec.recommendation,
                          });
                          if (res.status === 'REJECTED') {
                            alert(`Action rejected by Safety Guard: ${res.error_message}`);
                          } else {
                            alert(`Action staged in Response Engine (${res.action_id}). Opening Response Queue...`);
                            if (onNavigateToResponse) onNavigateToResponse();
                          }
                        } catch (err: any) {
                          alert(`Error proposing action: ${err.message}`);
                        }
                      }}
                    >
                      <ArrowRight size={13} />
                      Stage Action
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>

        </div>
      )}
    </div>
  );
};
