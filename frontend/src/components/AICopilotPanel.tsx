import React, { useState, useEffect, useRef } from 'react';
import {
  AIAnalysisReport,
  AIChatMessage,
  AIStatusResponse,
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
  Zap,
  MessageSquare,
  Send,
  Bot,
  User,
  Sliders,
  Check,
  HelpCircle,
  FileText
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
  // Tab view: 'report' for structured forensic synthesis, 'chat' for interactive analyst Q&A
  const [activeTab, setActiveTab] = useState<'report' | 'chat'>('report');
  const [selectedCitation, setSelectedCitation] = useState<string | null>(null);
  const [staging, setStaging] = useState<boolean>(false);
  const [stagingMessage, setStagingMessage] = useState<string | null>(null);

  // Interactive Chat State
  const [chatMessages, setChatMessages] = useState<AIChatMessage[]>([
    {
      id: 'welcome',
      sender: 'assistant',
      text: "Hello Analyst! I am your ThreadGrid Explainable AI Copilot. Ask me any question regarding this incident's attack progression, forensic citations, MITRE techniques, or containment options.",
      timestamp: new Date().toLocaleTimeString(),
    },
  ]);
  const [chatInput, setChatInput] = useState<string>('');
  const [chatLoading, setChatLoading] = useState<boolean>(false);
  const [aiStatus, setAiStatus] = useState<AIStatusResponse | null>(null);
  const chatBottomRef = useRef<HTMLDivElement>(null);

  // Load AI Status
  useEffect(() => {
    api.getAIStatus().then(setAiStatus).catch(() => null);
  }, []);

  // Auto-scroll chat to bottom
  useEffect(() => {
    if (activeTab === 'chat') {
      chatBottomRef.current?.scrollIntoView({ behavior: 'smooth' });
    }
  }, [chatMessages, activeTab]);

  const currentIncident = incidents.find((i) => i.incident_id === selectedIncidentId);

  const handleRunInvestigation = () => {
    if (selectedIncidentId) {
      onGenerateReport(selectedIncidentId);
    }
  };

  const handleSendMessage = async (textToSend?: string) => {
    const query = textToSend || chatInput;
    if (!query.trim() || !selectedIncidentId) return;

    const userMsg: AIChatMessage = {
      id: `user-${Date.now()}`,
      sender: 'user',
      text: query,
      timestamp: new Date().toLocaleTimeString(),
    };
    setChatMessages((prev) => [...prev, userMsg]);
    setChatInput('');
    setChatLoading(true);

    try {
      const historyPayload = chatMessages.map((m) => ({
        role: m.sender === 'user' ? 'user' : 'assistant',
        content: m.text,
      }));

      const res = await api.chatWithAI({
        incident_id: selectedIncidentId,
        prompt: query,
        history: historyPayload,
      });
      const botMsg: AIChatMessage = {
        id: `bot-${Date.now()}`,
        sender: 'assistant',
        text: res.answer,
        timestamp: new Date().toLocaleTimeString(),
        model_used: res.model_used,
        citations: res.citations,
        suggested_actions: res.suggested_actions,
        is_live_gemini: res.is_live_gemini,
      };
      setChatMessages((prev) => [...prev, botMsg]);
    } catch (err: any) {
      const errMsg: AIChatMessage = {
        id: `err-${Date.now()}`,
        sender: 'assistant',
        text: `Failed to query AI: ${err?.message || err}`,
        timestamp: new Date().toLocaleTimeString(),
      };
      setChatMessages((prev) => [...prev, errMsg]);
    } finally {
      setChatLoading(false);
    }
  };

  const quickPrompts = [
    { label: '🛡️ Explain Attack Narrative', prompt: 'Explain the attack narrative and how the attacker breached this asset step-by-step.' },
    { label: '📋 Draft CISO Briefing', prompt: 'Draft an executive briefing for the CISO summarizing risk, impacted assets, and containment status.' },
    { label: '⚡ Recommend Containment Plan', prompt: 'What immediate containment and remediation actions should be executed for this incident?' },
    { label: '🔍 Verify Evidence Citations', prompt: 'List the verified forensic evidence and explain why this activity was flagged.' },
  ];

  const getPriorityBadgeClass = (priority: string) => {
    switch (priority.toLowerCase()) {
      case 'immediate':
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

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      {/* ------------------------------------------------------------------- */}
      {/* Copilot Header & Selection Toolbar */}
      {/* ------------------------------------------------------------------- */}
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
                  Explainable AI Investigation Copilot
                </h3>
                {aiStatus?.gemini_configured ? (
                  <span
                    style={{
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: '0.3rem',
                      padding: '0.15rem 0.55rem',
                      borderRadius: '9999px',
                      fontSize: '0.7rem',
                      fontWeight: 600,
                      backgroundColor: 'rgba(56, 189, 248, 0.18)',
                      color: '#38bdf8',
                      border: '1px solid rgba(56, 189, 248, 0.4)',
                    }}
                  >
                    <Sparkles size={11} />
                    Gemini 2.5 Flash Enabled
                  </span>
                ) : (
                  <span className="badge badge-ai">Local Synthesizer</span>
                )}
              </div>
              <p style={{ fontSize: '0.75rem', color: '#94a3b8', margin: '0.15rem 0 0 0' }}>
                Strict citation validation • Zero hallucinations • MITRE ATT&CK alignment • Context-aware response staging
              </p>
            </div>
          </div>

          {/* Incident Selector & Trigger Button */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <select
              value={selectedIncidentId || ''}
              onChange={(e) => onSelectIncidentId(e.target.value)}
              style={{
                minWidth: '320px',
                cursor: 'pointer',
                backgroundColor: '#1e293b',
                color: '#f8fafc',
                border: '1px solid rgba(255, 255, 255, 0.1)',
                padding: '0.45rem 0.75rem',
                borderRadius: '6px',
                fontSize: '0.8125rem',
              }}
            >
              <option value="" disabled>Select Incident for AI Investigation...</option>
              {incidents.map((inc) => (
                <option key={inc.incident_id} value={inc.incident_id}>
                  [{inc.incident_id}] {inc.title.substring(0, 42)}... ({inc.severity.toUpperCase()}, Score: {inc.risk_score})
                </option>
              ))}
            </select>

            <button
              onClick={handleRunInvestigation}
              disabled={loading || !selectedIncidentId}
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '0.4rem',
                padding: '0.5rem 1rem',
                backgroundColor: '#7c3aed',
                color: '#ffffff',
                border: 'none',
                borderRadius: '6px',
                fontSize: '0.8125rem',
                fontWeight: 600,
                cursor: 'pointer',
                transition: 'background-color 0.15s ease',
              }}
              onMouseEnter={(e) => { e.currentTarget.style.backgroundColor = '#6d28d9'; }}
              onMouseLeave={(e) => { e.currentTarget.style.backgroundColor = '#7c3aed'; }}
            >
              {loading ? (
                <>
                  <RefreshCw size={15} className="animate-spin" />
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

        {/* Navigation Tabs: Structured Report vs Interactive Chat */}
        <div style={{ display: 'flex', gap: '0.5rem', marginTop: '1.25rem', borderTop: '1px solid rgba(255, 255, 255, 0.08)', paddingTop: '0.75rem' }}>
          <button
            onClick={() => setActiveTab('report')}
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '0.4rem',
              padding: '0.4rem 0.85rem',
              borderRadius: '6px',
              fontSize: '0.8rem',
              fontWeight: 600,
              backgroundColor: activeTab === 'report' ? '#7c3aed' : '#1e293b',
              color: activeTab === 'report' ? '#ffffff' : '#94a3b8',
              border: activeTab === 'report' ? '1px solid #a855f7' : '1px solid rgba(255, 255, 255, 0.08)',
              cursor: 'pointer',
            }}
          >
            <FileText size={14} />
            Structured Forensic Report
          </button>

          <button
            onClick={() => setActiveTab('chat')}
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '0.4rem',
              padding: '0.4rem 0.85rem',
              borderRadius: '6px',
              fontSize: '0.8rem',
              fontWeight: 600,
              backgroundColor: activeTab === 'chat' ? '#7c3aed' : '#1e293b',
              color: activeTab === 'chat' ? '#ffffff' : '#94a3b8',
              border: activeTab === 'chat' ? '1px solid #a855f7' : '1px solid rgba(255, 255, 255, 0.08)',
              cursor: 'pointer',
            }}
          >
            <MessageSquare size={14} />
            Interactive Analyst Q&A Copilot
          </button>
        </div>
      </div>

      {/* ------------------------------------------------------------------- */}
      {/* TAB 2: INTERACTIVE ANALYST Q&A CHAT */}
      {/* ------------------------------------------------------------------- */}
      {activeTab === 'chat' && (
        <div
          className="soc-card"
          style={{
            padding: '1.25rem',
            background: '#0f172a',
            display: 'flex',
            flexDirection: 'column',
            gap: '1rem',
            minHeight: '480px',
          }}
        >
          {/* Quick Prompt Suggestions */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
            <span style={{ fontSize: '0.75rem', color: '#94a3b8', display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
              <Zap size={13} color="#eab308" />
              Suggested Queries:
            </span>
            {quickPrompts.map((qp, idx) => (
              <button
                key={idx}
                onClick={() => handleSendMessage(qp.prompt)}
                disabled={chatLoading}
                style={{
                  padding: '0.3rem 0.65rem',
                  backgroundColor: '#1e293b',
                  color: '#e2e8f0',
                  border: '1px solid rgba(255, 255, 255, 0.1)',
                  borderRadius: '9999px',
                  fontSize: '0.75rem',
                  cursor: 'pointer',
                  transition: 'all 0.15s ease',
                }}
                onMouseEnter={(e) => {
                  e.currentTarget.style.backgroundColor = 'rgba(124, 58, 237, 0.2)';
                  e.currentTarget.style.borderColor = '#7c3aed';
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.backgroundColor = '#1e293b';
                  e.currentTarget.style.borderColor = 'rgba(255, 255, 255, 0.1)';
                }}
              >
                {qp.label}
              </button>
            ))}
          </div>

          {/* Chat Message Scrollable Container */}
          <div
            style={{
              flex: 1,
              maxHeight: '420px',
              overflowY: 'auto',
              display: 'flex',
              flexDirection: 'column',
              gap: '0.85rem',
              padding: '0.5rem',
              backgroundColor: '#090d16',
              borderRadius: '8px',
              border: '1px solid rgba(255, 255, 255, 0.05)',
            }}
          >
            {chatMessages.map((msg) => (
              <div
                key={msg.id}
                style={{
                  display: 'flex',
                  gap: '0.75rem',
                  alignSelf: msg.sender === 'user' ? 'flex-end' : 'flex-start',
                  maxWidth: '85%',
                }}
              >
                {msg.sender === 'assistant' && (
                  <div
                    style={{
                      width: '28px',
                      height: '28px',
                      borderRadius: '50%',
                      backgroundColor: 'rgba(124, 58, 237, 0.25)',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      color: '#a855f7',
                      flexShrink: 0,
                    }}
                  >
                    <Bot size={16} />
                  </div>
                )}

                <div
                  style={{
                    backgroundColor: msg.sender === 'user' ? '#7c3aed' : '#1e293b',
                    color: '#f8fafc',
                    padding: '0.75rem 1rem',
                    borderRadius: '8px',
                    fontSize: '0.8125rem',
                    lineHeight: '1.45',
                    border: msg.sender === 'user' ? 'none' : '1px solid rgba(255, 255, 255, 0.06)',
                  }}
                >
                  {/* Header with Model Badge */}
                  {msg.sender === 'assistant' && msg.model_used && (
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.4rem', borderBottom: '1px solid rgba(255, 255, 255, 0.08)', paddingBottom: '0.3rem' }}>
                      <span style={{ fontSize: '0.7rem', fontWeight: 600, color: msg.is_live_gemini ? '#38bdf8' : '#a855f7' }}>
                        {msg.model_used}
                      </span>
                      <span style={{ fontSize: '0.65rem', color: '#64748b' }}>{msg.timestamp}</span>
                    </div>
                  )}

                  {/* Message Prose with Markdown Whitespace */}
                  <div style={{ whiteSpace: 'pre-wrap' }}>{msg.text}</div>

                  {/* Citations Chips */}
                  {msg.citations && msg.citations.length > 0 && (
                    <div style={{ marginTop: '0.65rem', paddingTop: '0.4rem', borderTop: '1px solid rgba(255, 255, 255, 0.08)' }}>
                      <div style={{ fontSize: '0.68rem', color: '#94a3b8', textTransform: 'uppercase', marginBottom: '0.25rem', fontWeight: 600 }}>
                        Supporting Forensic Evidence:
                      </div>
                      <div style={{ display: 'flex', gap: '0.35rem', flexWrap: 'wrap' }}>
                        {msg.citations.map((cId) => (
                          <button
                            key={cId}
                            onClick={() => onInspectEvent && onInspectEvent(cId)}
                            style={{
                              fontFamily: 'monospace',
                              fontSize: '0.7rem',
                              padding: '0.15rem 0.45rem',
                              backgroundColor: 'rgba(56, 189, 248, 0.15)',
                              color: '#38bdf8',
                              border: '1px solid rgba(56, 189, 248, 0.3)',
                              borderRadius: '4px',
                              cursor: 'pointer',
                            }}
                          >
                            {cId}
                          </button>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Suggested Follow-up Actions */}
                  {msg.suggested_actions && msg.suggested_actions.length > 0 && (
                    <div style={{ display: 'flex', gap: '0.35rem', marginTop: '0.5rem', flexWrap: 'wrap' }}>
                      {msg.suggested_actions.map((act, aIdx) => (
                        <button
                          key={aIdx}
                          onClick={() => handleSendMessage(act)}
                          style={{
                            fontSize: '0.7rem',
                            padding: '0.15rem 0.5rem',
                            backgroundColor: 'rgba(255, 255, 255, 0.08)',
                            color: '#cbd5e1',
                            border: '1px solid rgba(255, 255, 255, 0.1)',
                            borderRadius: '4px',
                            cursor: 'pointer',
                          }}
                        >
                          → {act}
                        </button>
                      ))}
                    </div>
                  )}
                </div>

                {msg.sender === 'user' && (
                  <div
                    style={{
                      width: '28px',
                      height: '28px',
                      borderRadius: '50%',
                      backgroundColor: 'rgba(56, 189, 248, 0.25)',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      color: '#38bdf8',
                      flexShrink: 0,
                    }}
                  >
                    <User size={16} />
                  </div>
                )}
              </div>
            ))}

            {chatLoading && (
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: '#94a3b8', fontSize: '0.8rem', padding: '0.5rem' }}>
                <RefreshCw size={14} className="animate-spin" />
                Thinking & verifying grounded citations against database...
              </div>
            )}
            <div ref={chatBottomRef} />
          </div>

          {/* Chat Input Bar */}
          <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
            <input
              type="text"
              value={chatInput}
              onChange={(e) => setChatInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter' && !e.shiftKey) {
                  e.preventDefault();
                  handleSendMessage();
                }
              }}
              placeholder="Ask AI Copilot about this incident, attacker techniques, or containment steps..."
              style={{
                flex: 1,
                backgroundColor: '#1e293b',
                color: '#f8fafc',
                border: '1px solid rgba(255, 255, 255, 0.1)',
                padding: '0.55rem 0.85rem',
                borderRadius: '6px',
                fontSize: '0.8125rem',
                outline: 'none',
              }}
            />
            <button
              onClick={() => handleSendMessage()}
              disabled={chatLoading || !chatInput.trim()}
              style={{
                padding: '0.55rem 1rem',
                backgroundColor: '#7c3aed',
                color: '#ffffff',
                border: 'none',
                borderRadius: '6px',
                fontSize: '0.8125rem',
                fontWeight: 600,
                cursor: 'pointer',
                display: 'inline-flex',
                alignItems: 'center',
                gap: '0.35rem',
              }}
            >
              <Send size={14} />
              Send
            </button>
          </div>
        </div>
      )}

      {/* ------------------------------------------------------------------- */}
      {/* TAB 1: STRUCTURED FORENSIC REPORT */}
      {/* ------------------------------------------------------------------- */}
      {activeTab === 'report' && (
        <>
          {loading && (
            <div className="soc-card" style={{ padding: '2.5rem', textAlign: 'center', background: '#0f172a' }}>
              <div className="spin" style={{ display: 'inline-block', marginBottom: '1rem' }}>
                <Sparkles size={36} color="#a855f7" />
              </div>
              <h4 style={{ color: '#f8fafc', marginBottom: '0.5rem' }}>
                Performing Evidence-Grounded AI Synthesis
              </h4>
              <p style={{ color: '#94a3b8', fontSize: '0.85rem', maxWidth: '480px', margin: '0 auto' }}>
                Retrieving chronological log events, defanging potential prompt injections, and verifying citation proofs...
              </p>
            </div>
          )}

          {!report && !loading && (
            <div className="soc-card" style={{ padding: '2.5rem', textAlign: 'center', background: '#0f172a' }}>
              <Terminal size={36} color="#64748b" style={{ margin: '0 auto 1rem auto' }} />
              <h4 style={{ color: '#94a3b8', marginBottom: '0.5rem' }}>No AI Report Generated Yet</h4>
              <p style={{ color: '#64748b', fontSize: '0.85rem' }}>
                Select an incident from the queue above and click "Run AI Investigation" to begin.
              </p>
            </div>
          )}

          {report && !loading && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>

              {/* 1. Executive Summary & Verification Banner */}
              <div className="soc-card" style={{ padding: '1.25rem', background: '#0f172a' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.75rem' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    <h4 style={{ fontSize: '1rem', fontWeight: 600, color: '#f8fafc', margin: 0 }}>
                      Executive Triage Summary
                    </h4>
                    <span className="badge badge-neutral" style={{ fontSize: '0.7rem' }}>
                      Model: {report.model_used}
                    </span>
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    {report.citations_validated ? (
                      <span className="badge badge-low" style={{ display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
                        <ShieldCheck size={12} />
                        100% Citations Verified
                      </span>
                    ) : (
                      <span className="badge badge-high" style={{ display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
                        <AlertTriangle size={12} />
                        Unverified Citations Detected
                      </span>
                    )}
                  </div>
                </div>

                <p style={{ fontSize: '0.875rem', color: '#cbd5e1', lineHeight: '1.5' }}>
                  {report.executive_summary}
                </p>

                {report.sanitization_warnings && report.sanitization_warnings.length > 0 && (
                  <div style={{
                    marginTop: '0.75rem',
                    padding: '0.5rem 0.75rem',
                    backgroundColor: 'rgba(234, 179, 8, 0.1)',
                    border: '1px solid rgba(234, 179, 8, 0.3)',
                    borderRadius: '6px',
                    fontSize: '0.75rem',
                    color: '#facc15'
                  }}>
                    <strong>Prompt Defense Triggered:</strong> Untrusted text fields were defanged to prevent jailbreaks.
                  </div>
                )}
              </div>

              {/* 2. Verified Facts Grounded in Evidence */}
              <div className="soc-card" style={{ padding: '1.25rem', background: '#0f172a' }}>
                <h4 style={{
                  fontSize: '0.95rem',
                  fontWeight: 600,
                  color: '#f8fafc',
                  marginBottom: '1rem',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.5rem'
                }}>
                  <CheckCircle2 size={16} color="#10b981" />
                  Verified Forensic Facts (Strict Citations)
                </h4>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                  {report.verified_facts.map((fact, idx) => (
                    <div
                      key={idx}
                      style={{
                        padding: '0.85rem 1rem',
                        backgroundColor: '#1e293b',
                        borderRadius: '6px',
                        border: '1px solid rgba(255, 255, 255, 0.05)',
                        display: 'flex',
                        alignItems: 'flex-start',
                        justifyContent: 'space-between',
                        gap: '1rem'
                      }}
                    >
                      <div style={{ flex: 1, fontSize: '0.85rem', color: '#e2e8f0', lineHeight: '1.4' }}>
                        {fact.fact}
                      </div>

                      {/* Citation Proof Chips */}
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem', flexWrap: 'wrap' }}>
                        {fact.citations.map((cId) => (
                          <button
                            key={cId}
                            onClick={() => onInspectEvent && onInspectEvent(cId)}
                            style={{
                              fontFamily: 'monospace',
                              fontSize: '0.7rem',
                              padding: '0.15rem 0.45rem',
                              backgroundColor: 'rgba(56, 189, 248, 0.15)',
                              color: '#38bdf8',
                              border: '1px solid rgba(56, 189, 248, 0.3)',
                              borderRadius: '4px',
                              cursor: 'pointer',
                              display: 'inline-flex',
                              alignItems: 'center',
                              gap: '0.2rem'
                            }}
                            title={`Inspect event or alert ${cId}`}
                          >
                            {cId}
                            <ExternalLink size={9} />
                          </button>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* 3. Threat Hypotheses & MITRE ATT&CK Mapping */}
              <div className="soc-card" style={{ padding: '1.25rem', background: '#0f172a' }}>
                <h4 style={{
                  fontSize: '0.95rem',
                  fontWeight: 600,
                  color: '#f8fafc',
                  marginBottom: '1rem',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.5rem'
                }}>
                  <Cpu size={16} color="#a855f7" />
                  Threat Hypotheses & MITRE ATT&CK Mapping
                </h4>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                  {report.threat_hypotheses.map((hyp, idx) => (
                    <div
                      key={idx}
                      style={{
                        padding: '0.85rem 1rem',
                        backgroundColor: '#1e293b',
                        borderRadius: '6px',
                        border: '1px solid rgba(255, 255, 255, 0.05)',
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.35rem' }}>
                        <span style={{ fontSize: '0.75rem', fontWeight: 600, color: '#a855f7' }}>
                          MITRE: {hyp.mitre_technique || 'Unmapped'}
                        </span>
                        <span style={{ fontSize: '0.75rem', color: '#10b981', fontWeight: 600 }}>
                          Confidence: {(hyp.confidence * 100).toFixed(0)}%
                        </span>
                      </div>

                      <div style={{ fontSize: '0.85rem', color: '#e2e8f0', lineHeight: '1.4' }}>
                        {hyp.hypothesis}
                      </div>

                      {hyp.supporting_citations && hyp.supporting_citations.length > 0 && (
                        <div style={{ display: 'flex', gap: '0.35rem', marginTop: '0.4rem', flexWrap: 'wrap' }}>
                          {hyp.supporting_citations.map((cId) => (
                            <span
                              key={cId}
                              className="font-mono"
                              style={{
                                fontSize: '0.65rem',
                                color: '#94a3b8',
                                backgroundColor: 'rgba(255, 255, 255, 0.05)',
                                padding: '0.1rem 0.35rem',
                                borderRadius: '3px'
                              }}
                            >
                              {cId}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>

              {/* 4. Actionable Response Recommendations */}
              <div className="soc-card" style={{ padding: '1.25rem', background: '#0f172a' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1rem' }}>
                  <h4 style={{
                    fontSize: '0.95rem',
                    fontWeight: 600,
                    color: '#f8fafc',
                    margin: 0,
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.5rem'
                  }}>
                    <ShieldAlert size={16} color="#ef4444" />
                    Human-in-the-Loop Containment Actions ({report.actionable_recommendations.length})
                  </h4>

                  <button
                    className="btn btn-primary btn-sm"
                    disabled={staging}
                    onClick={async () => {
                      try {
                        setStaging(true);
                        const staged = await api.stageIncidentActions(report.incident_id);
                        setStagingMessage(`Successfully staged ${staged.length} actions in Response Queue!`);
                        if (onNavigateToResponse) {
                          setTimeout(() => onNavigateToResponse(), 1200);
                        }
                      } catch (err: any) {
                        alert(`Failed to stage actions: ${err.message}`);
                      } finally {
                        setStaging(false);
                      }
                    }}
                  >
                    <ArrowRight size={13} />
                    {staging ? 'Staging All...' : 'Stage All for Containment'}
                  </button>
                </div>

                {stagingMessage && (
                  <div style={{
                    padding: '0.6rem 0.85rem',
                    backgroundColor: 'rgba(16, 185, 129, 0.15)',
                    border: '1px solid rgba(16, 185, 129, 0.3)',
                    borderRadius: '6px',
                    color: '#10b981',
                    fontSize: '0.8rem',
                    marginBottom: '1rem',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.4rem'
                  }}>
                    <CheckCircle2 size={14} />
                    {stagingMessage}
                  </div>
                )}

                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                  {report.actionable_recommendations.map((rec, idx) => (
                    <div
                      key={idx}
                      style={{
                        padding: '0.85rem 1rem',
                        backgroundColor: '#1e293b',
                        borderRadius: '6px',
                        border: '1px solid rgba(255, 255, 255, 0.05)',
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

                      {/* Stage Individual Action Button */}
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
        </>
      )}
    </div>
  );
};
