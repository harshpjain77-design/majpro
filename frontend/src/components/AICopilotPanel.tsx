import React, { useState, useEffect, useRef } from 'react';
import {
  AIAnalysisReport,
  AIChatMessage,
  AIStatusResponse,
  ChatSession,
  Incident
} from '../types';
import { api } from '../services/api';
import { chatStorage } from '../services/chatStorage';
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
  FileText,
  Plus,
  Trash2,
  Edit2,
  Search,
  MessageCircle,
  X
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

  // Interactive Chat & Persistent Session State
  const [sessions, setSessions] = useState<ChatSession[]>(() => chatStorage.getSessions());
  const [activeSessionId, setActiveSessionId] = useState<string>(() => chatStorage.getActiveSessionId());
  const [chatSearchQuery, setChatSearchQuery] = useState<string>('');
  const [editingSessionId, setEditingSessionId] = useState<string | null>(null);
  const [editTitle, setEditTitle] = useState<string>('');
  
  const [chatInput, setChatInput] = useState<string>('');
  const [chatLoading, setChatLoading] = useState<boolean>(false);
  const [aiStatus, setAiStatus] = useState<AIStatusResponse | null>(null);
  const chatBottomRef = useRef<HTMLDivElement>(null);

  // Sync with persistent chatStorage
  useEffect(() => {
    const updateFromStorage = () => {
      setSessions(chatStorage.getSessions());
      setActiveSessionId(chatStorage.getActiveSessionId());
    };
    const unsubscribe = chatStorage.subscribe(updateFromStorage);
    return unsubscribe;
  }, []);

  const activeSession = sessions.find((s) => s.id === activeSessionId) || sessions[0] || chatStorage.getActiveSession();
  const chatMessages = activeSession?.messages || [];

  // Load AI Status
  useEffect(() => {
    api.getAIStatus().then(setAiStatus).catch(() => null);
  }, []);

  // Auto-scroll chat to bottom
  useEffect(() => {
    if (activeTab === 'chat') {
      chatBottomRef.current?.scrollIntoView({ behavior: 'smooth' });
    }
  }, [chatMessages, activeTab, activeSessionId]);

  const currentIncident = incidents.find((i) => i.incident_id === (activeSession?.incident_id || selectedIncidentId));

  const handleRunInvestigation = () => {
    if (selectedIncidentId) {
      onGenerateReport(selectedIncidentId);
    }
  };

  const handleNewChat = () => {
    const created = chatStorage.createSession(
      selectedIncidentId || 'general',
      currentIncident?.title
    );
    setActiveSessionId(created.id);
  };

  const handleDeleteSession = (sessionId: string, e: React.MouseEvent) => {
    e.stopPropagation();
    const nextSession = chatStorage.deleteSession(sessionId);
    setActiveSessionId(nextSession.id);
  };

  const handleStartRename = (session: ChatSession, e: React.MouseEvent) => {
    e.stopPropagation();
    setEditingSessionId(session.id);
    setEditTitle(session.title);
  };

  const handleSaveRename = (sessionId: string, e: React.MouseEvent | React.KeyboardEvent) => {
    e.stopPropagation();
    if (editTitle.trim()) {
      chatStorage.renameSession(sessionId, editTitle.trim());
    }
    setEditingSessionId(null);
  };

  const handleClearChat = () => {
    if (activeSession) {
      chatStorage.clearSessionMessages(activeSession.id);
    }
  };

  const handleSessionIncidentChange = (newIncidentId: string) => {
    if (!activeSession) return;
    const targetInc = incidents.find((i) => i.incident_id === newIncidentId);
    chatStorage.updateSessionIncident(
      activeSession.id,
      newIncidentId,
      targetInc?.title
    );
    if (newIncidentId !== 'general') {
      onSelectIncidentId(newIncidentId);
    }
  };

  const handleSendMessage = async (textToSend?: string) => {
    const query = textToSend || chatInput;
    if (!query.trim() || chatLoading || !activeSession) return;

    const userMsg: AIChatMessage = {
      id: `user-${Date.now()}`,
      sender: 'user',
      text: query,
      timestamp: new Date().toLocaleTimeString(),
    };

    // Save user message immediately to persistent storage
    chatStorage.addMessageToSession(activeSession.id, userMsg);
    setChatInput('');
    setChatLoading(true);

    try {
      const historyPayload = activeSession.messages.map((m) => ({
        role: m.sender === 'user' ? 'user' : 'assistant',
        content: m.text,
      }));

      const res = await api.chatWithAI({
        incident_id: activeSession.incident_id || selectedIncidentId || 'general',
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

      // Save bot response to persistent storage
      chatStorage.addMessageToSession(activeSession.id, botMsg);
    } catch (err: any) {
      const errMsg: AIChatMessage = {
        id: `err-${Date.now()}`,
        sender: 'assistant',
        text: `Failed to query AI: ${err?.message || err}`,
        timestamp: new Date().toLocaleTimeString(),
      };
      chatStorage.addMessageToSession(activeSession.id, errMsg);
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
      <div className="soc-card" style={{ padding: '1.25rem' }}>
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
                <h3 style={{ fontSize: '1.15rem', fontWeight: 600, color: 'var(--text-primary)' }}>
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
                      color: '#0284c7',
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
              <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', margin: '0.15rem 0 0 0' }}>
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
                backgroundColor: 'var(--bg-input)',
                color: 'var(--text-primary)',
                border: '1px solid var(--border-input)',
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
        <div style={{ display: 'flex', gap: '0.5rem', marginTop: '1.25rem', borderTop: '1px solid var(--border-color)', paddingTop: '0.75rem' }}>
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
              backgroundColor: activeTab === 'report' ? 'var(--color-ai)' : 'var(--bg-tertiary)',
              color: activeTab === 'report' ? '#ffffff' : 'var(--text-secondary)',
              border: activeTab === 'report' ? '1px solid var(--color-ai-border)' : '1px solid var(--border-color)',
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
              backgroundColor: activeTab === 'chat' ? 'var(--color-ai)' : 'var(--bg-tertiary)',
              color: activeTab === 'chat' ? '#ffffff' : 'var(--text-secondary)',
              border: activeTab === 'chat' ? '1px solid var(--color-ai-border)' : '1px solid var(--border-color)',
              cursor: 'pointer',
            }}
          >
            <MessageSquare size={14} />
            Interactive Analyst Q&A Copilot
          </button>
        </div>
      </div>

      {/* ------------------------------------------------------------------- */}
      {/* TAB 2: INTERACTIVE ANALYST Q&A CHAT APPLICATION (PERSISTENT SESSIONS) */}
      {/* ------------------------------------------------------------------- */}
      {activeTab === 'chat' && (
        <div
          className="soc-card"
          style={{
            padding: 0,
            background: 'var(--bg-surface)',
            display: 'flex',
            height: '660px',
            overflow: 'hidden',
            borderRadius: '12px',
            border: '1px solid var(--border-color)',
          }}
        >
          {/* --------------------------------------------------------------- */}
          {/* LEFT COLUMN: CHAT SESSIONS MANAGER SIDEBAR                      */}
          {/* --------------------------------------------------------------- */}
          <div
            style={{
              width: '290px',
              backgroundColor: 'var(--bg-tertiary)',
              borderRight: '1px solid var(--border-color)',
              display: 'flex',
              flexDirection: 'column',
              flexShrink: 0,
            }}
          >
            {/* New Chat Button */}
            <div style={{ padding: '0.875rem' }}>
              <button
                onClick={handleNewChat}
                style={{
                  width: '100%',
                  padding: '0.625rem 0.875rem',
                  background: 'linear-gradient(135deg, #7c3aed 0%, #a855f7 100%)',
                  color: '#ffffff',
                  border: 'none',
                  borderRadius: '8px',
                  fontSize: '0.8125rem',
                  fontWeight: 600,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  gap: '0.5rem',
                  cursor: 'pointer',
                  boxShadow: '0 4px 12px rgba(124, 58, 237, 0.35)',
                  transition: 'all 0.15s ease',
                }}
                onMouseEnter={(e) => (e.currentTarget.style.transform = 'translateY(-1px)')}
                onMouseLeave={(e) => (e.currentTarget.style.transform = 'translateY(0)')}
              >
                <Plus size={16} />
                New Investigation Chat
              </button>
            </div>

            {/* Sessions Search Bar */}
            <div style={{ padding: '0 0.875rem 0.625rem' }}>
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.5rem',
                  backgroundColor: 'var(--bg-input)',
                  padding: '0.4rem 0.625rem',
                  borderRadius: '6px',
                  border: '1px solid var(--border-input)',
                }}
              >
                <Search size={13} color="var(--text-muted)" />
                <input
                  type="text"
                  placeholder="Search saved chats..."
                  value={chatSearchQuery}
                  onChange={(e) => setChatSearchQuery(e.target.value)}
                  style={{
                    background: 'transparent',
                    border: 'none',
                    color: 'var(--text-primary)',
                    fontSize: '0.75rem',
                    outline: 'none',
                    width: '100%',
                  }}
                />
                {chatSearchQuery && (
                  <button
                    onClick={() => setChatSearchQuery('')}
                    style={{ background: 'transparent', border: 'none', color: '#94a3b8', cursor: 'pointer', padding: 0 }}
                  >
                    <X size={12} />
                  </button>
                )}
              </div>
            </div>

            {/* Sessions List */}
            <div
              style={{
                flex: 1,
                overflowY: 'auto',
                padding: '0.375rem 0.5rem',
                display: 'flex',
                flexDirection: 'column',
                gap: '0.25rem',
                scrollbarWidth: 'thin',
              }}
            >
              {sessions
                .filter((s) => s.title.toLowerCase().includes(chatSearchQuery.toLowerCase()))
                .map((s) => {
                  const isActive = s.id === activeSession?.id;
                  const isEditing = editingSessionId === s.id;
                  const sessionIncident = incidents.find((inc) => inc.incident_id === s.incident_id);

                  return (
                    <div
                      key={s.id}
                      onClick={() => {
                        if (!isEditing) {
                          setActiveSessionId(s.id);
                          chatStorage.setActiveSessionId(s.id);
                        }
                      }}
                      style={{
                        padding: '0.625rem 0.75rem',
                        borderRadius: '8px',
                        backgroundColor: isActive ? 'var(--color-ai-bg)' : 'transparent',
                        borderLeft: isActive ? '3px solid var(--color-ai)' : '3px solid transparent',
                        borderBottom: '1px solid var(--border-subtle)',
                        cursor: 'pointer',
                        transition: 'all 0.15s ease',
                        position: 'relative',
                      }}
                      onMouseEnter={(e) => {
                        if (!isActive) e.currentTarget.style.backgroundColor = 'var(--bg-hover)';
                      }}
                      onMouseLeave={(e) => {
                        if (!isActive) e.currentTarget.style.backgroundColor = 'transparent';
                      }}
                    >
                      {/* Session Title & Actions */}
                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '0.35rem' }}>
                        {isEditing ? (
                          <div style={{ display: 'flex', alignItems: 'center', gap: '0.25rem', width: '100%' }}>
                            <input
                              type="text"
                              value={editTitle}
                              onChange={(e) => setEditTitle(e.target.value)}
                              onKeyDown={(e) => e.key === 'Enter' && handleSaveRename(s.id, e)}
                              autoFocus
                              style={{
                                flex: 1,
                                padding: '0.2rem 0.35rem',
                                background: 'var(--bg-input)',
                                color: 'var(--text-primary)',
                                border: '1px solid var(--color-ai)',
                                borderRadius: '4px',
                                fontSize: '0.75rem',
                                outline: 'none',
                              }}
                            />
                            <button
                              onClick={(e) => handleSaveRename(s.id, e)}
                              style={{ background: 'transparent', border: 'none', color: '#10b981', cursor: 'pointer', padding: '0 2px' }}
                            >
                              <Check size={14} />
                            </button>
                            <button
                              onClick={(e) => {
                                e.stopPropagation();
                                setEditingSessionId(null);
                              }}
                              style={{ background: 'transparent', border: 'none', color: '#ef4444', cursor: 'pointer', padding: '0 2px' }}
                            >
                              <X size={14} />
                            </button>
                          </div>
                        ) : (
                          <>
                            <span
                              style={{
                                fontSize: '0.78125rem',
                                fontWeight: isActive ? 600 : 500,
                                color: isActive ? '#f8fafc' : '#cbd5e1',
                                whiteSpace: 'nowrap',
                                overflow: 'hidden',
                                textOverflow: 'ellipsis',
                                flex: 1,
                              }}
                              title={s.title}
                            >
                              {s.title}
                            </span>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '0.2rem' }}>
                              <button
                                onClick={(e) => handleStartRename(s, e)}
                                style={{
                                  background: 'transparent',
                                  border: 'none',
                                  color: '#64748b',
                                  cursor: 'pointer',
                                  padding: '2px',
                                  borderRadius: '3px',
                                }}
                                title="Rename Chat"
                                onMouseEnter={(e) => (e.currentTarget.style.color = '#cbd5e1')}
                                onMouseLeave={(e) => (e.currentTarget.style.color = '#64748b')}
                              >
                                <Edit2 size={12} />
                              </button>
                              <button
                                onClick={(e) => handleDeleteSession(s.id, e)}
                                style={{
                                  background: 'transparent',
                                  border: 'none',
                                  color: '#64748b',
                                  cursor: 'pointer',
                                  padding: '2px',
                                  borderRadius: '3px',
                                }}
                                title="Delete Chat"
                                onMouseEnter={(e) => (e.currentTarget.style.color = '#ef4444')}
                                onMouseLeave={(e) => (e.currentTarget.style.color = '#64748b')}
                              >
                                <Trash2 size={12} />
                              </button>
                            </div>
                          </>
                        )}
                      </div>

                      {/* Sub-line: Incident Binding & Message Count */}
                      <div
                        style={{
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'space-between',
                          marginTop: '0.3rem',
                          fontSize: '0.6875rem',
                          color: '#64748b',
                        }}
                      >
                        <span
                          style={{
                            padding: '0.1rem 0.35rem',
                            borderRadius: '3px',
                            background: sessionIncident ? 'rgba(56, 189, 248, 0.12)' : 'rgba(255, 255, 255, 0.05)',
                            color: sessionIncident ? '#38bdf8' : '#94a3b8',
                            fontSize: '0.65rem',
                            fontWeight: 500,
                          }}
                        >
                          {sessionIncident ? sessionIncident.incident_id : 'Global SOC'}
                        </span>
                        <span>{s.messages.length} msgs</span>
                      </div>
                    </div>
                  );
                })}
            </div>

            {/* Sidebar Footer */}
            <div
              style={{
                padding: '0.625rem 0.875rem',
                borderTop: '1px solid rgba(255, 255, 255, 0.08)',
                fontSize: '0.6875rem',
                color: '#64748b',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
              }}
            >
              <span>💾 Local History Preserved</span>
              <span>{sessions.length} Saved</span>
            </div>
          </div>

          {/* --------------------------------------------------------------- */}
          {/* RIGHT COLUMN: ACTIVE CHAT CONVERSATION WORKSPACE                */}
          {/* --------------------------------------------------------------- */}
          <div
            style={{
              flex: 1,
              display: 'flex',
              flexDirection: 'column',
              minWidth: 0,
              backgroundColor: 'var(--bg-surface)',
            }}
          >
            {/* Active Chat Header Toolbar */}
            <div
              style={{
                padding: '0.75rem 1rem',
                background: 'var(--bg-elevated)',
                borderBottom: '1px solid var(--border-color)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                flexWrap: 'wrap',
                gap: '0.5rem',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', minWidth: 0 }}>
                <div
                  style={{
                    background: 'linear-gradient(135deg, #7c3aed 0%, #a855f7 100%)',
                    width: '32px',
                    height: '32px',
                    borderRadius: '8px',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    flexShrink: 0,
                    boxShadow: '0 0 10px rgba(168, 85, 247, 0.4)',
                  }}
                >
                  <Bot size={18} color="#ffffff" />
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', minWidth: 0 }}>
                  <span style={{ fontSize: '0.875rem', fontWeight: 600, color: 'var(--text-primary)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                    {activeSession?.title || 'Interactive AI Investigation'}
                  </span>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginTop: '0.15rem' }}>
                    <span style={{ fontSize: '0.6875rem', color: 'var(--text-secondary)' }}>Context:</span>
                    <select
                      value={activeSession?.incident_id || 'general'}
                      onChange={(e) => handleSessionIncidentChange(e.target.value)}
                      style={{
                        padding: '0.15rem 0.45rem',
                        background: 'var(--bg-input)',
                        color: 'var(--text-primary)',
                        border: '1px solid var(--border-input)',
                        borderRadius: '4px',
                        fontSize: '0.6875rem',
                        fontFamily: 'inherit',
                        outline: 'none',
                        cursor: 'pointer',
                      }}
                    >
                      <option value="general">🌐 Global SOC Copilot (All Telemetry)</option>
                      {incidents.map((inc) => (
                        <option key={inc.incident_id} value={inc.incident_id}>
                          [{inc.severity.toUpperCase()}] {inc.incident_id} - {inc.title.slice(0, 32)}
                        </option>
                      ))}
                    </select>
                  </div>
                </div>
              </div>

              {/* Header Right Actions */}
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <span
                  style={{
                    fontSize: '0.6875rem',
                    fontWeight: 600,
                    padding: '0.2rem 0.5rem',
                    borderRadius: '4px',
                    background: aiStatus?.gemini_configured ? 'rgba(16, 185, 129, 0.15)' : 'rgba(168, 85, 247, 0.15)',
                    color: aiStatus?.gemini_configured ? '#10b981' : '#a855f7',
                    border: '1px solid currentColor',
                  }}
                >
                  {aiStatus?.gemini_configured ? 'Google Gemini 3.5 Flash' : 'ThreadGrid Synthesizer'}
                </span>

                {currentIncident && (
                  <button
                    onClick={async () => {
                      if (!currentIncident) return;
                      setStaging(true);
                      try {
                        await api.stageIncidentActions(currentIncident.incident_id);
                        setStagingMessage('✅ Actions staged to Response Console!');
                        setTimeout(() => setStagingMessage(null), 3500);
                      } catch (err: any) {
                        setStagingMessage(`❌ Staging failed: ${err?.message || err}`);
                        setTimeout(() => setStagingMessage(null), 3500);
                      } finally {
                        setStaging(false);
                      }
                    }}
                    disabled={staging}
                    style={{
                      padding: '0.25rem 0.55rem',
                      background: 'rgba(239, 68, 68, 0.15)',
                      border: '1px solid rgba(239, 68, 68, 0.35)',
                      borderRadius: '4px',
                      color: '#f87171',
                      fontSize: '0.6875rem',
                      fontWeight: 600,
                      cursor: 'pointer',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '0.25rem',
                    }}
                  >
                    <Zap size={11} />
                    Stage Containment
                  </button>
                )}

                <button
                  onClick={handleClearChat}
                  style={{
                    padding: '0.25rem 0.55rem',
                    background: 'var(--bg-tertiary)',
                    border: '1px solid var(--border-color)',
                    borderRadius: '4px',
                    color: 'var(--text-secondary)',
                    fontSize: '0.6875rem',
                    cursor: 'pointer',
                  }}
                  title="Clear messages in this chat"
                  onMouseEnter={(e) => (e.currentTarget.style.color = 'var(--text-primary)')}
                  onMouseLeave={(e) => (e.currentTarget.style.color = 'var(--text-secondary)')}
                >
                  🧹 Clear
                </button>
              </div>
            </div>

            {/* Staging notification toast */}
            {stagingMessage && (
              <div
                style={{
                  padding: '0.35rem 0.75rem',
                  background: stagingMessage.includes('✅') ? 'rgba(16, 185, 129, 0.2)' : 'rgba(239, 68, 68, 0.2)',
                  color: stagingMessage.includes('✅') ? '#10b981' : '#ef4444',
                  fontSize: '0.75rem',
                  textAlign: 'center',
                  fontWeight: 500,
                  borderBottom: '1px solid currentColor',
                }}
              >
                {stagingMessage}
              </div>
            )}

            {/* Quick Prompt Suggestions */}
            <div
              style={{
                padding: '0.5rem 0.875rem',
                backgroundColor: 'var(--bg-elevated)',
                borderBottom: '1px solid var(--border-color)',
                display: 'flex',
                alignItems: 'center',
                gap: '0.5rem',
                overflowX: 'auto',
                scrollbarWidth: 'none',
              }}
            >
              <span style={{ fontSize: '0.7rem', color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: '0.25rem', flexShrink: 0 }}>
                <Zap size={12} color="#eab308" />
                Quick Prompts:
              </span>
              {quickPrompts.map((qp, idx) => (
                <button
                  key={idx}
                  onClick={() => handleSendMessage(qp.prompt)}
                  disabled={chatLoading}
                  style={{
                    padding: '0.25rem 0.6rem',
                    backgroundColor: 'var(--bg-tertiary)',
                    color: 'var(--text-secondary)',
                    border: '1px solid var(--border-color)',
                    borderRadius: '9999px',
                    fontSize: '0.7rem',
                    cursor: 'pointer',
                    whiteSpace: 'nowrap',
                    transition: 'all 0.15s ease',
                    flexShrink: 0,
                  }}
                  onMouseEnter={(e) => {
                    e.currentTarget.style.backgroundColor = 'var(--color-ai-bg)';
                    e.currentTarget.style.borderColor = 'var(--color-ai)';
                  }}
                  onMouseLeave={(e) => {
                    e.currentTarget.style.backgroundColor = 'var(--bg-tertiary)';
                    e.currentTarget.style.borderColor = 'var(--border-color)';
                  }}
                >
                  {qp.label}
                </button>
              ))}
            </div>

            {/* Chat Message Scrollable Stream */}
            <div
              style={{
                flex: 1,
                overflowY: 'auto',
                display: 'flex',
                flexDirection: 'column',
                gap: '0.85rem',
                padding: '1rem',
                backgroundColor: 'var(--bg-canvas)',
                scrollbarWidth: 'thin',
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
                      backgroundColor: msg.sender === 'user' ? 'var(--color-ai)' : 'var(--bg-tertiary)',
                      color: msg.sender === 'user' ? '#ffffff' : 'var(--text-primary)',
                      padding: '0.75rem 1rem',
                      borderRadius: '8px',
                      fontSize: '0.8125rem',
                      lineHeight: '1.45',
                      border: msg.sender === 'user' ? 'none' : '1px solid var(--border-color)',
                      boxShadow: 'var(--shadow-sm)',
                    }}
                  >
                    {/* Header with Model Badge */}
                    {msg.sender === 'assistant' && msg.model_used && (
                      <div
                        style={{
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'space-between',
                          marginBottom: '0.4rem',
                          borderBottom: '1px solid rgba(255, 255, 255, 0.08)',
                          paddingBottom: '0.3rem',
                        }}
                      >
                        <span style={{ fontSize: '0.7rem', fontWeight: 600, color: msg.is_live_gemini ? '#38bdf8' : '#a855f7' }}>
                          {msg.model_used}
                        </span>
                        <span style={{ fontSize: '0.65rem', color: '#64748b' }}>{msg.timestamp}</span>
                      </div>
                    )}

                    {/* Message Prose with Whitespace Preservation */}
                    <div style={{ whiteSpace: 'pre-wrap' }}>{msg.text}</div>

                    {/* Supporting Forensic Evidence Citations */}
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
                  Gemini 3.5 synthesizing evidence...
                </div>
              )}
              <div ref={chatBottomRef} />
            </div>

            {/* Chat Input Bar */}
            <div style={{ padding: '0.75rem', backgroundColor: 'var(--bg-elevated)', borderTop: '1px solid var(--border-color)', display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
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
                placeholder={
                  activeSession?.incident_id === 'general'
                    ? 'Ask anything about SIEM events, detection rules, or endpoints...'
                    : 'Ask about this incident, attacker techniques, or containment steps...'
                }
                style={{
                  flex: 1,
                  backgroundColor: 'var(--bg-input)',
                  color: 'var(--text-primary)',
                  border: '1px solid var(--border-input)',
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
                  cursor: chatLoading || !chatInput.trim() ? 'not-allowed' : 'pointer',
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '0.35rem',
                  boxShadow: chatLoading || !chatInput.trim() ? 'none' : '0 0 10px rgba(124, 58, 237, 0.4)',
                }}
              >
                <Send size={14} />
                Send
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ------------------------------------------------------------------- */}
      {/* TAB 1: STRUCTURED FORENSIC REPORT */}
      {/* ------------------------------------------------------------------- */}
      {activeTab === 'report' && (
        <>
          {loading && (
            <div className="soc-card" style={{ padding: '2.5rem', textAlign: 'center' }}>
              <div className="spin" style={{ display: 'inline-block', marginBottom: '1rem' }}>
                <Sparkles size={36} color="var(--color-ai)" />
              </div>
              <h4 style={{ color: 'var(--text-primary)', marginBottom: '0.5rem' }}>
                Performing Evidence-Grounded AI Synthesis
              </h4>
              <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', maxWidth: '480px', margin: '0 auto' }}>
                Retrieving chronological log events, defanging potential prompt injections, and verifying citation proofs...
              </p>
            </div>
          )}

          {!report && !loading && (
            <div className="soc-card" style={{ padding: '2.5rem', textAlign: 'center' }}>
              <Terminal size={36} color="var(--text-muted)" style={{ margin: '0 auto 1rem auto' }} />
              <h4 style={{ color: 'var(--text-secondary)', marginBottom: '0.5rem' }}>No AI Report Generated Yet</h4>
              <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>
                Select an incident from the queue above and click "Run AI Investigation" to begin.
              </p>
            </div>
          )}

          {report && !loading && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>

              {/* 1. Executive Summary & Verification Banner */}
              <div className="soc-card" style={{ padding: '1.25rem' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.75rem' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    <h4 style={{ fontSize: '1rem', fontWeight: 600, color: 'var(--text-primary)', margin: 0 }}>
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
              <div className="soc-card" style={{ padding: '1.25rem' }}>
                <h4 style={{
                  fontSize: '0.95rem',
                  fontWeight: 600,
                  color: 'var(--text-primary)',
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
                        backgroundColor: 'var(--bg-tertiary)',
                        borderRadius: '6px',
                        border: '1px solid var(--border-color)',
                        display: 'flex',
                        alignItems: 'flex-start',
                        justifyContent: 'space-between',
                        gap: '1rem'
                      }}
                    >
                      <div style={{ flex: 1, fontSize: '0.85rem', color: 'var(--text-primary)', lineHeight: '1.4' }}>
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
                              backgroundColor: 'var(--color-primary-bg)',
                              color: 'var(--color-primary)',
                              border: '1px solid var(--color-primary-border)',
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
              <div className="soc-card" style={{ padding: '1.25rem' }}>
                <h4 style={{
                  fontSize: '0.95rem',
                  fontWeight: 600,
                  color: 'var(--text-primary)',
                  marginBottom: '1rem',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.5rem'
                }}>
                  <Cpu size={16} color="var(--color-ai)" />
                  Threat Hypotheses & MITRE ATT&CK Mapping
                </h4>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                  {report.threat_hypotheses.map((hyp, idx) => (
                    <div
                      key={idx}
                      style={{
                        padding: '0.85rem 1rem',
                        backgroundColor: 'var(--bg-tertiary)',
                        borderRadius: '6px',
                        border: '1px solid var(--border-color)',
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.35rem' }}>
                        <span style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--color-ai)' }}>
                          MITRE: {hyp.mitre_technique || 'Unmapped'}
                        </span>
                        <span style={{ fontSize: '0.75rem', color: '#10b981', fontWeight: 600 }}>
                          Confidence: {(hyp.confidence * 100).toFixed(0)}%
                        </span>
                      </div>

                      <div style={{ fontSize: '0.85rem', color: 'var(--text-primary)', lineHeight: '1.4' }}>
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
                                color: 'var(--text-secondary)',
                                backgroundColor: 'var(--bg-hover)',
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
              <div className="soc-card" style={{ padding: '1.25rem' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1rem' }}>
                  <h4 style={{
                    fontSize: '0.95rem',
                    fontWeight: 600,
                    color: 'var(--text-primary)',
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
                        backgroundColor: 'var(--bg-tertiary)',
                        borderRadius: '6px',
                        border: '1px solid var(--border-color)',
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
