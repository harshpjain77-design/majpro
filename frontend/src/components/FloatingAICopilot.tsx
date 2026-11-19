import React, { useState, useEffect, useRef } from 'react';
import { api } from '../services/api';
import { chatStorage } from '../services/chatStorage';
import { Incident, AIChatMessage, AIStatusResponse, ChatSession } from '../types';

export const FloatingAICopilot: React.FC = () => {
  const [isOpen, setIsOpen] = useState<boolean>(false);
  const [isMinimized, setIsMinimized] = useState<boolean>(false);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [aiStatus, setAiStatus] = useState<AIStatusResponse | null>(null);

  // Persistent Chat Sessions from chatStorage
  const [sessions, setSessions] = useState<ChatSession[]>(() => chatStorage.getSessions());
  const [activeSessionId, setActiveSessionId] = useState<string>(() => chatStorage.getActiveSessionId());

  // Input & loading state
  const [chatInput, setChatInput] = useState<string>('');
  const [chatLoading, setChatLoading] = useState<boolean>(false);
  const [actionSuccessMsg, setActionSuccessMsg] = useState<string | null>(null);

  const messagesEndRef = useRef<HTMLDivElement>(null);

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
  const selectedIncidentId = activeSession?.incident_id || 'general';

  // Auto-scroll chat to bottom
  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    if (isOpen && !isMinimized) {
      scrollToBottom();
    }
  }, [chatMessages, isOpen, isMinimized, activeSessionId]);

  // Load AI status & incidents on mount
  useEffect(() => {
    const fetchStatusAndIncidents = async () => {
      try {
        const [statusRes, incRes] = await Promise.all([
          api.getAIStatus().catch(() => null),
          api.getIncidents({ limit: 50 }).catch(() => ({ incidents: [] })),
        ]);
        if (statusRes) setAiStatus(statusRes);
        if (incRes && incRes.incidents) {
          setIncidents(incRes.incidents);
        }
      } catch (err) {
        console.error('Failed to load floating AI copilot data:', err);
      }
    };
    fetchStatusAndIncidents();
  }, []);

  const handleNewChat = () => {
    const created = chatStorage.createSession(selectedIncidentId || 'general');
    setActiveSessionId(created.id);
  };

  const handleSelectSession = (id: string) => {
    setActiveSessionId(id);
    chatStorage.setActiveSessionId(id);
  };

  const handleIncidentChange = (newIncidentId: string) => {
    if (!activeSession) return;
    const targetInc = incidents.find((i) => i.incident_id === newIncidentId);
    chatStorage.updateSessionIncident(
      activeSession.id,
      newIncidentId,
      targetInc?.title
    );
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

    // Save user message to persistent storage immediately
    chatStorage.addMessageToSession(activeSession.id, userMsg);
    setChatInput('');
    setChatLoading(true);
    setActionSuccessMsg(null);

    try {
      const historyPayload = activeSession.messages.map((m) => ({
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

      // Save bot response to persistent storage
      chatStorage.addMessageToSession(activeSession.id, botMsg);
    } catch (err: any) {
      const errMsg: AIChatMessage = {
        id: `err-${Date.now()}`,
        sender: 'assistant',
        text: `⚠️ Query error: ${err?.message || err}`,
        timestamp: new Date().toLocaleTimeString(),
      };
      chatStorage.addMessageToSession(activeSession.id, errMsg);
    } finally {
      setChatLoading(false);
    }
  };

  const handleStageResponse = async () => {
    if (!selectedIncidentId || selectedIncidentId === 'general') return;
    try {
      await api.stageIncidentActions(selectedIncidentId);
      setActionSuccessMsg('✅ Containment actions staged into Response Console!');
      setTimeout(() => setActionSuccessMsg(null), 4000);
    } catch (err: any) {
      setActionSuccessMsg(`❌ Staging failed: ${err?.message || err}`);
      setTimeout(() => setActionSuccessMsg(null), 4000);
    }
  };

  const handleClearChat = () => {
    if (activeSession) {
      chatStorage.clearSessionMessages(activeSession.id);
    }
  };

  const selectedIncident = incidents.find((i) => i.incident_id === selectedIncidentId);

  const quickPrompts = [
    { label: '🛡️ Attack Narrative', prompt: 'Explain the attack narrative and how the attacker breached this asset step-by-step.' },
    { label: '📋 CISO Briefing', prompt: 'Draft an executive briefing for the CISO summarizing risk, impacted assets, and containment status.' },
    { label: '⚡ Containment Plan', prompt: 'What immediate containment and remediation actions should be executed for this incident?' },
    { label: '🔍 Verify Citations', prompt: 'List the verified forensic evidence and explain why this activity was flagged.' },
  ];

  return (
    <>
      {/* ------------------------------------------------------------------- */}
      {/* Floating Action Launcher (When Window is Closed)                    */}
      {/* ------------------------------------------------------------------- */}
      {!isOpen && (
        <button
          onClick={() => {
            setIsOpen(true);
            setIsMinimized(false);
          }}
          style={{
            position: 'fixed',
            bottom: '24px',
            right: '24px',
            zIndex: 9999,
            display: 'flex',
            alignItems: 'center',
            gap: '0.625rem',
            padding: '0.75rem 1.15rem',
            background: 'linear-gradient(135deg, #7c3aed 0%, #a855f7 100%)',
            color: '#ffffff',
            border: '1px solid rgba(255, 255, 255, 0.25)',
            borderRadius: '9999px',
            boxShadow: '0 10px 25px -5px rgba(124, 58, 237, 0.6), 0 0 15px rgba(168, 85, 247, 0.4)',
            cursor: 'pointer',
            transition: 'all 0.25s cubic-bezier(0.4, 0, 0.2, 1)',
            fontFamily: 'inherit',
            fontWeight: 600,
            fontSize: '0.875rem',
          }}
          onMouseEnter={(e) => {
            e.currentTarget.style.transform = 'translateY(-3px) scale(1.03)';
            e.currentTarget.style.boxShadow = '0 14px 30px -5px rgba(124, 58, 237, 0.8), 0 0 20px rgba(168, 85, 247, 0.6)';
          }}
          onMouseLeave={(e) => {
            e.currentTarget.style.transform = 'translateY(0) scale(1)';
            e.currentTarget.style.boxShadow = '0 10px 25px -5px rgba(124, 58, 237, 0.6), 0 0 15px rgba(168, 85, 247, 0.4)';
          }}
          title="Open Floating AI Copilot"
        >
          <div style={{ position: 'relative', display: 'flex', alignItems: 'center' }}>
            <span style={{ fontSize: '1.25rem' }}>✨</span>
            <span
              style={{
                position: 'absolute',
                top: '-2px',
                right: '-2px',
                width: '8px',
                height: '8px',
                borderRadius: '50%',
                background: '#10b981',
                boxShadow: '0 0 8px #10b981',
              }}
            />
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-start', textAlign: 'left' }}>
            <span style={{ lineHeight: 1.1, letterSpacing: '0.01em' }}>XAI Copilot</span>
            <span style={{ fontSize: '0.6875rem', opacity: 0.85, fontWeight: 400 }}>
              {aiStatus?.gemini_configured ? 'Gemini 3.5 Active' : 'Local Engine'}
            </span>
          </div>
        </button>
      )}

      {/* ------------------------------------------------------------------- */}
      {/* Floating Chat Window                                                */}
      {/* ------------------------------------------------------------------- */}
      {isOpen && (
        <div
          style={{
            position: 'fixed',
            bottom: '24px',
            right: '24px',
            zIndex: 9999,
            width: isMinimized ? '340px' : '460px',
            height: isMinimized ? '52px' : '630px',
            maxHeight: 'calc(100vh - 48px)',
            maxWidth: 'calc(100vw - 32px)',
            background: 'var(--bg-elevated)',
            backdropFilter: 'blur(16px)',
            border: '1px solid var(--border-color)',
            borderRadius: '16px',
            boxShadow: '0 25px 60px -15px rgba(0, 0, 0, 0.3), 0 0 25px rgba(168, 85, 247, 0.2)',
            display: 'flex',
            flexDirection: 'column',
            overflow: 'hidden',
            transition: 'height 0.25s cubic-bezier(0.4, 0, 0.2, 1), width 0.25s cubic-bezier(0.4, 0, 0.2, 1)',
            fontFamily: 'inherit',
          }}
        >
          {/* Header Bar */}
          <div
            style={{
              padding: '0.75rem 1rem',
              background: 'var(--bg-surface)',
              borderBottom: isMinimized ? 'none' : '1px solid var(--border-color)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              gap: '0.5rem',
              userSelect: 'none',
            }}
          >
            <div
              style={{ display: 'flex', alignItems: 'center', gap: '0.625rem', cursor: 'pointer', flex: 1, minWidth: 0 }}
              onClick={() => setIsMinimized((prev) => !prev)}
            >
              <div
                style={{
                  background: 'linear-gradient(135deg, #7c3aed 0%, #a855f7 100%)',
                  width: '28px',
                  height: '28px',
                  borderRadius: '8px',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  fontSize: '0.875rem',
                  flexShrink: 0,
                  boxShadow: '0 0 10px rgba(168, 85, 247, 0.5)',
                }}
              >
                🤖
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', minWidth: 0 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.375rem' }}>
                  <span style={{ fontSize: '0.875rem', fontWeight: 600, color: 'var(--text-primary)', whiteSpace: 'nowrap' }}>
                    ThreadGrid XAI
                  </span>
                  <span
                    style={{
                      width: '6px',
                      height: '6px',
                      borderRadius: '50%',
                      background: '#10b981',
                      boxShadow: '0 0 6px #10b981',
                    }}
                  />
                </div>
                {!isMinimized && (
                  <span style={{ fontSize: '0.6875rem', color: '#a855f7', fontWeight: 500, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                    {aiStatus?.gemini_configured ? 'Google Gemini 3.5 Flash' : 'ThreadGrid Local Synthesizer'}
                  </span>
                )}
              </div>
            </div>

            {/* Window Controls & Chat Switcher */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem', flexShrink: 0 }}>
              {!isMinimized && (
                <>
                  <button
                    onClick={handleNewChat}
                    style={{
                      background: 'rgba(124, 58, 237, 0.25)',
                      border: '1px solid rgba(168, 85, 247, 0.4)',
                      color: '#d8b4fe',
                      cursor: 'pointer',
                      fontSize: '0.75rem',
                      fontWeight: 600,
                      padding: '0.2rem 0.5rem',
                      borderRadius: '4px',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '0.2rem',
                    }}
                    title="Start New Chat"
                  >
                    + New
                  </button>
                  <button
                    onClick={handleClearChat}
                    style={{
                      background: 'transparent',
                      border: 'none',
                      color: '#94a3b8',
                      cursor: 'pointer',
                      fontSize: '0.875rem',
                      padding: '0.25rem 0.4rem',
                      borderRadius: '4px',
                    }}
                    title="Clear conversation"
                    onMouseEnter={(e) => (e.currentTarget.style.color = '#f8fafc')}
                    onMouseLeave={(e) => (e.currentTarget.style.color = '#94a3b8')}
                  >
                    🧹
                  </button>
                </>
              )}
              <button
                onClick={() => setIsMinimized((prev) => !prev)}
                style={{
                  background: 'transparent',
                  border: 'none',
                  color: '#94a3b8',
                  cursor: 'pointer',
                  fontSize: '0.875rem',
                  padding: '0.25rem 0.4rem',
                  borderRadius: '4px',
                }}
                title={isMinimized ? 'Expand' : 'Minimize'}
                onMouseEnter={(e) => (e.currentTarget.style.color = '#f8fafc')}
                onMouseLeave={(e) => (e.currentTarget.style.color = '#94a3b8')}
              >
                {isMinimized ? '🗖' : '🗕'}
              </button>
              <button
                onClick={() => setIsOpen(false)}
                style={{
                  background: 'transparent',
                  border: 'none',
                  color: '#94a3b8',
                  cursor: 'pointer',
                  fontSize: '0.875rem',
                  padding: '0.25rem 0.4rem',
                  borderRadius: '4px',
                }}
                title="Close"
                onMouseEnter={(e) => (e.currentTarget.style.color = '#ef4444')}
                onMouseLeave={(e) => (e.currentTarget.style.color = '#94a3b8')}
              >
                ✕
              </button>
            </div>
          </div>

          {/* Body Content (Visible when not minimized) */}
          {!isMinimized && (
            <>
              {/* Context Toolbar: Chat Session Dropdown + Incident Selector */}
              <div
                style={{
                  padding: '0.5rem 0.75rem',
                  background: 'var(--bg-tertiary)',
                  borderBottom: '1px solid var(--border-color)',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '0.35rem',
                }}
              >
                {/* Session Selector */}
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <span style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', fontWeight: 600, whiteSpace: 'nowrap' }}>
                    Chat:
                  </span>
                  <select
                    value={activeSessionId}
                    onChange={(e) => handleSelectSession(e.target.value)}
                    style={{
                      flex: 1,
                      minWidth: 0,
                      padding: '0.25rem 0.45rem',
                      background: 'var(--bg-input)',
                      color: 'var(--text-primary)',
                      border: '1px solid var(--border-color)',
                      borderRadius: '4px',
                      fontSize: '0.75rem',
                      fontFamily: 'inherit',
                      outline: 'none',
                      cursor: 'pointer',
                    }}
                  >
                    {sessions.map((s) => (
                      <option key={s.id} value={s.id}>
                        {s.title} ({s.messages.length} msgs)
                      </option>
                    ))}
                  </select>
                </div>

                {/* Incident Context Selector */}
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <span style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', fontWeight: 600, whiteSpace: 'nowrap' }}>
                    Asset:
                  </span>
                  <select
                    value={selectedIncidentId}
                    onChange={(e) => handleIncidentChange(e.target.value)}
                    style={{
                      flex: 1,
                      minWidth: 0,
                      padding: '0.25rem 0.45rem',
                      background: 'var(--bg-input)',
                      color: 'var(--text-primary)',
                      border: '1px solid var(--border-color)',
                      borderRadius: '4px',
                      fontSize: '0.75rem',
                      fontFamily: 'inherit',
                      outline: 'none',
                      cursor: 'pointer',
                    }}
                  >
                    <option value="general">🌐 Global SOC Copilot (All Telemetry)</option>
                    {incidents.map((inc) => (
                      <option key={inc.incident_id} value={inc.incident_id}>
                        [{inc.severity.toUpperCase()}] {inc.incident_id} - {inc.title.slice(0, 28)}
                      </option>
                    ))}
                  </select>

                  {selectedIncident && selectedIncidentId !== 'general' && (
                    <span
                      style={{
                        fontSize: '0.65rem',
                        fontWeight: 700,
                        padding: '0.15rem 0.35rem',
                        borderRadius: '3px',
                        background:
                          selectedIncident.severity === 'critical'
                            ? 'rgba(239, 68, 68, 0.2)'
                            : selectedIncident.severity === 'high'
                            ? 'rgba(249, 115, 22, 0.2)'
                            : 'rgba(59, 130, 246, 0.2)',
                        color:
                          selectedIncident.severity === 'critical'
                            ? '#ef4444'
                            : selectedIncident.severity === 'high'
                            ? '#f97316'
                            : '#3b82f6',
                        border: '1px solid currentColor',
                        whiteSpace: 'nowrap',
                      }}
                    >
                      Risk {selectedIncident.risk_score.toFixed(0)}
                    </span>
                  )}
                </div>
              </div>

              {/* Action Staged Notification Banner */}
              {actionSuccessMsg && (
                <div
                  style={{
                    padding: '0.35rem 0.75rem',
                    background: actionSuccessMsg.includes('✅') ? 'rgba(16, 185, 129, 0.2)' : 'rgba(239, 68, 68, 0.2)',
                    color: actionSuccessMsg.includes('✅') ? '#10b981' : '#ef4444',
                    fontSize: '0.75rem',
                    textAlign: 'center',
                    borderBottom: '1px solid currentColor',
                    fontWeight: 500,
                  }}
                >
                  {actionSuccessMsg}
                </div>
              )}

              {/* Chat Messages Stream */}
              <div
                style={{
                  flex: 1,
                  overflowY: 'auto',
                  padding: '0.875rem',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '0.75rem',
                  scrollbarWidth: 'thin',
                }}
              >
                {chatMessages.map((msg) => (
                  <div
                    key={msg.id}
                    style={{
                      display: 'flex',
                      flexDirection: 'column',
                      alignSelf: msg.sender === 'user' ? 'flex-end' : 'flex-start',
                      maxWidth: '90%',
                    }}
                  >
                    <div
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: '0.375rem',
                        marginBottom: '0.25rem',
                        fontSize: '0.6875rem',
                        color: '#64748b',
                      }}
                    >
                      <span>{msg.sender === 'user' ? 'Analyst' : 'Copilot'}</span>
                      <span>•</span>
                      <span>{msg.timestamp}</span>
                    </div>

                    <div
                      style={{
                        padding: '0.625rem 0.875rem',
                        borderRadius: msg.sender === 'user' ? '12px 12px 2px 12px' : '12px 12px 12px 2px',
                        background:
                          msg.sender === 'user'
                            ? 'linear-gradient(135deg, #7c3aed 0%, #6d28d9 100%)'
                            : 'var(--bg-surface)',
                        color: msg.sender === 'user' ? '#ffffff' : 'var(--text-primary)',
                        fontSize: '0.8125rem',
                        lineHeight: 1.5,
                        wordBreak: 'break-word',
                        border: msg.sender === 'user' ? 'none' : '1px solid var(--border-color)',
                        boxShadow: '0 2px 6px rgba(0, 0, 0, 0.1)',
                      }}
                    >
                      {/* Markdown prose rendering */}
                      <div style={{ whiteSpace: 'pre-wrap' }}>{msg.text}</div>

                      {/* Evidence Citations */}
                      {msg.citations && msg.citations.length > 0 && (
                        <div
                          style={{
                            marginTop: '0.5rem',
                            paddingTop: '0.375rem',
                            borderTop: '1px solid var(--border-color)',
                            display: 'flex',
                            flexWrap: 'wrap',
                            gap: '0.25rem',
                            alignItems: 'center',
                          }}
                        >
                          <span style={{ fontSize: '0.6875rem', color: 'var(--text-muted)' }}>Evidence:</span>
                          {msg.citations.map((cite, i) => (
                            <span
                              key={i}
                              style={{
                                fontSize: '0.6875rem',
                                padding: '0.1rem 0.35rem',
                                background: 'rgba(168, 85, 247, 0.15)',
                                border: '1px solid rgba(168, 85, 247, 0.3)',
                                borderRadius: '4px',
                                color: '#a855f7',
                                fontFamily: 'monospace',
                              }}
                            >
                              [{cite}]
                            </span>
                          ))}
                        </div>
                      )}

                      {/* Staged Response Action Buttons */}
                      {msg.sender === 'assistant' && selectedIncidentId !== 'general' && (
                        <div style={{ marginTop: '0.5rem', display: 'flex', gap: '0.375rem', flexWrap: 'wrap' }}>
                          <button
                            onClick={handleStageResponse}
                            style={{
                              padding: '0.25rem 0.5rem',
                              background: 'rgba(239, 68, 68, 0.15)',
                              border: '1px solid rgba(239, 68, 68, 0.4)',
                              borderRadius: '4px',
                              color: '#f87171',
                              fontSize: '0.6875rem',
                              fontWeight: 600,
                              cursor: 'pointer',
                              display: 'flex',
                              alignItems: 'center',
                              gap: '0.25rem',
                            }}
                            onMouseEnter={(e) => (e.currentTarget.style.background = 'rgba(239, 68, 68, 0.3)')}
                            onMouseLeave={(e) => (e.currentTarget.style.background = 'rgba(239, 68, 68, 0.15)')}
                          >
                            ⚡ Stage Containment
                          </button>
                        </div>
                      )}
                    </div>
                  </div>
                ))}

                {/* Loading indicator */}
                {chatLoading && (
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', padding: '0.5rem' }}>
                    <div
                      style={{
                        width: '18px',
                        height: '18px',
                        border: '2px solid rgba(168, 85, 247, 0.3)',
                        borderTopColor: '#a855f7',
                        borderRadius: '50%',
                        animation: 'spin 0.8s linear infinite',
                      }}
                    />
                    <span style={{ fontSize: '0.75rem', color: '#94a3b8' }}>
                      Gemini 3.5 synthesizing evidence...
                    </span>
                  </div>
                )}
                <div ref={messagesEndRef} />
              </div>

              {/* Quick Prompt Suggestions */}
              <div
                style={{
                  padding: '0.375rem 0.75rem',
                  background: 'var(--bg-tertiary)',
                  borderTop: '1px solid var(--border-color)',
                  display: 'flex',
                  gap: '0.375rem',
                  overflowX: 'auto',
                  scrollbarWidth: 'none',
                }}
              >
                {quickPrompts.map((qp, idx) => (
                  <button
                    key={idx}
                    onClick={() => handleSendMessage(qp.prompt)}
                    disabled={chatLoading}
                    style={{
                      padding: '0.25rem 0.5rem',
                      background: 'var(--bg-surface)',
                      border: '1px solid var(--border-color)',
                      borderRadius: '9999px',
                      color: 'var(--text-secondary)',
                      fontSize: '0.6875rem',
                      whiteSpace: 'nowrap',
                      cursor: 'pointer',
                      transition: 'all 0.15s ease',
                      flexShrink: 0,
                    }}
                    onMouseEnter={(e) => {
                      e.currentTarget.style.borderColor = '#a855f7';
                      e.currentTarget.style.color = 'var(--text-primary)';
                    }}
                    onMouseLeave={(e) => {
                      e.currentTarget.style.borderColor = 'var(--border-color)';
                      e.currentTarget.style.color = 'var(--text-secondary)';
                    }}
                  >
                    {qp.label}
                  </button>
                ))}
              </div>

              {/* Chat Input Bar */}
              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  handleSendMessage();
                }}
                style={{
                  padding: '0.625rem 0.75rem',
                  background: 'var(--bg-surface)',
                  borderTop: '1px solid var(--border-color)',
                  display: 'flex',
                  gap: '0.5rem',
                  alignItems: 'center',
                }}
              >
                <input
                  type="text"
                  value={chatInput}
                  onChange={(e) => setChatInput(e.target.value)}
                  placeholder={
                    selectedIncidentId === 'general'
                      ? 'Ask anything about SIEM events, rules, or hosts...'
                      : 'Ask about this incident or containment...'
                  }
                  disabled={chatLoading}
                  style={{
                    flex: 1,
                    padding: '0.5rem 0.75rem',
                    background: 'var(--bg-input)',
                    color: 'var(--text-primary)',
                    border: '1px solid var(--border-color)',
                    borderRadius: '8px',
                    fontSize: '0.8125rem',
                    outline: 'none',
                    fontFamily: 'inherit',
                  }}
                  onFocus={(e) => (e.target.style.borderColor = '#a855f7')}
                  onBlur={(e) => (e.target.style.borderColor = 'var(--border-color)')}
                />
                <button
                  type="submit"
                  disabled={!chatInput.trim() || chatLoading}
                  style={{
                    padding: '0.5rem 0.875rem',
                    background:
                      !chatInput.trim() || chatLoading
                        ? '#334155'
                        : 'linear-gradient(135deg, #7c3aed 0%, #a855f7 100%)',
                    color: '#ffffff',
                    border: 'none',
                    borderRadius: '8px',
                    fontWeight: 600,
                    fontSize: '0.8125rem',
                    cursor: !chatInput.trim() || chatLoading ? 'not-allowed' : 'pointer',
                    transition: 'all 0.15s ease',
                    boxShadow:
                      !chatInput.trim() || chatLoading
                        ? 'none'
                        : '0 0 10px rgba(168, 85, 247, 0.4)',
                  }}
                >
                  Send
                </button>
              </form>
            </>
          )}
        </div>
      )}
    </>
  );
};
