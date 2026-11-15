import { ChatSession, AIChatMessage } from '../types';

const SESSIONS_KEY = 'threadgrid_chat_sessions_v1';
const ACTIVE_KEY = 'threadgrid_active_session_id_v1';
const EVENT_NAME = 'threadgrid_chat_storage_change';

const createDefaultSession = (incidentId: string = 'general', incidentTitle?: string): ChatSession => {
  const now = new Date().toISOString();
  const title = incidentId === 'general' ? 'Global SOC Investigation' : (incidentTitle ? `${incidentTitle.slice(0, 32)}` : `Investigation ${incidentId}`);
  return {
    id: `session-${Date.now()}`,
    title,
    incident_id: incidentId,
    created_at: now,
    updated_at: now,
    messages: [
      {
        id: `welcome-${Date.now()}`,
        sender: 'assistant',
        text: `### 👋 ThreadGrid SIEM AI Copilot Ready\n\nI am your **Explainable AI Assistant**, powered by **Google Gemini 3.5 Flash** with verified evidence citations.\n\nAsk any question regarding attack progression, MITRE ATT&CK techniques, forensic evidence, or containment playbooks. Your chat history is **automatically saved and preserved** across all tabs and pages.`,
        timestamp: new Date().toLocaleTimeString(),
        model_used: 'Google Gemini (gemini-3.5-flash)',
        is_live_gemini: true,
        suggested_actions: ['Explain Attack Narrative', 'Draft CISO Briefing', 'Recommend Containment Plan'],
      },
    ],
  };
};

export const chatStorage = {
  getSessions(): ChatSession[] {
    try {
      const data = localStorage.getItem(SESSIONS_KEY);
      if (!data) {
        const initial = [createDefaultSession()];
        localStorage.setItem(SESSIONS_KEY, JSON.stringify(initial));
        return initial;
      }
      const parsed = JSON.parse(data);
      if (Array.isArray(parsed) && parsed.length > 0) {
        return parsed;
      }
      const initial = [createDefaultSession()];
      localStorage.setItem(SESSIONS_KEY, JSON.stringify(initial));
      return initial;
    } catch (e) {
      console.warn('Failed to read chat sessions from localStorage:', e);
      return [createDefaultSession()];
    }
  },

  saveSessions(sessions: ChatSession[]): void {
    try {
      localStorage.setItem(SESSIONS_KEY, JSON.stringify(sessions));
      window.dispatchEvent(new CustomEvent(EVENT_NAME, { detail: { sessions } }));
    } catch (e) {
      console.error('Failed to save chat sessions to localStorage:', e);
    }
  },

  getActiveSessionId(): string {
    const id = localStorage.getItem(ACTIVE_KEY);
    if (id) return id;
    const sessions = this.getSessions();
    const fallbackId = sessions[0]?.id || `session-${Date.now()}`;
    localStorage.setItem(ACTIVE_KEY, fallbackId);
    return fallbackId;
  },

  setActiveSessionId(id: string): void {
    localStorage.setItem(ACTIVE_KEY, id);
    window.dispatchEvent(new CustomEvent(EVENT_NAME, { detail: { activeSessionId: id } }));
  },

  getActiveSession(): ChatSession {
    const activeId = this.getActiveSessionId();
    const sessions = this.getSessions();
    const found = sessions.find((s) => s.id === activeId);
    if (found) return found;

    if (sessions.length > 0) {
      this.setActiveSessionId(sessions[0].id);
      return sessions[0];
    }

    const brandNew = createDefaultSession();
    this.saveSessions([brandNew]);
    this.setActiveSessionId(brandNew.id);
    return brandNew;
  },

  createSession(incidentId: string = 'general', incidentTitle?: string): ChatSession {
    const sessions = this.getSessions();
    const newSession = createDefaultSession(incidentId, incidentTitle);
    const updated = [newSession, ...sessions];
    this.saveSessions(updated);
    this.setActiveSessionId(newSession.id);
    return newSession;
  },

  addMessageToSession(sessionId: string, message: AIChatMessage): void {
    const sessions = this.getSessions();
    const sessionIndex = sessions.findIndex((s) => s.id === sessionId);
    if (sessionIndex === -1) return;

    const session = sessions[sessionIndex];
    const newMessages = [...session.messages, message];

    // Auto-generate title if this is the first user prompt and title was default
    let newTitle = session.title;
    if (
      message.sender === 'user' &&
      (session.title.startsWith('Global SOC') || session.title.startsWith('Investigation'))
    ) {
      newTitle = message.text.slice(0, 36) + (message.text.length > 36 ? '...' : '');
    }

    const updatedSession: ChatSession = {
      ...session,
      title: newTitle,
      messages: newMessages,
      updated_at: new Date().toISOString(),
    };

    // Move recently active session to the top
    const remaining = sessions.filter((s) => s.id !== sessionId);
    this.saveSessions([updatedSession, ...remaining]);
  },

  renameSession(sessionId: string, newTitle: string): void {
    const sessions = this.getSessions();
    const updated = sessions.map((s) => (s.id === sessionId ? { ...s, title: newTitle.trim() || s.title } : s));
    this.saveSessions(updated);
  },

  deleteSession(sessionId: string): ChatSession {
    const sessions = this.getSessions();
    const remaining = sessions.filter((s) => s.id !== sessionId);
    if (remaining.length === 0) {
      const fresh = createDefaultSession();
      this.saveSessions([fresh]);
      this.setActiveSessionId(fresh.id);
      return fresh;
    }
    this.saveSessions(remaining);
    if (this.getActiveSessionId() === sessionId) {
      this.setActiveSessionId(remaining[0].id);
      return remaining[0];
    }
    return remaining[0];
  },

  clearSessionMessages(sessionId: string): void {
    const sessions = this.getSessions();
    const updated = sessions.map((s) => {
      if (s.id === sessionId) {
        return {
          ...s,
          messages: [
            {
              id: `cleared-${Date.now()}`,
              sender: 'assistant' as const,
              text: '🧹 Conversation cleared. How can I assist you with your security investigation?',
              timestamp: new Date().toLocaleTimeString(),
              suggested_actions: ['Explain Attack Narrative', 'Draft CISO Briefing', 'Recommend Containment Plan'],
            },
          ],
          updated_at: new Date().toISOString(),
        };
      }
      return s;
    });
    this.saveSessions(updated);
  },

  updateSessionIncident(sessionId: string, incidentId: string, incidentTitle?: string): void {
    const sessions = this.getSessions();
    const updated = sessions.map((s) => {
      if (s.id === sessionId) {
        return {
          ...s,
          incident_id: incidentId,
          title: incidentTitle ? `${incidentTitle.slice(0, 32)}` : s.title,
          updated_at: new Date().toISOString(),
        };
      }
      return s;
    });
    this.saveSessions(updated);
  },

  subscribe(callback: () => void): () => void {
    window.addEventListener(EVENT_NAME, callback);
    return () => window.removeEventListener(EVENT_NAME, callback);
  },
};
