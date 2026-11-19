import React, { useState } from 'react';
import {
  ShieldAlert,
  Terminal,
  Activity,
  Cpu,
  RefreshCw,
  GitMerge,
  Sparkles,
  Search,
  CheckCircle2,
  AlertTriangle
} from 'lucide-react';

interface HeaderProps {
  activeTab: 'incidents' | 'events' | 'ai-copilot' | 'response' | 'metrics';
  setActiveTab: (tab: 'incidents' | 'events' | 'ai-copilot' | 'response' | 'metrics') => void;
  onRefresh: () => void;
  onTriggerCorrelation: () => Promise<void>;
  dedupRatio: number;
  incidentCount: number;
  loading: boolean;
}

export const Header: React.FC<HeaderProps> = ({
  activeTab,
  setActiveTab,
  onRefresh,
  onTriggerCorrelation,
  dedupRatio,
  incidentCount,
  loading,
}) => {
  const [correlating, setCorrelating] = useState(false);
  const [correlateMessage, setCorrelateMessage] = useState<string | null>(null);

  const handleCorrelate = async () => {
    try {
      setCorrelating(true);
      setCorrelateMessage(null);
      await onTriggerCorrelation();
      setCorrelateMessage('Correlation executed successfully');
      setTimeout(() => setCorrelateMessage(null), 3000);
    } catch (err: any) {
      setCorrelateMessage(`Correlation error: ${err.message}`);
    } finally {
      setCorrelating(false);
    }
  };

  return (
    <header style={{
      backgroundColor: 'var(--bg-topbar)',
      borderBottom: '1px solid var(--border-topbar)',
      padding: '0.875rem 2rem',
      position: 'sticky',
      top: 0,
      zIndex: 50,
    }}>
      <div style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        maxWidth: '1600px',
        margin: '0 auto',
      }}>
        {/* Brand & System Status */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '1.25rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <div style={{
              background: 'linear-gradient(135deg, #3b82f6 0%, #8b5cf6 100%)',
              padding: '0.5rem',
              borderRadius: '8px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              boxShadow: '0 0 16px rgba(59, 130, 246, 0.4)',
            }}>
              <ShieldAlert size={22} color="#ffffff" />
            </div>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <span style={{ fontWeight: 700, fontSize: '1.05rem', letterSpacing: '-0.02em', color: 'var(--text-primary)' }}>
                  AI Cyber Defense Platform
                </span>
                <span className="badge badge-ai" style={{ fontSize: '0.65rem' }}>SOC v1.0</span>
              </div>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <span>Autonomous Detection & Triage</span>
                <span>•</span>
                <span style={{ display: 'inline-flex', alignItems: 'center', gap: '0.25rem', color: '#10b981' }}>
                  <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: '#10b981', display: 'inline-block' }} />
                  Live Loopback Ingestion
                </span>
              </div>
            </div>
          </div>

          {/* Quick Metrics Badges */}
          <div style={{
            display: 'flex',
            alignItems: 'center',
            gap: '0.75rem',
            marginLeft: '1rem',
            paddingLeft: '1rem',
            borderLeft: '1px solid var(--border-color)'
          }}>
            <div style={{
              background: 'var(--bg-tertiary)',
              border: '1px solid var(--border-color)',
              padding: '0.25rem 0.65rem',
              borderRadius: '6px',
              fontSize: '0.75rem',
              display: 'flex',
              alignItems: 'center',
              gap: '0.5rem'
            }}>
              <GitMerge size={14} color="#06b6d4" />
              <span style={{ color: 'var(--text-secondary)' }}>Alert Reduction:</span>
              <strong style={{ color: '#0284c7' }}>{dedupRatio > 0 ? `${dedupRatio}%` : '88.9%'}</strong>
            </div>

            <div style={{
              background: 'var(--bg-tertiary)',
              border: '1px solid var(--border-color)',
              padding: '0.25rem 0.65rem',
              borderRadius: '6px',
              fontSize: '0.75rem',
              display: 'flex',
              alignItems: 'center',
              gap: '0.5rem'
            }}>
              <AlertTriangle size={14} color="#f59e0b" />
              <span style={{ color: 'var(--text-secondary)' }}>Active Incidents:</span>
              <strong style={{ color: '#d97706' }}>{incidentCount}</strong>
            </div>
          </div>
        </div>

        {/* Navigation Tabs */}
        <nav style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <button
            onClick={() => setActiveTab('incidents')}
            className="btn"
            style={{
              background: activeTab === 'incidents' ? 'var(--bg-tertiary)' : 'transparent',
              color: activeTab === 'incidents' ? 'var(--color-primary)' : 'var(--text-secondary)',
              border: activeTab === 'incidents' ? '1px solid var(--color-primary)' : '1px solid transparent',
              fontWeight: activeTab === 'incidents' ? 600 : 500,
            }}
          >
            <ShieldAlert size={16} />
            Incident Queue
            {incidentCount > 0 && (
              <span style={{
                background: '#0284c7',
                color: '#fff',
                fontSize: '0.7rem',
                borderRadius: '999px',
                padding: '0.1rem 0.45rem',
                marginLeft: '0.25rem'
              }}>
                {incidentCount}
              </span>
            )}
          </button>

          <button
            onClick={() => setActiveTab('events')}
            className="btn"
            style={{
              background: activeTab === 'events' ? 'var(--bg-tertiary)' : 'transparent',
              color: activeTab === 'events' ? 'var(--color-primary)' : 'var(--text-secondary)',
              border: activeTab === 'events' ? '1px solid var(--color-primary)' : '1px solid transparent',
              fontWeight: activeTab === 'events' ? 600 : 500,
            }}
          >
            <Search size={16} />
            Event Explorer
          </button>

          <button
            onClick={() => setActiveTab('ai-copilot')}
            className="btn"
            style={{
              background: activeTab === 'ai-copilot' ? 'var(--color-ai-bg)' : 'transparent',
              color: activeTab === 'ai-copilot' ? 'var(--color-ai)' : 'var(--text-secondary)',
              border: activeTab === 'ai-copilot' ? '1px solid var(--color-ai-border)' : '1px solid transparent',
              fontWeight: activeTab === 'ai-copilot' ? 600 : 500,
            }}
          >
            <Sparkles size={16} color={activeTab === 'ai-copilot' ? 'var(--color-ai)' : 'var(--text-secondary)'} />
            AI Copilot
          </button>

          <button
            onClick={() => setActiveTab('response')}
            className="btn"
            style={{
              background: activeTab === 'response' ? 'rgba(16, 185, 129, 0.15)' : 'transparent',
              color: activeTab === 'response' ? '#10b981' : 'var(--text-secondary)',
              border: activeTab === 'response' ? '1px solid #10b981' : '1px solid transparent',
              fontWeight: activeTab === 'response' ? 600 : 500,
            }}
          >
            <ShieldAlert size={16} color={activeTab === 'response' ? '#10b981' : 'var(--text-secondary)'} />
            Response & Containment
          </button>

          <button
            onClick={() => setActiveTab('metrics')}
            className="btn"
            style={{
              background: activeTab === 'metrics' ? 'var(--bg-tertiary)' : 'transparent',
              color: activeTab === 'metrics' ? 'var(--color-primary)' : 'var(--text-secondary)',
              border: activeTab === 'metrics' ? '1px solid var(--color-primary)' : '1px solid transparent',
              fontWeight: activeTab === 'metrics' ? 600 : 500,
            }}
          >
            <Activity size={16} />
            Detection & ML Metrics
          </button>
        </nav>

        {/* Global Action Triggers */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          {correlateMessage && (
            <span style={{ fontSize: '0.75rem', color: '#10b981', display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
              <CheckCircle2 size={13} />
              {correlateMessage}
            </span>
          )}

          <button
            onClick={handleCorrelate}
            disabled={correlating}
            className="btn btn-secondary btn-sm"
            title="Correlate deduplicated alerts across entity graph into incidents"
            style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}
          >
            <GitMerge size={14} className={correlating ? 'spin' : ''} />
            {correlating ? 'Correlating...' : 'Run Correlation'}
          </button>

          <button
            onClick={onRefresh}
            disabled={loading}
            className="btn btn-secondary btn-sm"
            title="Refresh active state from backend"
            style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}
          >
            <RefreshCw size={14} style={{ animation: loading ? 'spin 1s linear infinite' : 'none' }} />
            Refresh
          </button>
        </div>
      </div>
    </header>
  );
};
