import React, { useState, useEffect, useRef } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import {
  Menu,
  Search,
  Bell,
  Settings,
  Clock,
  ChevronRight,
  ShieldAlert,
  X,
  Sun,
  Moon
} from 'lucide-react';

import { useTheme } from '../../context/ThemeContext';
import { api } from '../../services/api';

export interface TopBarProps {
  onToggleSidebar: () => void;
  sidebarCollapsed: boolean;
}

export const TopBar: React.FC<TopBarProps> = ({
  onToggleSidebar,
  sidebarCollapsed: _sidebarCollapsed
}) => {
  const { theme, toggleTheme } = useTheme();
  const location = useLocation();
  const navigate = useNavigate();
  const searchInputRef = useRef<HTMLInputElement>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [currentTime, setCurrentTime] = useState<string>('');
  const [notificationsOpen, setNotificationsOpen] = useState(false);
  const [recentAlerts, setRecentAlerts] = useState<any[]>([]);

  useEffect(() => {
    let isMounted = true;
    const fetchRecent = async () => {
      try {
        const alerts = await api.getAlerts({ limit: 5 });
        if (isMounted && Array.isArray(alerts)) {
          setRecentAlerts(alerts);
        }
      } catch {
        // Silent catch on topbar polling
      }
    };
    fetchRecent();
    const interval = setInterval(fetchRecent, 3000);
    return () => {
      isMounted = false;
      clearInterval(interval);
    };
  }, []);

  // Update clock every minute
  useEffect(() => {
    const updateTime = () => {
      const now = new Date();
      const timeStr = now.toLocaleTimeString([], {
        hour: '2-digit',
        minute: '2-digit',
        hour12: false
      });
      const tzOffset = Intl.DateTimeFormat().resolvedOptions().timeZone;
      const tzAbbr = tzOffset.split('/').pop()?.replace('_', ' ') || 'UTC';
      setCurrentTime(`${timeStr} ${tzAbbr}`);
    };

    updateTime();
    const interval = setInterval(updateTime, 1000 * 30);
    return () => clearInterval(interval);
  }, []);

  // Keyboard shortcut Ctrl+K / Cmd+K to focus search
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        searchInputRef.current?.focus();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  // Format breadcrumbs from pathname
  const formatBreadcrumb = (segment: string) => {
    if (!segment) return '';
    return segment
      .split('-')
      .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
      .join(' ');
  };

  const pathSegments = location.pathname.split('/').filter(Boolean);
  const currentSection = pathSegments.length > 0 ? formatBreadcrumb(pathSegments[0]) : 'Overview';

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!searchQuery.trim()) return;
    navigate(`/events?q=${encodeURIComponent(searchQuery.trim())}`);
  };

  return (
    <header
      style={{
        height: '56px',
        backgroundColor: 'var(--bg-topbar, #0d1117)',
        borderBottom: '1px solid var(--border-sidebar, rgba(255, 255, 255, 0.06))',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        padding: '0 20px',
        position: 'sticky',
        top: 0,
        zIndex: 40,
        width: '100%',
        boxSizing: 'border-box'
      }}
    >
      {/* Left Area: Toggle + Breadcrumbs */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '16px', minWidth: 0 }}>
        <button
          onClick={onToggleSidebar}
          aria-label="Toggle navigation"
          style={{
            background: 'transparent',
            border: 'none',
            color: '#9ca3af',
            cursor: 'pointer',
            padding: '6px',
            borderRadius: '6px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            transition: 'all 0.15s ease'
          }}
          onMouseEnter={(e) => {
            e.currentTarget.style.color = '#ffffff';
            e.currentTarget.style.backgroundColor = 'rgba(255, 255, 255, 0.06)';
          }}
          onMouseLeave={(e) => {
            e.currentTarget.style.color = '#9ca3af';
            e.currentTarget.style.backgroundColor = 'transparent';
          }}
        >
          <Menu size={20} />
        </button>

        {/* Breadcrumb */}
        <nav
          aria-label="Breadcrumb"
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            fontSize: '0.8125rem',
            whiteSpace: 'nowrap',
            overflow: 'hidden'
          }}
        >
          <span
            style={{
              color: 'var(--text-muted, #6b7280)',
              fontWeight: 500,
              cursor: 'pointer'
            }}
            onClick={() => navigate('/overview')}
          >
            ThreatGrid
          </span>
          <ChevronRight size={13} color="var(--text-muted, #4b5563)" />
          <span
            style={{
              color: 'var(--text-primary, #f3f4f6)',
              fontWeight: 600,
              letterSpacing: '-0.01em'
            }}
          >
            {currentSection}
          </span>
          {pathSegments.length > 1 && (
            <>
              <ChevronRight size={13} color="var(--text-muted, #4b5563)" />
              <span
                style={{
                  color: 'var(--text-secondary, #9ca3af)',
                  fontWeight: 500,
                  maxWidth: '180px',
                  overflow: 'hidden',
                  textOverflow: 'ellipsis'
                }}
              >
                {formatBreadcrumb(pathSegments[1])}
              </span>
            </>
          )}
        </nav>
      </div>

      {/* Center: Global Search Bar */}
      <div
        style={{
          flex: '1',
          maxWidth: '520px',
          margin: '0 24px',
          position: 'relative'
        }}
      >
        <form onSubmit={handleSearchSubmit} style={{ position: 'relative', width: '100%' }}>
          <Search
            size={16}
            style={{
              position: 'absolute',
              left: '12px',
              top: '50%',
              transform: 'translateY(-50%)',
              color: '#6b7280',
              pointerEvents: 'none'
            }}
          />
          <input
            ref={searchInputRef}
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search events, alerts, entities..."
            style={{
              width: '100%',
              height: '36px',
              backgroundColor: 'var(--bg-input, #111827)',
              border: '1px solid var(--border-input, rgba(255, 255, 255, 0.08))',
              borderRadius: '6px',
              padding: '0 64px 0 36px',
              color: 'var(--text-primary, #f9fafb)',
              fontSize: '0.8125rem',
              outline: 'none',
              transition: 'all 0.15s ease',
              boxSizing: 'border-box'
            }}
            onFocus={(e) => {
              e.target.style.borderColor = 'var(--color-primary, #3b82f6)';
              e.target.style.boxShadow = '0 0 0 2px var(--color-primary-bg, rgba(59, 130, 246, 0.2))';
            }}
            onBlur={(e) => {
              e.target.style.borderColor = 'var(--border-input, rgba(255, 255, 255, 0.08))';
              e.target.style.boxShadow = 'none';
            }}
          />
          {searchQuery && (
            <button
              type="button"
              onClick={() => setSearchQuery('')}
              style={{
                position: 'absolute',
                right: '48px',
                top: '50%',
                transform: 'translateY(-50%)',
                background: 'transparent',
                border: 'none',
                color: '#6b7280',
                cursor: 'pointer',
                padding: '4px',
                display: 'flex',
                alignItems: 'center'
              }}
            >
              <X size={14} />
            </button>
          )}
          <span
            style={{
              position: 'absolute',
              right: '8px',
              top: '50%',
              transform: 'translateY(-50%)',
              backgroundColor: 'rgba(255, 255, 255, 0.06)',
              border: '1px solid rgba(255, 255, 255, 0.1)',
              borderRadius: '4px',
              padding: '2px 5px',
              fontSize: '0.6875rem',
              fontFamily: 'var(--font-mono, monospace)',
              color: '#9ca3af',
              pointerEvents: 'none',
              lineHeight: 1
            }}
          >
            Ctrl+K
          </span>
        </form>
      </div>

      {/* Right Area: Actions & Profile */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flexShrink: 0 }}>
        {/* Live Clock */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '6px',
            backgroundColor: 'var(--bg-hover, rgba(255, 255, 255, 0.03))',
            border: '1px solid var(--border-color, rgba(255, 255, 255, 0.06))',
            padding: '4px 8px',
            borderRadius: '6px',
            fontSize: '0.75rem',
            fontFamily: 'var(--font-mono, monospace)',
            color: 'var(--text-secondary, #9ca3af)'
          }}
          title="Current SOC Time"
        >
          <Clock size={13} color="#60a5fa" />
          <span>{currentTime || '00:00 UTC'}</span>
        </div>

        {/* Light / Dark Mode Toggle Button */}
        <button
          onClick={toggleTheme}
          aria-label={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
          title={theme === 'dark' ? 'Switch to Light Mode' : 'Switch to Dark Mode'}
          style={{
            width: '34px',
            height: '34px',
            borderRadius: '6px',
            background: 'transparent',
            border: '1px solid var(--border-color, rgba(255, 255, 255, 0.08))',
            color: theme === 'dark' ? '#fbbf24' : '#6366f1',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            cursor: 'pointer',
            transition: 'all 0.15s ease'
          }}
          onMouseEnter={(e) => {
            e.currentTarget.style.backgroundColor = 'var(--bg-hover, rgba(255, 255, 255, 0.05))';
            e.currentTarget.style.color = theme === 'dark' ? '#f59e0b' : '#4f46e5';
          }}
          onMouseLeave={(e) => {
            e.currentTarget.style.backgroundColor = 'transparent';
            e.currentTarget.style.color = theme === 'dark' ? '#fbbf24' : '#6366f1';
          }}
        >
          {theme === 'dark' ? <Sun size={17} /> : <Moon size={17} />}
        </button>

        {/* Notifications Button */}
        <div style={{ position: 'relative' }}>
          <button
            onClick={() => setNotificationsOpen(!notificationsOpen)}
            aria-label="Notifications"
            style={{
              width: '34px',
              height: '34px',
              borderRadius: '6px',
              background: notificationsOpen ? 'rgba(59, 130, 246, 0.15)' : 'transparent',
              border: '1px solid var(--border-color, rgba(255, 255, 255, 0.06))',
              color: notificationsOpen ? '#60a5fa' : 'var(--text-secondary, #9ca3af)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              cursor: 'pointer',
              position: 'relative',
              transition: 'all 0.15s ease'
            }}
            onMouseEnter={(e) => {
              e.currentTarget.style.color = 'var(--text-primary, #ffffff)';
              e.currentTarget.style.backgroundColor = 'var(--bg-hover, rgba(255, 255, 255, 0.05))';
            }}
            onMouseLeave={(e) => {
              if (!notificationsOpen) {
                e.currentTarget.style.color = 'var(--text-secondary, #9ca3af)';
                e.currentTarget.style.backgroundColor = 'transparent';
              }
            }}
          >
            <Bell size={17} />
            {recentAlerts.length > 0 && (
              <span
                style={{
                  position: 'absolute',
                  top: '4px',
                  right: '4px',
                  backgroundColor: '#ef4444',
                  color: '#ffffff',
                  fontSize: '0.625rem',
                  fontWeight: 700,
                  width: '16px',
                  height: '16px',
                  borderRadius: '50%',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  boxShadow: '0 0 6px rgba(239, 68, 68, 0.5)'
                }}
              >
                {recentAlerts.length}
              </span>
            )}
          </button>

          {/* Quick Notifications Dropdown */}
          {notificationsOpen && (
            <div
              style={{
                position: 'absolute',
                top: '44px',
                right: 0,
                width: '320px',
                backgroundColor: 'var(--bg-elevated, #111827)',
                border: '1px solid var(--border-color, rgba(255, 255, 255, 0.1))',
                borderRadius: '8px',
                boxShadow: 'var(--shadow-xl, 0 10px 25px -5px rgba(0, 0, 0, 0.6))',
                zIndex: 100,
                overflow: 'hidden'
              }}
            >
              <div
                style={{
                  padding: '10px 14px',
                  borderBottom: '1px solid var(--border-color, rgba(255, 255, 255, 0.06))',
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center'
                }}
              >
                <span style={{ fontSize: '0.8125rem', fontWeight: 600, color: 'var(--text-primary, #ffffff)' }}>
                  Recent Alerts ({recentAlerts.length})
                </span>
                <span
                  style={{ fontSize: '0.7rem', color: 'var(--color-primary, #3b82f6)', cursor: 'pointer' }}
                  onClick={() => setNotificationsOpen(false)}
                >
                  Close
                </span>
              </div>
              <div style={{ maxHeight: '240px', overflowY: 'auto' }}>
                {recentAlerts.length === 0 ? (
                  <div style={{ padding: '16px', textAlign: 'center', color: 'var(--text-muted, #6b7280)', fontSize: '0.75rem' }}>
                    No security alerts evaluated
                  </div>
                ) : (
                  recentAlerts.map((n) => {
                    const sevColor = n.severity === 'critical' ? '#ef4444' : n.severity === 'high' ? '#f97316' : '#3b82f6';
                    return (
                      <div
                        key={n.alert_id}
                        style={{
                          padding: '10px 14px',
                          borderBottom: '1px solid var(--border-subtle, rgba(255, 255, 255, 0.04))',
                          display: 'flex',
                          gap: '10px',
                          cursor: 'pointer'
                        }}
                        onClick={() => {
                          setNotificationsOpen(false);
                          navigate('/alerts');
                        }}
                      >
                        <div
                          style={{
                            width: '8px',
                            height: '8px',
                            borderRadius: '50%',
                            backgroundColor: sevColor,
                            marginTop: '5px',
                            flexShrink: 0
                          }}
                        />
                        <div>
                          <div style={{ fontSize: '0.78rem', color: 'var(--text-primary, #f3f4f6)', fontWeight: 500 }}>
                            {n.rule_name || n.rule_id}
                          </div>
                          <div style={{ fontSize: '0.6875rem', color: 'var(--text-muted, #6b7280)', marginTop: '2px' }}>
                            {n.timestamp ? new Date(n.timestamp).toLocaleTimeString() : 'Recent'} &bull; {n.severity?.toUpperCase()}
                          </div>
                        </div>
                      </div>
                    );
                  })
                )}
              </div>
              <div
                style={{
                  padding: '8px',
                  textAlign: 'center',
                  backgroundColor: 'var(--bg-tertiary, rgba(0, 0, 0, 0.2))',
                  borderTop: '1px solid var(--border-subtle, rgba(255, 255, 255, 0.04))'
                }}
              >
                <button
                  onClick={() => {
                    setNotificationsOpen(false);
                    navigate('/alerts');
                  }}
                  style={{
                    background: 'transparent',
                    border: 'none',
                    color: 'var(--color-primary, #60a5fa)',
                    fontSize: '0.75rem',
                    fontWeight: 600,
                    cursor: 'pointer'
                  }}
                >
                  View all alerts
                </button>
              </div>
            </div>
          )}
        </div>

        {/* Settings Button */}
        <button
          onClick={() => navigate('/settings')}
          aria-label="Settings"
          style={{
            width: '34px',
            height: '34px',
            borderRadius: '6px',
            background: 'transparent',
            border: '1px solid var(--border-color, rgba(255, 255, 255, 0.06))',
            color: 'var(--text-secondary, #9ca3af)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            cursor: 'pointer',
            transition: 'all 0.15s ease'
          }}
          onMouseEnter={(e) => {
            e.currentTarget.style.color = 'var(--text-primary, #ffffff)';
            e.currentTarget.style.backgroundColor = 'var(--bg-hover, rgba(255, 255, 255, 0.05))';
          }}
          onMouseLeave={(e) => {
            e.currentTarget.style.color = 'var(--text-secondary, #9ca3af)';
            e.currentTarget.style.backgroundColor = 'transparent';
          }}
          title="Platform Settings"
        >
          <Settings size={17} />
        </button>

        {/* User Avatar Circle */}
        <div
          style={{
            position: 'relative',
            display: 'flex',
            alignItems: 'center',
            cursor: 'pointer'
          }}
          title="SOC Analyst (Tier 2)"
          onClick={() => navigate('/settings')}
        >
          <div
            style={{
              width: '34px',
              height: '34px',
              borderRadius: '50%',
              background: 'linear-gradient(135deg, #1e293b, #334155)',
              border: '1.5px solid rgba(59, 130, 246, 0.5)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              fontWeight: 700,
              fontSize: '0.75rem',
              color: '#f9fafb',
              letterSpacing: '0.04em'
            }}
          >
            SA
          </div>
          {/* Online green indicator */}
          <span
            style={{
              position: 'absolute',
              bottom: 0,
              right: 0,
              width: '9px',
              height: '9px',
              borderRadius: '50%',
              backgroundColor: '#10b981',
              border: '1.5px solid var(--bg-topbar, #0d1117)'
            }}
          />
        </div>
      </div>
    </header>
  );
};
