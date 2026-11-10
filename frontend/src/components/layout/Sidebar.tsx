import React from 'react';
import { Link } from 'react-router-dom';
import {
  LayoutDashboard,
  Bell,
  AlertTriangle,
  Search,
  Users,
  Server,
  Globe,
  TrendingUp,
  Shield,
  FileText,
  Bot,
  BookOpen,
  Zap,
  Settings,
  ShieldCheck,
  ChevronLeft,
  ChevronRight,
  Activity,
  X
} from 'lucide-react';

export interface SidebarProps {
  currentPath: string;
  collapsed: boolean;
  onToggleCollapse: () => void;
  mobileOpen?: boolean;
  onCloseMobile?: () => void;
}

interface NavItem {
  id: string;
  label: string;
  path: string;
  icon: React.ComponentType<{ size?: number | string; className?: string; style?: React.CSSProperties }>;
  badge?: number;
  badgeColor?: string;
}

interface NavSection {
  title: string;
  items: NavItem[];
}

import { api } from '../../services/api';

interface HealthIndicator {
  name: string;
  status: 'healthy' | 'warning' | 'error';
  latency?: string;
}

const BASE_NAV_SECTIONS: NavSection[] = [
  {
    title: 'MAIN',
    items: [
      { id: 'overview', label: 'Overview', path: '/overview', icon: LayoutDashboard },
      { id: 'alerts', label: 'Alerts', path: '/alerts', icon: Bell, badgeColor: '#ef4444' },
      { id: 'incidents', label: 'Incidents', path: '/incidents', icon: AlertTriangle, badgeColor: '#f97316' },
      { id: 'events', label: 'Events', path: '/events', icon: Search }
    ]
  },
  {
    title: 'INVESTIGATION',
    items: [
      { id: 'entities', label: 'Entities', path: '/entities', icon: Users },
      { id: 'assets', label: 'Assets', path: '/assets', icon: Server },
      { id: 'threat-intel', label: 'Threat Intel', path: '/threat-intel', icon: Globe },
      { id: 'analytics', label: 'Analytics', path: '/analytics', icon: TrendingUp }
    ]
  },
  {
    title: 'MANAGEMENT',
    items: [
      { id: 'rules', label: 'Rules', path: '/rules', icon: Shield },
      { id: 'reports', label: 'Reports', path: '/reports', icon: FileText },
      { id: 'ai-assistant', label: 'AI Assistant', path: '/ai-assistant', icon: Bot },
      { id: 'playbooks', label: 'Playbooks', path: '/playbooks', icon: BookOpen },
      { id: 'automation', label: 'Automation', path: '/automation', icon: Zap },
      { id: 'settings', label: 'Settings', path: '/settings', icon: Settings }
    ]
  }
];

export const Sidebar: React.FC<SidebarProps> = ({
  currentPath,
  collapsed,
  onToggleCollapse,
  mobileOpen = false,
  onCloseMobile
}) => {
  const [hoveredPath, setHoveredPath] = React.useState<string | null>(null);
  const [alertsCount, setAlertsCount] = React.useState<number>(0);
  const [incidentsCount, setIncidentsCount] = React.useState<number>(0);
  const [systemHealth, setSystemHealth] = React.useState<HealthIndicator[]>([
    { name: 'Ingestion', status: 'healthy', latency: 'active' },
    { name: 'Storage', status: 'healthy', latency: 'syncing' },
    { name: 'ML Models', status: 'warning', latency: 'eval' },
    { name: 'Database', status: 'healthy', latency: 'WAL' }
  ]);

  React.useEffect(() => {
    let isMounted = true;
    const fetchTelemetry = async () => {
      try {
        const [alerts, incData, health, mlStatus] = await Promise.allSettled([
          api.getAlerts({ limit: 100 }),
          api.getIncidents({ limit: 1 }),
          api.getSystemHealth(),
          api.getMLStatus()
        ]);

        if (!isMounted) return;

        if (alerts.status === 'fulfilled' && Array.isArray(alerts.value)) {
          setAlertsCount(alerts.value.length);
        }

        if (incData.status === 'fulfilled' && incData.value) {
          setIncidentsCount(incData.value.total || 0);
        }

        const newHealth: HealthIndicator[] = [];

        // Ingestion status
        if (health.status === 'fulfilled' && health.value.status === 'ok') {
          newHealth.push({ name: 'Ingestion', status: 'healthy', latency: `${Math.round(health.value.uptime_seconds)}s` });
          newHealth.push({ name: 'Storage', status: 'healthy', latency: `${health.value.events_stored} evts` });
          newHealth.push({ name: 'Database', status: health.value.database === 'connected' ? 'healthy' : 'error', latency: 'WAL' });
        } else {
          newHealth.push({ name: 'Ingestion', status: 'error', latency: 'offline' });
          newHealth.push({ name: 'Storage', status: 'warning', latency: 'unknown' });
          newHealth.push({ name: 'Database', status: 'error', latency: 'disconnected' });
        }

        // ML status
        if (mlStatus.status === 'fulfilled' && mlStatus.value) {
          const isTrained = mlStatus.value.is_trained;
          newHealth.splice(2, 0, {
            name: 'ML Models',
            status: isTrained ? 'healthy' : 'warning',
            latency: isTrained ? `${mlStatus.value.baseline_samples_count} fit` : 'uncalibrated'
          });
        } else {
          newHealth.splice(2, 0, {
            name: 'ML Models',
            status: 'warning',
            latency: 'offline'
          });
        }

        setSystemHealth(newHealth);
      } catch (err) {
        console.warn('Failed to refresh sidebar telemetry:', err);
      }
    };

    fetchTelemetry();
    const timer = setInterval(fetchTelemetry, 15000);
    return () => {
      isMounted = false;
      clearInterval(timer);
    };
  }, []);

  const navSections: NavSection[] = BASE_NAV_SECTIONS.map((section) => ({
    ...section,
    items: section.items.map((item) => {
      if (item.id === 'alerts') {
        return { ...item, badge: alertsCount > 0 ? alertsCount : undefined };
      }
      if (item.id === 'incidents') {
        return { ...item, badge: incidentsCount > 0 ? incidentsCount : undefined };
      }
      return item;
    })
  }));

  const getHealthColor = (status: 'healthy' | 'warning' | 'error') => {
    switch (status) {
      case 'healthy':
        return '#10b981';
      case 'warning':
        return '#f59e0b';
      case 'error':
        return '#ef4444';
      default:
        return '#6b7280';
    }
  };

  const isItemActive = (path: string) => {
    if (path === '/overview' && (currentPath === '/' || currentPath === '/overview')) {
      return true;
    }
    return currentPath === path || currentPath.startsWith(path + '/');
  };

  return (
    <aside
      className={`threatgrid-sidebar ${collapsed ? 'collapsed' : ''} ${mobileOpen ? 'mobile-open' : ''}`}
      style={{
        width: collapsed ? '64px' : '240px',
        minWidth: collapsed ? '64px' : '240px',
        height: '100vh',
        backgroundColor: 'var(--bg-sidebar, #0d1117)',
        borderRight: '1px solid var(--border-sidebar, rgba(255, 255, 255, 0.06))',
        display: 'flex',
        flexDirection: 'column',
        position: 'sticky',
        top: 0,
        left: 0,
        zIndex: 50,
        transition: 'width 0.25s cubic-bezier(0.4, 0, 0.2, 1), min-width 0.25s cubic-bezier(0.4, 0, 0.2, 1), transform 0.25s ease',
        userSelect: 'none',
        overflow: 'hidden'
      }}
    >
      {/* Brand Header */}
      <div
        style={{
          height: '56px',
          padding: collapsed ? '0 12px' : '0 16px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: collapsed ? 'center' : 'space-between',
          borderBottom: '1px solid var(--border-sidebar, rgba(255, 255, 255, 0.06))',
          position: 'relative'
        }}
      >
        <Link
          to="/overview"
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '10px',
            textDecoration: 'none',
            color: 'inherit',
            overflow: 'hidden'
          }}
          title="ThreatGrid SOC"
        >
          <div
            style={{
              width: '34px',
              height: '34px',
              borderRadius: '8px',
              background: 'linear-gradient(135deg, #2563eb, #6366f1)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              flexShrink: 0,
              boxShadow: '0 0 12px rgba(59, 130, 246, 0.35)'
            }}
          >
            <ShieldCheck size={20} color="#ffffff" strokeWidth={2.2} />
          </div>

          {!collapsed && (
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <span
                style={{
                  fontWeight: 700,
                  fontSize: '1rem',
                  letterSpacing: '-0.02em',
                  color: '#ffffff',
                  whiteSpace: 'nowrap'
                }}
              >
                ThreatGrid
              </span>
              <span
                style={{
                  fontSize: '0.65rem',
                  fontWeight: 700,
                  color: 'var(--accent-blue, #3b82f6)',
                  backgroundColor: 'rgba(59, 130, 246, 0.15)',
                  border: '1px solid rgba(59, 130, 246, 0.3)',
                  padding: '1px 5px',
                  borderRadius: '4px',
                  letterSpacing: '0.04em'
                }}
              >
                SOC
              </span>
            </div>
          )}
        </Link>

        {/* Mobile close button / Desktop collapse toggle */}
        {mobileOpen && (
          <button
            onClick={onCloseMobile}
            style={{
              background: 'transparent',
              border: 'none',
              color: '#9ca3af',
              cursor: 'pointer',
              padding: '6px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              borderRadius: '4px'
            }}
            aria-label="Close sidebar"
          >
            <X size={18} />
          </button>
        )}
      </div>

      {/* Navigation Links (Scrollable) */}
      <div
        style={{
          flex: 1,
          overflowY: 'auto',
          overflowX: 'hidden',
          padding: '12px 0',
          scrollbarWidth: 'thin'
        }}
      >
        {navSections.map((section, sIdx) => (
          <div key={section.title} style={{ marginBottom: '16px' }}>
            {/* Section Header */}
            {!collapsed ? (
              <div
                style={{
                  padding: '4px 18px 6px',
                  fontSize: '0.6875rem',
                  fontWeight: 700,
                  textTransform: 'uppercase',
                  letterSpacing: '0.08em',
                  color: '#6b7280'
                }}
              >
                {section.title}
              </div>
            ) : (
              sIdx > 0 && (
                <div
                  style={{
                    height: '1px',
                    backgroundColor: 'rgba(255, 255, 255, 0.05)',
                    margin: '8px 12px'
                  }}
                />
              )
            )}

            {/* Nav items */}
            {section.items.map((item) => {
              const active = isItemActive(item.path);
              const hovered = hoveredPath === item.path;
              const Icon = item.icon;

              return (
                <Link
                  key={item.id}
                  to={item.path}
                  onMouseEnter={() => setHoveredPath(item.path)}
                  onMouseLeave={() => setHoveredPath(null)}
                  onClick={() => {
                    if (onCloseMobile) onCloseMobile();
                  }}
                  title={collapsed ? item.label : undefined}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: collapsed ? 'center' : 'space-between',
                    padding: collapsed ? '9px 0' : '9px 16px',
                    margin: '1px 0',
                    textDecoration: 'none',
                    fontSize: '0.85rem',
                    fontWeight: active ? 600 : 500,
                    color: active ? '#ffffff' : hovered ? '#f3f4f6' : '#9ca3af',
                    backgroundColor: active
                      ? 'var(--bg-sidebar-active, rgba(59, 130, 246, 0.1))'
                      : hovered
                      ? 'var(--bg-sidebar-hover, rgba(255, 255, 255, 0.04))'
                      : 'transparent',
                    borderLeft: active
                      ? '3px solid var(--accent-blue, #3b82f6)'
                      : '3px solid transparent',
                    transition: 'all 0.15s ease',
                    position: 'relative'
                  }}
                >
                  <div
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: '12px',
                      minWidth: 0
                    }}
                  >
                    <Icon
                      size={18}
                      style={{
                        color: active ? '#3b82f6' : hovered ? '#d1d5db' : '#8590a5',
                        flexShrink: 0,
                        transition: 'color 0.15s ease'
                      }}
                    />

                    {!collapsed && (
                      <span
                        style={{
                          whiteSpace: 'nowrap',
                          overflow: 'hidden',
                          textOverflow: 'ellipsis'
                        }}
                      >
                        {item.label}
                      </span>
                    )}
                  </div>

                  {/* Badges */}
                  {item.badge !== undefined && item.badge > 0 && (
                    <>
                      {!collapsed ? (
                        <span
                          style={{
                            backgroundColor: item.badgeColor || 'var(--accent-blue, #3b82f6)',
                            color: '#ffffff',
                            fontSize: '0.6875rem',
                            fontWeight: 700,
                            padding: '1px 6px',
                            borderRadius: '9999px',
                            lineHeight: 1.3,
                            boxShadow: '0 1px 3px rgba(0,0,0,0.3)',
                            flexShrink: 0
                          }}
                        >
                          {item.badge}
                        </span>
                      ) : (
                        <span
                          style={{
                            position: 'absolute',
                            top: '6px',
                            right: '12px',
                            width: '8px',
                            height: '8px',
                            borderRadius: '50%',
                            backgroundColor: item.badgeColor || 'var(--accent-blue, #3b82f6)',
                            border: '1.5px solid var(--bg-sidebar, #0d1117)'
                          }}
                          title={`${item.label}: ${item.badge}`}
                        />
                      )}
                    </>
                  )}
                </Link>
              );
            })}
          </div>
        ))}
      </div>

      {/* Bottom Section: System Health */}
      <div
        style={{
          borderTop: '1px solid var(--border-sidebar, rgba(255, 255, 255, 0.06))',
          backgroundColor: 'rgba(0, 0, 0, 0.2)',
          padding: collapsed ? '12px 8px' : '12px 14px',
          flexShrink: 0
        }}
      >
        {!collapsed ? (
          <div>
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                marginBottom: '8px'
              }}
            >
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px',
                  fontSize: '0.6875rem',
                  fontWeight: 700,
                  textTransform: 'uppercase',
                  letterSpacing: '0.06em',
                  color: '#6b7280'
                }}
              >
                <Activity size={13} color="#3b82f6" />
                <span>System Health</span>
              </div>
              <span
                style={{
                  fontSize: '0.625rem',
                  color: '#10b981',
                  fontWeight: 600
                }}
              >
                Operational
              </span>
            </div>

            <div
              style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(2, 1fr)',
                gap: '6px 8px'
              }}
            >
              {systemHealth.map((item) => (
                <div
                  key={item.name}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    fontSize: '0.72rem',
                    color: '#9ca3af',
                    backgroundColor: 'rgba(255, 255, 255, 0.02)',
                    padding: '3px 6px',
                    borderRadius: '4px',
                    border: '1px solid rgba(255, 255, 255, 0.03)'
                  }}
                  title={`${item.name} (${item.status}) - ${item.latency || 'OK'}`}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '5px' }}>
                    <span
                      style={{
                        width: '6px',
                        height: '6px',
                        borderRadius: '50%',
                        backgroundColor: getHealthColor(item.status),
                        boxShadow: `0 0 6px ${getHealthColor(item.status)}`
                      }}
                    />
                    <span style={{ fontSize: '0.7rem' }}>{item.name}</span>
                  </div>
                  <span
                    style={{
                      fontSize: '0.65rem',
                      fontFamily: 'var(--font-mono, monospace)',
                      color: '#6b7280'
                    }}
                  >
                    {item.latency}
                  </span>
                </div>
              ))}
            </div>
          </div>
        ) : (
          /* Collapsed Health Indicator */
          <div
            style={{
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              gap: '6px'
            }}
            title="System Status: All services healthy"
          >
            <div
              style={{
                display: 'flex',
                gap: '4px',
                alignItems: 'center',
                justifyContent: 'center',
                padding: '4px'
              }}
            >
              {systemHealth.map((item) => (
                <span
                  key={item.name}
                  style={{
                    width: '6px',
                    height: '6px',
                    borderRadius: '50%',
                    backgroundColor: getHealthColor(item.status),
                    boxShadow: `0 0 4px ${getHealthColor(item.status)}`
                  }}
                  title={`${item.name}: ${item.status}`}
                />
              ))}
            </div>
          </div>
        )}

        {/* Collapse toggle footer button */}
        <button
          onClick={onToggleCollapse}
          aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          style={{
            marginTop: '8px',
            width: '100%',
            height: '28px',
            background: 'transparent',
            border: '1px solid rgba(255, 255, 255, 0.04)',
            borderRadius: '4px',
            color: '#6b7280',
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            gap: '6px',
            fontSize: '0.75rem',
            transition: 'all 0.15s ease'
          }}
          onMouseEnter={(e) => {
            e.currentTarget.style.color = '#ffffff';
            e.currentTarget.style.backgroundColor = 'rgba(255, 255, 255, 0.05)';
          }}
          onMouseLeave={(e) => {
            e.currentTarget.style.color = '#6b7280';
            e.currentTarget.style.backgroundColor = 'transparent';
          }}
        >
          {collapsed ? (
            <ChevronRight size={14} />
          ) : (
            <>
              <ChevronLeft size={14} />
              <span style={{ fontSize: '0.7rem', fontWeight: 500 }}>Collapse Menu</span>
            </>
          )}
        </button>
      </div>
    </aside>
  );
};
