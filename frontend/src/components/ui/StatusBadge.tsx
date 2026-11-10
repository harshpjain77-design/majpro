import React from 'react';

export interface StatusBadgeProps {
  status: string;
  variant?: 'default' | 'outline';
  className?: string;
  withDot?: boolean;
}

interface StatusTheme {
  color: string;
  bg: string;
  border: string;
  displayName: string;
}

const getStatusTheme = (rawStatus: string): StatusTheme => {
  const s = (rawStatus || '').toUpperCase().trim().replace(/[- ]+/g, '_');

  switch (s) {
    case 'NEW':
    case 'OPEN':
    case 'UNACKNOWLEDGED':
      return {
        color: '#06b6d4',
        bg: 'rgba(6, 182, 212, 0.15)',
        border: 'rgba(6, 182, 212, 0.35)',
        displayName: 'New'
      };

    case 'INVESTIGATING':
    case 'IN_PROGRESS':
    case 'ACTIVE':
    case 'ASSIGNED':
      return {
        color: '#f59e0b',
        bg: 'rgba(245, 158, 11, 0.15)',
        border: 'rgba(245, 158, 11, 0.35)',
        displayName: 'Investigating'
      };

    case 'ACKNOWLEDGED':
    case 'TRIAGED':
      return {
        color: '#3b82f6',
        bg: 'rgba(59, 130, 246, 0.15)',
        border: 'rgba(59, 130, 246, 0.35)',
        displayName: 'Acknowledged'
      };

    case 'RESOLVED':
    case 'MITIGATED':
    case 'FIXED':
    case 'HEALTHY':
      return {
        color: '#10b981',
        bg: 'rgba(16, 185, 129, 0.15)',
        border: 'rgba(16, 185, 129, 0.35)',
        displayName: 'Resolved'
      };

    case 'CLOSED':
      return {
        color: '#8b5cf6',
        bg: 'rgba(139, 92, 246, 0.15)',
        border: 'rgba(139, 92, 246, 0.35)',
        displayName: 'Closed'
      };

    case 'ESCALATED':
    case 'CRITICAL':
    case 'ERROR':
    case 'BREACH':
      return {
        color: '#ef4444',
        bg: 'rgba(239, 68, 68, 0.15)',
        border: 'rgba(239, 68, 68, 0.35)',
        displayName: 'Escalated'
      };

    case 'FALSE_POSITIVE':
    case 'SUPPRESSED':
    case 'IGNORED':
    case 'DISMISSED':
    case 'ARCHIVED':
      return {
        color: '#9ca3af',
        bg: 'rgba(156, 163, 175, 0.12)',
        border: 'rgba(156, 163, 175, 0.25)',
        displayName: s.replace(/_/g, ' ')
      };

    default:
      // Fallback
      return {
        color: '#94a3b8',
        bg: 'rgba(148, 163, 184, 0.12)',
        border: 'rgba(148, 163, 184, 0.25)',
        displayName: rawStatus || 'Unknown'
      };
  }
};

export const StatusBadge: React.FC<StatusBadgeProps> = ({
  status,
  variant = 'default',
  className = '',
  withDot = true
}) => {
  const theme = getStatusTheme(status);
  const isOutline = variant === 'outline';

  return (
    <span
      className={`threatgrid-status-badge ${className}`}
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: '5px',
        padding: '2px 8px',
        fontSize: '0.72rem',
        fontWeight: 600,
        lineHeight: 1.3,
        letterSpacing: '0.04em',
        textTransform: 'uppercase',
        borderRadius: '4px',
        color: theme.color,
        backgroundColor: isOutline ? 'transparent' : theme.bg,
        border: `1px solid ${theme.border}`,
        whiteSpace: 'nowrap',
        userSelect: 'none'
      }}
    >
      {withDot && (
        <span
          style={{
            width: '6px',
            height: '6px',
            borderRadius: '50%',
            backgroundColor: theme.color,
            flexShrink: 0
          }}
        />
      )}
      <span>{theme.displayName}</span>
    </span>
  );
};
