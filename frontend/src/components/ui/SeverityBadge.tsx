import React from 'react';

export type SeverityLevel = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface SeverityBadgeProps {
  severity: SeverityLevel;
  size?: 'sm' | 'md';
  withDot?: boolean;
  className?: string;
}

interface SeverityConfig {
  color: string;
  bg: string;
  border: string;
  label: string;
}

const SEVERITY_CONFIGS: Record<SeverityLevel, SeverityConfig> = {
  critical: {
    color: '#ef4444',
    bg: 'rgba(239, 68, 68, 0.15)',
    border: 'rgba(239, 68, 68, 0.35)',
    label: 'Critical'
  },
  high: {
    color: '#f97316',
    bg: 'rgba(249, 115, 22, 0.15)',
    border: 'rgba(249, 115, 22, 0.35)',
    label: 'High'
  },
  medium: {
    color: '#eab308',
    bg: 'rgba(234, 179, 8, 0.15)',
    border: 'rgba(234, 179, 8, 0.35)',
    label: 'Medium'
  },
  low: {
    color: '#06b6d4',
    bg: 'rgba(6, 182, 212, 0.15)',
    border: 'rgba(6, 182, 212, 0.35)',
    label: 'Low'
  },
  info: {
    color: '#8b5cf6',
    bg: 'rgba(139, 92, 246, 0.15)',
    border: 'rgba(139, 92, 246, 0.35)',
    label: 'Info'
  }
};

export const SeverityBadge: React.FC<SeverityBadgeProps> = ({
  severity,
  size = 'md',
  withDot = false,
  className = ''
}) => {
  // Normalize lowercase
  const normalizedSeverity = (severity?.toLowerCase() || 'info') as SeverityLevel;
  const config = SEVERITY_CONFIGS[normalizedSeverity] || SEVERITY_CONFIGS.info;

  const isSmall = size === 'sm';
  const isCritical = normalizedSeverity === 'critical';

  return (
    <>
      <style>{`
        @keyframes severityPulse {
          0% {
            transform: scale(0.95);
            box-shadow: 0 0 0 0 rgba(239, 68, 68, 0.7);
          }
          70% {
            transform: scale(1.1);
            box-shadow: 0 0 0 5px rgba(239, 68, 68, 0);
          }
          100% {
            transform: scale(0.95);
            box-shadow: 0 0 0 0 rgba(239, 68, 68, 0);
          }
        }
      `}</style>
      <span
        className={`threatgrid-severity-badge ${className}`}
        style={{
          display: 'inline-flex',
          alignItems: 'center',
          gap: isSmall ? '4px' : '6px',
          padding: isSmall ? '1px 6px' : '3px 8px',
          fontSize: isSmall ? '0.6875rem' : '0.75rem',
          fontWeight: 600,
          lineHeight: 1.25,
          letterSpacing: '0.04em',
          textTransform: 'uppercase',
          borderRadius: '4px',
          color: config.color,
          backgroundColor: config.bg,
          border: `1px solid ${config.border}`,
          whiteSpace: 'nowrap',
          userSelect: 'none'
        }}
      >
        {withDot && (
          <span
            style={{
              position: 'relative',
              display: 'inline-flex',
              width: isSmall ? '5px' : '6px',
              height: isSmall ? '5px' : '6px'
            }}
          >
            <span
              style={{
                width: '100%',
                height: '100%',
                borderRadius: '50%',
                backgroundColor: config.color,
                animation: isCritical ? 'severityPulse 1.8s infinite' : 'none'
              }}
            />
          </span>
        )}
        <span>{config.label}</span>
      </span>
    </>
  );
};
