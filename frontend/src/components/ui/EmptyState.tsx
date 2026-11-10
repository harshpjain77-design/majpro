import React from 'react';
import { Inbox } from 'lucide-react';

export interface EmptyStateProps {
  icon?: React.ReactNode;
  title: string;
  description?: string;
  action?: { label: string; onClick: () => void };
  className?: string;
  compact?: boolean;
}

export const EmptyState: React.FC<EmptyStateProps> = ({
  icon,
  title,
  description,
  action,
  className = '',
  compact = false
}) => {
  return (
    <div
      className={`threatgrid-empty-state ${className}`}
      style={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        textAlign: 'center',
        padding: compact ? '24px 16px' : '48px 24px',
        width: '100%',
        boxSizing: 'border-box'
      }}
    >
      {/* Icon with soft circular backdrop */}
      <div
        style={{
          width: compact ? '48px' : '64px',
          height: compact ? '48px' : '64px',
          borderRadius: '50%',
          backgroundColor: 'rgba(255, 255, 255, 0.03)',
          border: '1px solid rgba(255, 255, 255, 0.06)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          color: '#6b7280',
          marginBottom: compact ? '12px' : '16px'
        }}
      >
        {icon || <Inbox size={compact ? 24 : 32} strokeWidth={1.5} />}
      </div>

      {/* Title */}
      <h3
        style={{
          fontSize: compact ? '0.9375rem' : '1.0625rem',
          fontWeight: 600,
          color: '#f3f4f6',
          margin: 0,
          marginBottom: description ? '6px' : 0,
          letterSpacing: '-0.01em'
        }}
      >
        {title}
      </h3>

      {/* Description */}
      {description && (
        <p
          style={{
            fontSize: '0.8125rem',
            color: '#9ca3af',
            maxWidth: '420px',
            margin: 0,
            lineHeight: 1.5
          }}
        >
          {description}
        </p>
      )}

      {/* Optional Action Button */}
      {action && (
        <button
          onClick={action.onClick}
          type="button"
          style={{
            marginTop: '16px',
            padding: '7px 16px',
            fontSize: '0.8125rem',
            fontWeight: 600,
            color: '#ffffff',
            backgroundColor: 'var(--accent-blue, #3b82f6)',
            border: '1px solid #2563eb',
            borderRadius: '6px',
            cursor: 'pointer',
            transition: 'all 0.15s ease',
            display: 'inline-flex',
            alignItems: 'center',
            justifyContent: 'center',
            boxShadow: '0 1px 3px rgba(0, 0, 0, 0.3)'
          }}
          onMouseEnter={(e) => {
            e.currentTarget.style.backgroundColor = '#2563eb';
          }}
          onMouseLeave={(e) => {
            e.currentTarget.style.backgroundColor = 'var(--accent-blue, #3b82f6)';
          }}
        >
          {action.label}
        </button>
      )}
    </div>
  );
};
