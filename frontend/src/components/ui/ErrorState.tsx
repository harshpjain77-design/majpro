import React from 'react';
import { AlertCircle, RefreshCw } from 'lucide-react';

export interface ErrorStateProps {
  title?: string;
  message: string;
  onRetry?: () => void;
  className?: string;
  compact?: boolean;
}

export const ErrorState: React.FC<ErrorStateProps> = ({
  title = 'An error occurred',
  message,
  onRetry,
  className = '',
  compact = false
}) => {
  return (
    <div
      className={`threatgrid-error-state ${className}`}
      style={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        textAlign: 'center',
        padding: compact ? '20px 16px' : '40px 24px',
        backgroundColor: 'rgba(239, 68, 68, 0.04)',
        border: '1px solid rgba(239, 68, 68, 0.2)',
        borderRadius: '8px',
        width: '100%',
        boxSizing: 'border-box'
      }}
    >
      {/* Icon with subtle red glow */}
      <div
        style={{
          width: compact ? '40px' : '52px',
          height: compact ? '40px' : '52px',
          borderRadius: '50%',
          backgroundColor: 'rgba(239, 68, 68, 0.12)',
          border: '1px solid rgba(239, 68, 68, 0.3)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          color: '#ef4444',
          marginBottom: compact ? '10px' : '14px',
          boxShadow: '0 0 16px rgba(239, 68, 68, 0.2)'
        }}
      >
        <AlertCircle size={compact ? 22 : 28} />
      </div>

      {/* Error Title */}
      <h3
        style={{
          fontSize: compact ? '0.875rem' : '1rem',
          fontWeight: 600,
          color: '#f87171',
          margin: 0,
          marginBottom: '6px'
        }}
      >
        {title}
      </h3>

      {/* Error Message */}
      <p
        style={{
          fontSize: '0.8125rem',
          color: '#9ca3af',
          maxWidth: '460px',
          margin: 0,
          lineHeight: 1.5,
          wordBreak: 'break-word'
        }}
      >
        {message}
      </p>

      {/* Retry Button */}
      {onRetry && (
        <button
          type="button"
          onClick={onRetry}
          style={{
            marginTop: '16px',
            display: 'inline-flex',
            alignItems: 'center',
            gap: '8px',
            padding: '7px 16px',
            backgroundColor: '#1f2937',
            border: '1px solid rgba(239, 68, 68, 0.4)',
            borderRadius: '6px',
            color: '#fca5a5',
            fontSize: '0.8125rem',
            fontWeight: 500,
            cursor: 'pointer',
            transition: 'all 0.15s ease'
          }}
          onMouseEnter={(e) => {
            e.currentTarget.style.backgroundColor = 'rgba(239, 68, 68, 0.15)';
            e.currentTarget.style.color = '#ffffff';
          }}
          onMouseLeave={(e) => {
            e.currentTarget.style.backgroundColor = '#1f2937';
            e.currentTarget.style.color = '#fca5a5';
          }}
        >
          <RefreshCw size={14} />
          <span>Retry Operation</span>
        </button>
      )}
    </div>
  );
};
