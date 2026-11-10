import React from 'react';
import { Loader2 } from 'lucide-react';

export interface LoadingStateProps {
  message?: string;
  variant?: 'spinner' | 'skeleton' | 'pulse';
  rows?: number;
  className?: string;
}

export const LoadingState: React.FC<LoadingStateProps> = ({
  message = 'Loading data...',
  variant = 'spinner',
  rows = 4,
  className = ''
}) => {
  return (
    <>
      <style>{`
        @keyframes tgShimmer {
          0% {
            background-position: -200% 0;
          }
          100% {
            background-position: 200% 0;
          }
        }
        @keyframes tgPulse {
          0%, 100% {
            opacity: 1;
          }
          50% {
            opacity: 0.4;
          }
        }
      `}</style>

      {variant === 'spinner' && (
        <div
          className={`threatgrid-loading-spinner ${className}`}
          style={{
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            justifyContent: 'center',
            padding: '48px 24px',
            width: '100%'
          }}
        >
          <Loader2
            size={36}
            style={{
              color: 'var(--accent-blue, #3b82f6)',
              animation: 'spin 1s linear infinite',
              marginBottom: '12px'
            }}
          />
          {message && (
            <p
              style={{
                fontSize: '0.8125rem',
                color: '#9ca3af',
                margin: 0,
                letterSpacing: '0.01em'
              }}
            >
              {message}
            </p>
          )}
        </div>
      )}

      {variant === 'skeleton' && (
        <div
          className={`threatgrid-loading-skeleton ${className}`}
          style={{
            display: 'flex',
            flexDirection: 'column',
            gap: '12px',
            width: '100%',
            padding: '16px 0'
          }}
        >
          {Array.from({ length: rows }).map((_, index) => {
            // Vary widths for realistic look
            const widths = ['100%', '82%', '94%', '68%', '78%'];
            const width = widths[index % widths.length];

            return (
              <div
                key={index}
                style={{
                  height: '24px',
                  width,
                  borderRadius: '4px',
                  background: 'linear-gradient(90deg, rgba(255, 255, 255, 0.03) 25%, rgba(255, 255, 255, 0.08) 50%, rgba(255, 255, 255, 0.03) 75%)',
                  backgroundSize: '200% 100%',
                  animation: 'tgShimmer 1.8s infinite ease-in-out'
                }}
              />
            );
          })}
        </div>
      )}

      {variant === 'pulse' && (
        <div
          className={`threatgrid-loading-pulse ${className}`}
          style={{
            display: 'flex',
            flexDirection: 'column',
            gap: '14px',
            width: '100%',
            padding: '20px',
            backgroundColor: 'rgba(255, 255, 255, 0.02)',
            border: '1px solid rgba(255, 255, 255, 0.05)',
            borderRadius: '8px',
            animation: 'tgPulse 1.6s ease-in-out infinite'
          }}
        >
          <div
            style={{
              height: '20px',
              width: '35%',
              backgroundColor: 'rgba(255, 255, 255, 0.08)',
              borderRadius: '4px'
            }}
          />
          <div
            style={{
              height: '48px',
              width: '100%',
              backgroundColor: 'rgba(255, 255, 255, 0.04)',
              borderRadius: '6px'
            }}
          />
          <div
            style={{
              height: '14px',
              width: '60%',
              backgroundColor: 'rgba(255, 255, 255, 0.06)',
              borderRadius: '4px'
            }}
          />
        </div>
      )}
    </>
  );
};
