import React from 'react';

export interface ChartCardProps {
  title: string;
  subtitle?: string;
  children: React.ReactNode;
  action?: React.ReactNode;
  className?: string;
  height?: number;
}

export const ChartCard: React.FC<ChartCardProps> = ({
  title,
  subtitle,
  children,
  action,
  className = '',
  height = 300
}) => {
  return (
    <div
      className={`threatgrid-chart-card ${className}`}
      style={{
        backgroundColor: '#1a1f2e',
        border: '1px solid rgba(255, 255, 255, 0.06)',
        borderRadius: '8px',
        display: 'flex',
        flexDirection: 'column',
        overflow: 'hidden',
        boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.25)',
        width: '100%',
        boxSizing: 'border-box'
      }}
    >
      {/* Header bar */}
      <div
        style={{
          padding: '16px 20px',
          borderBottom: '1px solid rgba(255, 255, 255, 0.05)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          gap: '16px',
          flexWrap: 'wrap'
        }}
      >
        <div style={{ minWidth: 0, flex: 1 }}>
          <h4
            style={{
              fontSize: '0.9375rem',
              fontWeight: 600,
              color: '#f9fafb',
              margin: 0,
              letterSpacing: '-0.01em',
              whiteSpace: 'nowrap',
              overflow: 'hidden',
              textOverflow: 'ellipsis'
            }}
          >
            {title}
          </h4>
          {subtitle && (
            <p
              style={{
                fontSize: '0.75rem',
                color: '#9ca3af',
                margin: '2px 0 0 0',
                lineHeight: 1.4
              }}
            >
              {subtitle}
            </p>
          )}
        </div>

        {action && (
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
              flexShrink: 0
            }}
          >
            {action}
          </div>
        )}
      </div>

      {/* Content Chart Container */}
      <div
        style={{
          flex: 1,
          minHeight: `${height}px`,
          padding: '16px 20px',
          display: 'flex',
          flexDirection: 'column',
          position: 'relative'
        }}
      >
        {children}
      </div>
    </div>
  );
};
