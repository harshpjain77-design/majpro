import React, { useState } from 'react';
import { ArrowUpRight, ArrowDownRight, Minus } from 'lucide-react';

export interface StatCardProps {
  title: string;
  value: string | number;
  change?: number;
  changeLabel?: string;
  trend?: 'up' | 'down' | 'stable';
  icon: React.ReactNode;
  iconColor?: string;
  onClick?: () => void;
}

export const StatCard: React.FC<StatCardProps> = ({
  title,
  value,
  change,
  changeLabel = 'vs last 24h',
  trend,
  icon,
  iconColor = '#3b82f6',
  onClick
}) => {
  const [isHovered, setIsHovered] = useState(false);

  // Determine trend direction if not explicitly supplied
  const effectiveTrend: 'up' | 'down' | 'stable' =
    trend || (change !== undefined ? (change > 0 ? 'up' : change < 0 ? 'down' : 'stable') : 'stable');

  // Trend formatting
  const isPositive = effectiveTrend === 'up';
  const isNegative = effectiveTrend === 'down';

  const trendColor = isPositive ? '#10b981' : isNegative ? '#ef4444' : '#9ca3af';
  const trendBg = isPositive
    ? 'rgba(16, 185, 129, 0.12)'
    : isNegative
    ? 'rgba(239, 68, 68, 0.12)'
    : 'rgba(156, 163, 175, 0.1)';

  return (
    <div
      onClick={onClick}
      onMouseEnter={() => setIsHovered(true)}
      onMouseLeave={() => setIsHovered(false)}
      role={onClick ? 'button' : undefined}
      tabIndex={onClick ? 0 : undefined}
      onKeyDown={(e) => {
        if (onClick && (e.key === 'Enter' || e.key === ' ')) {
          e.preventDefault();
          onClick();
        }
      }}
      style={{
        backgroundColor: '#1a1f2e',
        border: `1px solid ${isHovered ? 'rgba(255, 255, 255, 0.14)' : 'rgba(255, 255, 255, 0.06)'}`,
        borderRadius: '12px',
        padding: '1.25rem',
        display: 'flex',
        flexDirection: 'column',
        justifyContent: 'space-between',
        cursor: onClick ? 'pointer' : 'default',
        transform: isHovered && onClick ? 'translateY(-2px)' : isHovered ? 'translateY(-1px)' : 'none',
        transition: 'transform 0.18s ease, border-color 0.18s ease, box-shadow 0.18s ease',
        boxShadow: isHovered
          ? '0 6px 16px -2px rgba(0, 0, 0, 0.4), 0 0 1px 1px rgba(255, 255, 255, 0.05)'
          : '0 4px 6px -1px rgba(0, 0, 0, 0.25)',
        position: 'relative',
        overflow: 'hidden'
      }}
    >
      {/* Top Header: Title & Colored Icon */}
      <div
        style={{
          display: 'flex',
          alignItems: 'flex-start',
          justifyContent: 'space-between',
          gap: '12px',
          marginBottom: '1rem'
        }}
      >
        <div style={{ flex: 1, minWidth: 0 }}>
          <span
            style={{
              fontSize: '0.75rem',
              fontWeight: 700,
              textTransform: 'uppercase',
              letterSpacing: '0.06em',
              color: '#9ca3af',
              display: 'block',
              lineHeight: 1.4
            }}
          >
            {title}
          </span>
        </div>

        {/* Circular Icon Container with 15% opacity tint */}
        <div
          style={{
            width: '42px',
            height: '42px',
            borderRadius: '50%',
            backgroundColor: `${iconColor}26`, // 15% opacity hex
            border: `1px solid ${iconColor}40`,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            flexShrink: 0,
            color: iconColor
          }}
        >
          {icon}
        </div>
      </div>

      {/* Main Metric Value */}
      <div style={{ marginBottom: change !== undefined ? '0.75rem' : '0' }}>
        <div
          style={{
            fontSize: '2rem',
            fontWeight: 700,
            color: '#f9fafb',
            letterSpacing: '-0.03em',
            lineHeight: 1.1,
            fontFamily: 'var(--font-sans, sans-serif)'
          }}
        >
          {value}
        </div>
      </div>

      {/* Bottom Change Indicator */}
      {change !== undefined && (
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            fontSize: '0.75rem',
            lineHeight: 1
          }}
        >
          <div
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '3px',
              padding: '3px 6px',
              borderRadius: '4px',
              backgroundColor: trendBg,
              color: trendColor,
              fontWeight: 600,
              fontSize: '0.72rem'
            }}
          >
            {isPositive && <ArrowUpRight size={13} strokeWidth={2.5} />}
            {isNegative && <ArrowDownRight size={13} strokeWidth={2.5} />}
            {!isPositive && !isNegative && <Minus size={13} strokeWidth={2.5} />}
            <span>
              {change > 0 ? `+${change}%` : `${change}%`}
            </span>
          </div>

          {changeLabel && (
            <span style={{ color: '#6b7280', fontSize: '0.75rem' }}>
              {changeLabel}
            </span>
          )}
        </div>
      )}
    </div>
  );
};
