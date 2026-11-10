import React from 'react';
import { EmptyState } from '../components/ui/EmptyState';
import { TrendingUp } from 'lucide-react';

export const AnalyticsPage: React.FC = () => (
  <div style={{ padding: '0' }}>
    <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '1.5rem' }}>
      <TrendingUp size={22} color="#3b82f6" />
      <h1 style={{ fontSize: '1.5rem', fontWeight: 600, color: '#f9fafb', margin: 0 }}>Security Analytics</h1>
    </div>
    <EmptyState
      icon={<TrendingUp size={48} />}
      title="Security Analytics"
      description="Security analytics, trend analysis, and behavioral baselines."
    />
  </div>
);
