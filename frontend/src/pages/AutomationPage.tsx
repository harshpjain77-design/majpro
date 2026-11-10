import React from 'react';
import { EmptyState } from '../components/ui/EmptyState';
import { Zap } from 'lucide-react';

export const AutomationPage: React.FC = () => (
  <div style={{ padding: '0' }}>
    <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '1.5rem' }}>
      <Zap size={22} color="#eab308" />
      <h1 style={{ fontSize: '1.5rem', fontWeight: 600, color: '#f9fafb', margin: 0 }}>Automation & SOAR</h1>
    </div>
    <EmptyState
      icon={<Zap size={48} />}
      title="Automation & SOAR"
      description="Automated response workflows and SOAR integrations."
    />
  </div>
);
