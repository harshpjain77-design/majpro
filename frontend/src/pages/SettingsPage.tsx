import React from 'react';
import { EmptyState } from '../components/ui/EmptyState';
import { Settings2 } from 'lucide-react';

export const SettingsPage: React.FC = () => (
  <div style={{ padding: '0' }}>
    <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '1.5rem' }}>
      <Settings2 size={22} color="#9ca3af" />
      <h1 style={{ fontSize: '1.5rem', fontWeight: 600, color: '#f9fafb', margin: 0 }}>Settings</h1>
    </div>
    <EmptyState
      icon={<Settings2 size={48} />}
      title="Settings"
      description="Platform configuration, API keys, collector settings, and user preferences."
    />
  </div>
);
