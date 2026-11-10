import React from 'react';
import { EmptyState } from '../components/ui/EmptyState';
import { Server } from 'lucide-react';

export const AssetsPage: React.FC = () => (
  <div style={{ padding: '0' }}>
    <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '1.5rem' }}>
      <Server size={22} color="#14b8a6" />
      <h1 style={{ fontSize: '1.5rem', fontWeight: 600, color: '#f9fafb', margin: 0 }}>Asset Inventory</h1>
    </div>
    <EmptyState
      icon={<Server size={48} />}
      title="Asset Inventory"
      description="Asset inventory tracking servers, workstations, and network devices."
    />
  </div>
);
