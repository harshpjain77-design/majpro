import React from 'react';
import { EmptyState } from '../components/ui/EmptyState';
import { Users } from 'lucide-react';

export const EntitiesPage: React.FC = () => (
  <div style={{ padding: '0' }}>
    <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '1.5rem' }}>
      <Users size={22} color="#06b6d4" />
      <h1 style={{ fontSize: '1.5rem', fontWeight: 600, color: '#f9fafb', margin: 0 }}>Entities</h1>
    </div>
    <EmptyState
      icon={<Users size={48} />}
      title="Entities"
      description="Entity profiles track IP addresses, users, and hosts across events and incidents."
    />
  </div>
);
