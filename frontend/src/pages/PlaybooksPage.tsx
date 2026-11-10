import React from 'react';
import { EmptyState } from '../components/ui/EmptyState';
import { BookOpen } from 'lucide-react';

export const PlaybooksPage: React.FC = () => (
  <div style={{ padding: '0' }}>
    <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '1.5rem' }}>
      <BookOpen size={22} color="#f59e0b" />
      <h1 style={{ fontSize: '1.5rem', fontWeight: 600, color: '#f9fafb', margin: 0 }}>Incident Playbooks</h1>
    </div>
    <EmptyState
      icon={<BookOpen size={48} />}
      title="Incident Playbooks"
      description="Incident response playbooks and standard operating procedures."
    />
  </div>
);
