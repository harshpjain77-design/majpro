import React from 'react';
import { EmptyState } from '../components/ui/EmptyState';
import { FileText } from 'lucide-react';

export const ReportsPage: React.FC = () => (
  <div style={{ padding: '0' }}>
    <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '1.5rem' }}>
      <FileText size={22} color="#10b981" />
      <h1 style={{ fontSize: '1.5rem', fontWeight: 600, color: '#f9fafb', margin: 0 }}>Reports</h1>
    </div>
    <EmptyState
      icon={<FileText size={48} />}
      title="Reports"
      description="Investigation and compliance reports will be generated here."
    />
  </div>
);
