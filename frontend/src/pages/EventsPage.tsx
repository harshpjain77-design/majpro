import React from 'react';
import { EventExplorer } from '../components/EventExplorer';
import { Search } from 'lucide-react';

export const EventsPage: React.FC = () => {
  return (
    <div style={{ padding: '0' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '1.5rem' }}>
        <Search size={22} color="#3b82f6" />
        <h1 style={{ fontSize: '1.5rem', fontWeight: 600, color: '#f9fafb', margin: 0 }}>Event Explorer</h1>
      </div>
      <EventExplorer initialEventId={null} onClearInitialEvent={() => {}} />
    </div>
  );
};
