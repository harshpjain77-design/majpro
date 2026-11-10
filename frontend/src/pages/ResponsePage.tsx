import React, { useState, useEffect } from 'react';
import { Incident } from '../types';
import { api } from '../services/api';
import { ResponseConsole } from '../components/ResponseConsole';
import { ShieldAlert } from 'lucide-react';

export const ResponsePage: React.FC = () => {
  const [incidents, setIncidents] = useState<Incident[]>([]);

  useEffect(() => {
    api.getIncidents({ limit: 100 }).then(res => setIncidents(res.incidents || [])).catch(console.error);
  }, []);

  const refreshAll = async () => {
    const res = await api.getIncidents({ limit: 100 });
    setIncidents(res.incidents || []);
  };

  return (
    <div style={{ padding: '0' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '1.5rem' }}>
        <ShieldAlert size={22} color="#ef4444" />
        <h1 style={{ fontSize: '1.5rem', fontWeight: 600, color: '#f9fafb', margin: 0 }}>Response & Containment</h1>
      </div>
      <ResponseConsole incidents={incidents} onRefreshAll={refreshAll} />
    </div>
  );
};
