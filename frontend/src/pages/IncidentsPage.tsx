import React, { useState, useEffect, useCallback } from 'react';
import { Incident, IncidentStatus } from '../types';
import { api } from '../services/api';
import { IncidentQueue } from '../components/IncidentQueue';
import { IncidentDetailModal } from '../components/IncidentDetailModal';
import { AlertTriangle } from 'lucide-react';

export const IncidentsPage: React.FC = () => {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null);
  const [loading, setLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const refreshData = useCallback(async (silent = false) => {
    try {
      if (!silent) setLoading(true);
      setErrorMessage(null);
      const res = await api.getIncidents({ limit: 100 });
      setIncidents(res.incidents || []);
    } catch (err: any) {
      console.error('Failed to load incidents:', err);
      if (!silent) setErrorMessage(err.message || 'Error loading incidents');
    } finally {
      if (!silent) setLoading(false);
    }
  }, []);

  useEffect(() => {
    refreshData(false);
    const interval = setInterval(() => refreshData(true), 5000);
    return () => clearInterval(interval);
  }, [refreshData]);

  const handleUpdateStatus = async (incidentId: string, status: IncidentStatus) => {
    try {
      const updated = await api.updateIncidentStatus(incidentId, status);
      setIncidents(prev => prev.map(i => i.incident_id === incidentId ? updated : i));
      if (selectedIncident?.incident_id === incidentId) setSelectedIncident(updated);
    } catch (err: any) {
      alert(`Failed to update status: ${err.message}`);
    }
  };

  const handleAddNote = async (incidentId: string, author: string, content: string) => {
    await api.addIncidentNote(incidentId, author, content);
    const updated = await api.getIncident(incidentId);
    setIncidents(prev => prev.map(i => i.incident_id === incidentId ? updated : i));
    if (selectedIncident?.incident_id === incidentId) setSelectedIncident(updated);
  };

  return (
    <div style={{ padding: '0' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '1.5rem' }}>
        <AlertTriangle size={22} color="#f59e0b" />
        <h1 style={{ fontSize: '1.5rem', fontWeight: 600, color: '#f9fafb', margin: 0 }}>Incident Management</h1>
        <span style={{ fontSize: '0.8rem', color: '#6b7280', background: 'rgba(255,255,255,0.05)', padding: '0.2rem 0.6rem', borderRadius: 4 }}>
          {incidents.length} incidents
        </span>
      </div>

      {errorMessage && (
        <div style={{ padding: '0.75rem 1rem', marginBottom: '1rem', background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.3)', borderRadius: 8, color: '#f87171', fontSize: '0.85rem' }}>
          {errorMessage}
        </div>
      )}

      <IncidentQueue
        incidents={incidents}
        onSelectIncident={setSelectedIncident}
        onLaunchAI={() => {}}
        onUpdateStatus={handleUpdateStatus}
        loading={loading}
      />

      {selectedIncident && (
        <IncidentDetailModal
          incident={selectedIncident}
          onClose={() => setSelectedIncident(null)}
          onUpdateStatus={handleUpdateStatus}
          onAddNote={handleAddNote}
          onLaunchAI={() => {}}
        />
      )}
    </div>
  );
};
