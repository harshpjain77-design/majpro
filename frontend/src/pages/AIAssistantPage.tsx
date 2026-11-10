import React, { useState, useEffect } from 'react';
import { Incident, AIAnalysisReport } from '../types';
import { api } from '../services/api';
import { AICopilotPanel } from '../components/AICopilotPanel';
import { Bot } from 'lucide-react';

export const AIAssistantPage: React.FC = () => {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [selectedIncidentId, setSelectedIncidentId] = useState<string | null>(null);
  const [aiReport, setAiReport] = useState<AIAnalysisReport | null>(null);
  const [aiLoading, setAiLoading] = useState(false);

  useEffect(() => {
    api.getIncidents({ limit: 50 }).then(res => {
      setIncidents(res.incidents || []);
      if (res.incidents?.length > 0) setSelectedIncidentId(res.incidents[0].incident_id);
    }).catch(console.error);
  }, []);

  const handleGenerateReport = async (incidentId: string) => {
    try {
      setAiLoading(true);
      const report = await api.investigateIncidentWithAI(incidentId);
      setAiReport(report);
    } catch (err: any) {
      console.error('AI Investigation failed:', err);
    } finally {
      setAiLoading(false);
    }
  };

  return (
    <div style={{ padding: '0' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '1.5rem' }}>
        <Bot size={22} color="#8b5cf6" />
        <h1 style={{ fontSize: '1.5rem', fontWeight: 600, color: '#f9fafb', margin: 0 }}>AI Investigation Assistant</h1>
      </div>
      <AICopilotPanel
        incidents={incidents}
        selectedIncidentId={selectedIncidentId}
        onSelectIncidentId={(id) => { setSelectedIncidentId(id); handleGenerateReport(id); }}
        report={aiReport}
        loading={aiLoading}
        onGenerateReport={handleGenerateReport}
        onInspectEvent={() => {}}
        onNavigateToResponse={() => {}}
      />
    </div>
  );
};
