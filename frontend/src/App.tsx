import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AppLayout } from './components/layout/AppLayout';

import { OverviewPage } from './pages/OverviewPage';
import { AlertsPage } from './pages/AlertsPage';
import { IncidentsPage } from './pages/IncidentsPage';
import { EventsPage } from './pages/EventsPage';
import { EntitiesPage } from './pages/EntitiesPage';
import { AssetsPage } from './pages/AssetsPage';
import { ThreatIntelPage } from './pages/ThreatIntelPage';
import { AnalyticsPage } from './pages/AnalyticsPage';
import { RulesPage } from './pages/RulesPage';
import { ReportsPage } from './pages/ReportsPage';
import { AIAssistantPage } from './pages/AIAssistantPage';
import { PlaybooksPage } from './pages/PlaybooksPage';
import { AutomationPage } from './pages/AutomationPage';
import { ResponsePage } from './pages/ResponsePage';
import { SettingsPage } from './pages/SettingsPage';
import { SystemPage } from './pages/SystemPage';

export const App: React.FC = () => {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<AppLayout />}>
          <Route index element={<Navigate to="/overview" replace />} />
          <Route path="overview" element={<OverviewPage />} />
          <Route path="alerts" element={<AlertsPage />} />
          <Route path="incidents" element={<IncidentsPage />} />
          <Route path="events" element={<EventsPage />} />
          <Route path="entities" element={<EntitiesPage />} />
          <Route path="assets" element={<AssetsPage />} />
          <Route path="threat-intel" element={<ThreatIntelPage />} />
          <Route path="analytics" element={<AnalyticsPage />} />
          <Route path="rules" element={<RulesPage />} />
          <Route path="reports" element={<ReportsPage />} />
          <Route path="ai-assistant" element={<AIAssistantPage />} />
          <Route path="playbooks" element={<PlaybooksPage />} />
          <Route path="automation" element={<AutomationPage />} />
          <Route path="response" element={<ResponsePage />} />
          <Route path="settings" element={<SettingsPage />} />
          <Route path="system" element={<SystemPage />} />
          {/* Catch-all redirect to overview */}
          <Route path="*" element={<Navigate to="/overview" replace />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
};

export default App;
