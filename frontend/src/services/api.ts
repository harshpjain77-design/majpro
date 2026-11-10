import {
  AIAnalysisReport,
  DeduplicationMetrics,
  EventExplanation,
  Incident,
  IncidentStatus,
  MLEvaluationMetrics,
  MLStatus,
  ResponseActionRecord,
  SafetyStatusResponse,
  SecurityEvent,
} from '../types';

const API_BASE = '/api/v1';
const API_KEY = 'test-collector-api-key-replace-in-production';

const defaultHeaders = {
  'Content-Type': 'application/json',
  'X-API-Key': API_KEY,
};

async function handleResponse<T>(res: Response): Promise<T> {
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.detail || `HTTP Error ${res.status}: ${res.statusText}`);
  }
  return res.json();
}

export const api = {
  // Incident endpoints
  async getIncidents(params: {
    status?: string;
    severity?: string;
    limit?: number;
    offset?: number;
  } = {}): Promise<{ total: number; limit: number; offset: number; incidents: Incident[] }> {
    const query = new URLSearchParams();
    if (params.status && params.status !== 'ALL') query.append('status', params.status);
    if (params.severity && params.severity !== 'ALL') query.append('severity', params.severity);
    if (params.limit) query.append('limit', params.limit.toString());
    if (params.offset) query.append('offset', params.offset.toString());

    const res = await fetch(`${API_BASE}/incidents?${query.toString()}`, {
      headers: defaultHeaders,
    });
    return handleResponse(res);
  },

  async getIncident(id: string): Promise<Incident> {
    const res = await fetch(`${API_BASE}/incidents/${id}`, {
      headers: defaultHeaders,
    });
    return handleResponse(res);
  },

  async updateIncidentStatus(
    id: string,
    status: IncidentStatus,
    analyst: string = 'soc_analyst'
  ): Promise<Incident> {
    const res = await fetch(`${API_BASE}/incidents/${id}/status`, {
      method: 'PATCH',
      headers: defaultHeaders,
      body: JSON.stringify({ status, analyst }),
    });
    return handleResponse(res);
  },

  async addIncidentNote(id: string, author: string, content: string): Promise<any> {
    const res = await fetch(`${API_BASE}/incidents/${id}/notes`, {
      method: 'POST',
      headers: defaultHeaders,
      body: JSON.stringify({ author, content }),
    });
    return handleResponse(res);
  },

  async triggerCorrelation(): Promise<any> {
    const res = await fetch(`${API_BASE}/incidents/correlate`, {
      method: 'POST',
      headers: defaultHeaders,
    });
    return handleResponse(res);
  },

  async getDeduplicationMetrics(): Promise<DeduplicationMetrics> {
    const res = await fetch(`${API_BASE}/incidents/metrics/deduplication`, {
      headers: defaultHeaders,
    });
    return handleResponse(res);
  },

  // Event search endpoints
  async searchEvents(params: {
    source_ip?: string;
    username?: string;
    source_host?: string;
    event_type?: string;
    severity?: string;
    query?: string;
    limit?: number;
    offset?: number;
    sort_by?: string;
    sort_dir?: string;
  } = {}): Promise<{ total: number; limit: number; offset: number; events: SecurityEvent[] }> {
    const query = new URLSearchParams();
    if (params.source_ip) {
      query.append('source_ip', params.source_ip);
      query.append('ip', params.source_ip);
    }
    if (params.username) query.append('username', params.username);
    if (params.source_host) {
      query.append('source_host', params.source_host);
      query.append('host', params.source_host);
    }
    if (params.event_type) query.append('event_type', params.event_type);
    if (params.severity && params.severity !== 'ALL') query.append('severity', params.severity);
    if (params.query) {
      query.append('query', params.query);
      query.append('q', params.query);
    }
    if (params.sort_by) query.append('sort_by', params.sort_by);
    if (params.sort_dir) query.append('sort_dir', params.sort_dir);
    if (params.limit) query.append('limit', params.limit.toString());
    if (params.offset) query.append('offset', params.offset.toString());

    const res = await fetch(`${API_BASE}/events?${query.toString()}`, {
      headers: defaultHeaders,
    });
    return handleResponse(res);
  },

  async getEventSummaryCounts(): Promise<{
    total_events: number;
    by_severity: Record<string, number>;
    by_event_type: Record<string, number>;
    by_source_host: Record<string, number>;
    time_series: Array<{ bucket: string; count: number }>;
  }> {
    const res = await fetch(`${API_BASE}/events/summary/counts`, {
      headers: defaultHeaders,
    });
    return handleResponse(res);
  },

  async getEventById(id: string): Promise<SecurityEvent> {
    const res = await fetch(`${API_BASE}/events/${id}`, {
      headers: defaultHeaders,
    });
    return handleResponse(res);
  },

  async getRawEvent(id: string): Promise<{ event_id: string; raw_event: string }> {
    const res = await fetch(`${API_BASE}/events/${id}/raw`, {
      headers: defaultHeaders,
    });
    return handleResponse(res);
  },

  // AI Copilot endpoints
  async investigateIncidentWithAI(incidentId: string): Promise<AIAnalysisReport> {
    const res = await fetch(`${API_BASE}/ai/investigate/${incidentId}`, {
      method: 'POST',
      headers: defaultHeaders,
    });
    return handleResponse(res);
  },

  async explainEventWithAI(eventId: string): Promise<EventExplanation> {
    const res = await fetch(`${API_BASE}/ai/explain_event/${eventId}`, {
      method: 'POST',
      headers: defaultHeaders,
    });
    return handleResponse(res);
  },

  // ML Anomaly endpoints
  async getMLStatus(): Promise<MLStatus> {
    const res = await fetch(`${API_BASE}/ml/status`, {
      headers: defaultHeaders,
    });
    return handleResponse(res);
  },

  async getMLBenchmark(): Promise<MLEvaluationMetrics> {
    const res = await fetch(`${API_BASE}/ml/benchmark`, {
      headers: defaultHeaders,
    });
    return handleResponse(res);
  },

  // Response Engine endpoints (Phase 8)
  async getSafetyStatus(): Promise<SafetyStatusResponse> {
    const res = await fetch(`${API_BASE}/response/safety/status`, {
      headers: defaultHeaders,
    });
    return handleResponse(res);
  },

  async getResponseActions(params: {
    incident_id?: string;
    status?: string;
    limit?: number;
    offset?: number;
  } = {}): Promise<{ total: number; limit: number; offset: number; actions: ResponseActionRecord[] }> {
    const query = new URLSearchParams();
    if (params.incident_id) query.append('incident_id', params.incident_id);
    if (params.status && params.status !== 'ALL') query.append('status', params.status);
    if (params.limit) query.append('limit', params.limit.toString());
    if (params.offset) query.append('offset', params.offset.toString());

    const res = await fetch(`${API_BASE}/response/actions?${query.toString()}`, {
      headers: defaultHeaders,
    });
    return handleResponse(res);
  },

  async proposeResponseAction(proposal: {
    incident_id: string;
    action_type: string;
    target: string;
    parameters?: Record<string, any>;
    priority?: string;
    reason: string;
  }): Promise<ResponseActionRecord> {
    const res = await fetch(`${API_BASE}/response/propose`, {
      method: 'POST',
      headers: defaultHeaders,
      body: JSON.stringify(proposal),
    });
    return handleResponse(res);
  },

  async stageIncidentActions(incidentId: string): Promise<ResponseActionRecord[]> {
    const res = await fetch(`${API_BASE}/response/stage_incident/${incidentId}`, {
      method: 'POST',
      headers: defaultHeaders,
    });
    return handleResponse(res);
  },

  async approveResponseAction(
    actionId: string,
    analystName: string = 'lead_soc_analyst',
    comment?: string
  ): Promise<ResponseActionRecord> {
    const res = await fetch(`${API_BASE}/response/actions/${actionId}/approve`, {
      method: 'POST',
      headers: defaultHeaders,
      body: JSON.stringify({ analyst_name: analystName, comment }),
    });
    return handleResponse(res);
  },

  async executeResponseAction(actionId: string, forceLive: boolean = false): Promise<any> {
    const query = forceLive ? '?force_live=true' : '';
    const res = await fetch(`${API_BASE}/response/actions/${actionId}/execute${query}`, {
      method: 'POST',
      headers: defaultHeaders,
    });
    return handleResponse(res);
  },

  async rollbackResponseAction(
    actionId: string,
    analystName: string = 'lead_soc_analyst',
    comment?: string
  ): Promise<any> {
    const res = await fetch(`${API_BASE}/response/actions/${actionId}/rollback`, {
      method: 'POST',
      headers: defaultHeaders,
      body: JSON.stringify({ analyst_name: analystName, comment }),
    });
    return handleResponse(res);
  },

  // Alerts endpoints (Real detection evaluation)
  async getAlerts(params: {
    start_time?: string;
    end_time?: string;
    severity?: string;
    limit?: number;
  } = {}): Promise<any[]> {
    const query = new URLSearchParams();
    if (params.start_time) query.append('start_time', params.start_time);
    if (params.end_time) query.append('end_time', params.end_time);
    if (params.severity && params.severity !== 'ALL') query.append('severity', params.severity);
    if (params.limit) query.append('limit', params.limit.toString());

    const res = await fetch(`${API_BASE}/alerts?${query.toString()}`, {
      headers: defaultHeaders,
    });
    return handleResponse(res);
  },

  async getAlertById(alertId: string): Promise<any> {
    const res = await fetch(`${API_BASE}/alerts/${alertId}`, {
      headers: defaultHeaders,
    });
    return handleResponse(res);
  },

  async getDetectionRules(): Promise<{ rules: any[] }> {
    const res = await fetch(`${API_BASE}/detection/rules`, {
      headers: defaultHeaders,
    });
    return handleResponse(res);
  },

  // Real System Health
  async getSystemHealth(): Promise<{
    status: string;
    version: string;
    database: string;
    events_stored: number;
    uptime_seconds: number;
  }> {
    const res = await fetch(`${API_BASE}/system/health`, {
      headers: defaultHeaders,
    });
    return handleResponse(res);
  },
};


