import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import { SeverityBadge, SeverityLevel } from '../components/ui/SeverityBadge';
import { DataTable, Column } from '../components/ui/DataTable';
import { LoadingState } from '../components/ui/LoadingState';
import { EmptyState } from '../components/ui/EmptyState';
import { Shield, CheckCircle2, Sliders, RefreshCw, Cpu } from 'lucide-react';

interface RuleMeta {
  rule_id: string;
  rule_version: string;
  name: string;
  description: string;
  default_severity: string;
}

export const RulesPage: React.FC = () => {
  const [rules, setRules] = useState<RuleMeta[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [mlEnabled, setMlEnabled] = useState<boolean>(true);

  useEffect(() => {
    api.getDetectionRules()
      .then((res) => {
        setRules(res.rules || []);
      })
      .catch((err) => console.error('Failed to load rules:', err))
      .finally(() => setLoading(false));
  }, []);

  const columns: Column<RuleMeta>[] = [
    {
      key: 'rule_id',
      header: 'Rule ID',
      width: '120px',
      render: (item) => (
        <span style={{ fontFamily: 'var(--font-mono, monospace)', fontWeight: 600, color: '#93c5fd', fontSize: '0.8rem' }}>
          {item.rule_id}
        </span>
      ),
    },
    {
      key: 'name',
      header: 'Rule Name & Scope',
      render: (item) => (
        <div>
          <div style={{ fontWeight: 600, color: '#f3f4f6', fontSize: '0.85rem' }}>{item.name}</div>
          <div style={{ color: '#9ca3af', fontSize: '0.75rem', marginTop: '2px', lineHeight: 1.4 }}>
            {item.description}
          </div>
        </div>
      ),
    },
    {
      key: 'default_severity',
      header: 'Default Severity',
      width: '140px',
      render: (item) => (
        <SeverityBadge severity={item.default_severity as SeverityLevel} size="sm" />
      ),
    },
    {
      key: 'status',
      header: 'Engine Status',
      width: '120px',
      render: () => (
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: '5px', color: '#10b981', fontSize: '0.72rem', fontWeight: 600 }}>
          <CheckCircle2 size={13} />
          ACTIVE
        </span>
      ),
    },
  ];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
      {/* Top Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '12px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <div style={{ width: '36px', height: '36px', borderRadius: '8px', backgroundColor: 'rgba(59, 130, 246, 0.15)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <Shield size={20} color="#3b82f6" />
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <h1 style={{ fontSize: '1.375rem', fontWeight: 700, color: '#f9fafb', margin: 0 }}>
                Deterministic Threat Detection Rules
              </h1>
              <span style={{ fontSize: '0.72rem', fontWeight: 600, padding: '2px 8px', borderRadius: '10px', backgroundColor: 'rgba(59, 130, 246, 0.15)', color: '#93c5fd', border: '1px solid rgba(59, 130, 246, 0.3)' }}>
                PHASE 8 CORE
              </span>
            </div>
            <p style={{ color: '#9ca3af', fontSize: '0.8rem', margin: '2px 0 0 0' }}>
              Deterministic temporal rules evaluated against raw security telemetry before correlation and deduplication
            </p>
          </div>
        </div>
      </div>

      {/* Rules Table */}
      {loading ? (
        <LoadingState variant="skeleton" rows={5} message="Loading registered detection rules..." />
      ) : rules.length === 0 ? (
        <EmptyState
          icon={<Shield size={48} color="#6b7280" />}
          title="No Detection Rules Registered"
          description="The detection engine has no active rules loaded."
        />
      ) : (
        <div style={{ backgroundColor: '#1a1f2e', border: '1px solid rgba(255, 255, 255, 0.06)', borderRadius: '8px', padding: '16px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
            <span style={{ fontSize: '0.78rem', color: '#9ca3af' }}>
              <strong style={{ color: '#f3f4f6' }}>{rules.length}</strong> active deterministic rules evaluated on every event batch
            </span>
          </div>

          <DataTable<RuleMeta>
            columns={columns}
            data={rules}
            keyExtractor={(item) => item.rule_id}
            compact
          />
        </div>
      )}

      {/* Unsupervised ML Anomaly Rule Card */}
      <div style={{ backgroundColor: '#1a1f2e', border: '1px solid rgba(139, 92, 246, 0.25)', borderRadius: '8px', padding: '16px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
          <Cpu size={18} color="#a78bfa" />
          <h3 style={{ fontSize: '0.9375rem', fontWeight: 600, color: '#f9fafb', margin: 0 }}>
            Unsupervised ML Anomaly Detection (RULE: ML-ANOMALY-001)
          </h3>
          <span style={{ fontSize: '0.68rem', padding: '2px 6px', borderRadius: '4px', backgroundColor: 'rgba(139, 92, 246, 0.15)', color: '#a78bfa', fontWeight: 600 }}>
            Isolation Forest
          </span>
        </div>
        <p style={{ color: '#9ca3af', fontSize: '0.8rem', lineHeight: 1.45, margin: 0 }}>
          Complements deterministic rules by scoring 10 continuous behavioral features (failure ratios, entropy, auth velocity, inter-arrival variance) to flag slow-and-low attacks that bypass static thresholds.
        </p>
      </div>
    </div>
  );
};
export default RulesPage;
