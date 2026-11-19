import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  BookOpen,
  Shield,
  Zap,
  Check,
  Copy,
  Terminal,
  FileText,
  Search,
  Download,
  X,
  Lock,
  AlertTriangle,
  UserCheck,
  Activity,
  ArrowRight
} from 'lucide-react';
import { api } from '../services/api';
import { Incident } from '../types';

/* ==========================================================================
   Clean, Understandable Playbook Definitions
   ========================================================================== */

interface SimplePlaybook {
  id: string;
  title: string;
  ruleTag?: string;
  severity: 'critical' | 'high' | 'medium';
  icon: 'shield' | 'alert' | 'lock' | 'terminal' | 'user' | 'network';
  summary: string;
  whatHappened: string;
  howToStop: {
    description: string;
    linuxCommand?: string;
    windowsCommand?: string;
  };
  howToRecover: string;
  howToPrevent: string;
}

const PLAYBOOKS: SimplePlaybook[] = [
  {
    id: 'PB-001',
    title: 'SSH & Logon Brute Force Attack',
    ruleTag: 'RULE-001',
    severity: 'high',
    icon: 'shield',
    summary: 'An external attacker is repeatedly guessing passwords from a single IP to break in.',
    whatHappened: 'The attacker sent rapid, repeated failed login attempts within a few minutes. If unchecked, they could guess a weak password and gain server access.',
    howToStop: {
      description: 'Immediately block the attacking IP address at the firewall so their connection is dropped.',
      linuxCommand: 'sudo iptables -I INPUT -s {ATTACKER_IP} -j DROP',
      windowsCommand: 'netsh advfirewall firewall add rule name="Block-Attacker" dir=in action=block remoteip={ATTACKER_IP}',
    },
    howToRecover: 'Check if any login from that IP succeeded. If not, normal operations can continue.',
    howToPrevent: 'Disable password authentication in SSH (`PasswordAuthentication no`) and require SSH keys.',
  },
  {
    id: 'PB-002',
    title: 'Account Compromise & Password Breach',
    ruleTag: 'RULE-002',
    severity: 'critical',
    icon: 'alert',
    summary: 'Failed logins were immediately followed by a successful login. The account may be breached.',
    whatHappened: 'The attacker tested passwords until one worked, or they used leaked credentials to successfully log in.',
    howToStop: {
      description: 'Lock the compromised user account immediately and terminate all their active sessions.',
      linuxCommand: 'sudo usermod -L {USERNAME} && sudo pkill -KILL -u {USERNAME}',
      windowsCommand: 'net user {USERNAME} /active:no',
    },
    howToRecover: 'Audit `~/.ssh/authorized_keys` and recent bash history for backdoors. Reset the user password.',
    howToPrevent: 'Enforce Multi-Factor Authentication (MFA) on all user accounts and disable administrative direct logons.',
  },
  {
    id: 'PB-003',
    title: 'Distributed Password Spraying',
    ruleTag: 'RULE-003',
    severity: 'high',
    icon: 'network',
    summary: 'An attacker is trying one common password across multiple IP addresses to avoid lockout.',
    whatHappened: 'Instead of attacking from one IP, the attacker used multiple proxies/IPs to test passwords against accounts.',
    howToStop: {
      description: 'Block the list of attacking IPs and temporarily freeze affected user accounts for verification.',
      linuxCommand: 'sudo iptables -I INPUT -s {ATTACKER_IP} -j DROP',
      windowsCommand: 'netsh advfirewall firewall add rule name="Block-Spray" dir=in action=block remoteip={ATTACKER_IP}',
    },
    howToRecover: 'Verify that zero spray attempts succeeded. Force password reset if any attempt showed success.',
    howToPrevent: 'Enforce smart lockout policies and block known proxy / Tor exit node IP ranges.',
  },
  {
    id: 'PB-004',
    title: 'Unauthorized Sudo & Privilege Escalation',
    ruleTag: 'RULE-004',
    severity: 'critical',
    icon: 'terminal',
    summary: 'A user executed sensitive administrative commands (/etc/shadow, visudo, or root shell).',
    whatHappened: 'A non-admin user or compromised account attempted to access password hashes or gain root privileges.',
    howToStop: {
      description: 'Kill the rogue process immediately and isolate the host from the network.',
      linuxCommand: 'sudo kill -9 {PROCESS_ID}',
      windowsCommand: 'taskkill /PID {PROCESS_ID} /F',
    },
    howToRecover: 'Check `/etc/passwd` and `/etc/sudoers` to ensure no unauthorized accounts or rules were created.',
    howToPrevent: 'Strictly restrict sudo permissions in `/etc/sudoers` and forbid `NOPASSWD` entries.',
  },
  {
    id: 'PB-005',
    title: 'Account Reconnaissance & Username Probing',
    ruleTag: 'RULE-005',
    severity: 'medium',
    icon: 'user',
    summary: 'A remote scanner is testing random usernames to see which accounts exist on the server.',
    whatHappened: 'The attacker is probing common usernames (admin, test, guest) to build a target list for future brute force.',
    howToStop: {
      description: 'Block the scanning IP at the gateway router or host firewall.',
      linuxCommand: 'sudo iptables -I INPUT -s {SCANNER_IP} -j DROP',
      windowsCommand: 'netsh advfirewall firewall add rule name="Block-Scanner" dir=in action=block remoteip={SCANNER_IP}',
    },
    howToRecover: 'Confirm that no valid internal usernames were guessed or compromised.',
    howToPrevent: 'Ensure server responses return identical error messages and constant-time delays for all usernames.',
  },
  {
    id: 'PB-006',
    title: 'Zero Trust Architecture Checklist',
    ruleTag: 'Framework',
    severity: 'medium',
    icon: 'lock',
    summary: 'Guidelines based on "Never Trust, Always Verify" across users, devices, and networks.',
    whatHappened: 'Proactive defense strategy to limit blast radius and stop lateral movement in your network.',
    howToStop: {
      description: 'Segment internal networks and enforce Multi-Factor Authentication everywhere.',
      linuxCommand: '# Restrict access to database port 5432 only to application backend:\nsudo iptables -A INPUT -p tcp --dport 5432 -s 192.168.1.50 -j ACCEPT\nsudo iptables -A INPUT -p tcp --dport 5432 -j DROP',
    },
    howToRecover: 'Review all standing privileges and remove unnecessary administrative access.',
    howToPrevent: 'Adopt the 5 Zero Trust Pillars: User Trust, Device Trust, Application Trust, Data Trust, Network Trust.',
  },
];

export const PlaybooksPage: React.FC = () => {
  const navigate = useNavigate();

  // Tabs: 'playbooks' | 'report'
  const [activeTab, setActiveTab] = useState<'playbooks' | 'report'>('playbooks');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [selectedPlaybook, setSelectedPlaybook] = useState<SimplePlaybook | null>(null);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  // IR Generator State
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [selectedIncId, setSelectedIncId] = useState<string>('');
  const [irSummary, setIrSummary] = useState({
    title: '',
    severity: 'HIGH',
    attacker: '',
    target: '',
    actions: '',
    recovery: '',
  });
  const [copiedReport, setCopiedReport] = useState<boolean>(false);

  useEffect(() => {
    api.getIncidents({ limit: 50 })
      .then((res) => {
        if (res && res.incidents && res.incidents.length > 0) {
          setIncidents(res.incidents);
          loadIncidentData(res.incidents[0]);
        }
      })
      .catch(() => null);
  }, []);

  const loadIncidentData = (inc: Incident) => {
    setSelectedIncId(inc.incident_id);
    const ips = inc.entities.source_ips || [];
    const users = inc.entities.usernames || [];
    const hosts = inc.entities.hosts || [];

    setIrSummary({
      title: inc.title,
      severity: inc.severity.toUpperCase(),
      attacker: ips.join(', ') || 'Unknown IP',
      target: `User: ${users.join(', ') || 'N/A'} on Host: ${hosts.join(', ') || 'N/A'}`,
      actions: `1. Block source IP (${ips.join(', ') || 'Attacker'})\n2. Temporarily lock account (${users.join(', ') || 'Target'})\n3. Verify sessions in Response Console`,
      recovery: 'Rotate user credentials, verify SSH configurations, and re-enable account with MFA.',
    });
  };

  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const generateReportText = () => {
    return `# Incident Response Report — ${selectedIncId || 'DRAFT'}
**Incident:** ${irSummary.title}
**Severity:** ${irSummary.severity}
**Date:** ${new Date().toLocaleDateString()}

---

### 1. What Happened
- **Attacker Origin:** ${irSummary.attacker}
- **Targeted Assets:** ${irSummary.target}

### 2. Immediate Actions Taken
${irSummary.actions}

### 3. Recovery & Prevention
${irSummary.recovery}

---
*Report generated via ThreadGrid SIEM Playbook Engine*
`;
  };

  const filteredPlaybooks = PLAYBOOKS.filter((pb) =>
    pb.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
    pb.summary.toLowerCase().includes(searchQuery.toLowerCase()) ||
    (pb.ruleTag && pb.ruleTag.toLowerCase().includes(searchQuery.toLowerCase()))
  );

  const getIcon = (type: string) => {
    switch (type) {
      case 'shield':
        return <Shield size={20} color="#f59e0b" />;
      case 'alert':
        return <AlertTriangle size={20} color="#ef4444" />;
      case 'terminal':
        return <Terminal size={20} color="#a855f7" />;
      case 'user':
        return <UserCheck size={20} color="#38bdf8" />;
      case 'lock':
        return <Lock size={20} color="#10b981" />;
      default:
        return <Activity size={20} color="#f59e0b" />;
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem', maxWidth: '1200px', margin: '0 auto' }}>
      {/* ------------------------------------------------------------------- */}
      {/* Simple, Clean Header                                                */}
      {/* ------------------------------------------------------------------- */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '1rem', borderBottom: '1px solid var(--border-color)', paddingBottom: '1rem' }}>
        <div>
          <h1 style={{ fontSize: '1.5rem', fontWeight: 700, color: 'var(--text-primary)', margin: 0 }}>
            Incident Playbooks
          </h1>
          <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', margin: '0.25rem 0 0 0' }}>
            Simple, step-by-step procedures to handle security threats and contain attackers.
          </p>
        </div>

        {/* Tab Switcher */}
        <div style={{ display: 'flex', gap: '0.5rem', background: 'var(--bg-tertiary)', padding: '0.25rem', borderRadius: '8px', border: '1px solid var(--border-color)' }}>
          <button
            onClick={() => setActiveTab('playbooks')}
            style={{
              padding: '0.45rem 0.85rem',
              background: activeTab === 'playbooks' ? 'var(--color-primary)' : 'transparent',
              color: activeTab === 'playbooks' ? '#ffffff' : 'var(--text-secondary)',
              border: 'none',
              borderRadius: '6px',
              fontSize: '0.8125rem',
              fontWeight: 600,
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '0.35rem',
            }}
          >
            <BookOpen size={14} />
            Playbooks
          </button>
          <button
            onClick={() => setActiveTab('report')}
            style={{
              padding: '0.45rem 0.85rem',
              background: activeTab === 'report' ? 'var(--color-primary)' : 'transparent',
              color: activeTab === 'report' ? '#ffffff' : 'var(--text-secondary)',
              border: 'none',
              borderRadius: '6px',
              fontSize: '0.8125rem',
              fontWeight: 600,
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '0.35rem',
            }}
          >
            <FileText size={14} />
            Create Incident Report
          </button>
        </div>
      </div>

      {/* =================================================================== */}
      {/* TAB 1: PLAYBOOKS LIST (CLEAN & SIMPLE)                              */}
      {/* =================================================================== */}
      {activeTab === 'playbooks' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          {/* Simple Search Input */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', background: 'var(--bg-surface)', border: '1px solid var(--border-color)', borderRadius: '8px', padding: '0.6rem 0.85rem' }}>
            <Search size={16} color="var(--text-muted)" />
            <input
              type="text"
              placeholder="Search playbooks (e.g. brute force, password, sudo)..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              style={{
                width: '100%',
                background: 'transparent',
                border: 'none',
                color: 'var(--text-primary)',
                fontSize: '0.875rem',
                outline: 'none',
              }}
            />
          </div>

          {/* Cards Grid */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(340px, 1fr))', gap: '1rem' }}>
            {filteredPlaybooks.map((pb) => {
              const severityBg =
                pb.severity === 'critical' ? 'rgba(239, 68, 68, 0.15)' : pb.severity === 'high' ? 'rgba(249, 115, 22, 0.15)' : 'rgba(59, 130, 246, 0.15)';
              const severityColor =
                pb.severity === 'critical' ? '#ef4444' : pb.severity === 'high' ? '#f97316' : '#0284c7';

              return (
                <div
                  key={pb.id}
                  style={{
                    background: 'var(--bg-surface)',
                    border: '1px solid var(--border-color)',
                    borderRadius: '10px',
                    padding: '1.25rem',
                    display: 'flex',
                    flexDirection: 'column',
                    justifyContent: 'space-between',
                    gap: '1rem',
                    transition: 'border-color 0.15s ease, box-shadow 0.15s ease',
                    boxShadow: 'var(--shadow-card)',
                    cursor: 'pointer',
                  }}
                  onMouseEnter={(e) => (e.currentTarget.style.borderColor = 'var(--color-primary)')}
                  onMouseLeave={(e) => (e.currentTarget.style.borderColor = 'var(--border-color)')}
                  onClick={() => setSelectedPlaybook(pb)}
                >
                  <div>
                    {/* Card Top: Icon, Rule Tag, Severity */}
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.75rem' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                        <div style={{ padding: '0.4rem', borderRadius: '6px', background: 'var(--bg-tertiary)' }}>
                          {getIcon(pb.icon)}
                        </div>
                        {pb.ruleTag && (
                          <span style={{ fontSize: '0.75rem', fontFamily: 'monospace', fontWeight: 600, color: 'var(--text-secondary)' }}>
                            {pb.ruleTag}
                          </span>
                        )}
                      </div>

                      <span style={{ fontSize: '0.6875rem', fontWeight: 700, color: severityColor, background: severityBg, padding: '0.2rem 0.5rem', borderRadius: '4px', textTransform: 'uppercase' }}>
                        {pb.severity}
                      </span>
                    </div>

                    {/* Title & Plain English Summary */}
                    <h3 style={{ fontSize: '1rem', fontWeight: 600, color: 'var(--text-primary)', margin: '0 0 0.4rem 0' }}>
                      {pb.title}
                    </h3>
                    <p style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', margin: 0, lineHeight: 1.45 }}>
                      {pb.summary}
                    </p>
                  </div>

                  {/* Card Bottom: View Button */}
                  <div style={{ borderTop: '1px solid var(--border-color)', paddingTop: '0.75rem', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                    <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Action Checklist</span>
                    <span style={{ fontSize: '0.75rem', color: 'var(--color-primary)', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
                      Open Steps <ArrowRight size={13} />
                    </span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* =================================================================== */}
      {/* PLAYBOOK DETAIL MODAL (SIMPLE 3 STEPS)                              */}
      {/* =================================================================== */}
      {selectedPlaybook && (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            background: 'rgba(0, 0, 0, 0.75)',
            backdropFilter: 'blur(4px)',
            zIndex: 9999,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            padding: '1rem',
          }}
          onClick={() => setSelectedPlaybook(null)}
        >
          <div
            style={{
              width: '640px',
              maxWidth: '100%',
              maxHeight: '90vh',
              background: 'var(--bg-elevated)',
              border: '1px solid var(--border-color)',
              borderRadius: '12px',
              boxShadow: 'var(--shadow-xl)',
              display: 'flex',
              flexDirection: 'column',
              overflow: 'hidden',
            }}
            onClick={(e) => e.stopPropagation()}
          >
            {/* Modal Header */}
            <div style={{ padding: '1rem 1.25rem', background: 'var(--color-primary-bg)', borderBottom: '1px solid var(--border-color)', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.625rem' }}>
                <div style={{ padding: '0.35rem', borderRadius: '6px', background: 'var(--color-primary-bg)' }}>
                  {getIcon(selectedPlaybook.icon)}
                </div>
                <div>
                  <h3 style={{ fontSize: '1rem', fontWeight: 700, color: 'var(--text-primary)', margin: 0 }}>
                    {selectedPlaybook.title}
                  </h3>
                  <span style={{ fontSize: '0.75rem', color: 'var(--color-primary)' }}>
                    {selectedPlaybook.ruleTag ? `Detection: ${selectedPlaybook.ruleTag}` : 'Standard Procedure'}
                  </span>
                </div>
              </div>

              <button
                onClick={() => setSelectedPlaybook(null)}
                style={{ background: 'transparent', border: 'none', color: 'var(--text-secondary)', cursor: 'pointer', padding: '0.25rem' }}
              >
                <X size={18} />
              </button>
            </div>

            {/* Modal Body: 3 Clear Steps */}
            <div style={{ padding: '1.25rem', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              {/* Step 1: Check */}
              <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border-color)', borderRadius: '8px', padding: '1rem' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.4rem' }}>
                  <span style={{ background: '#0284c7', color: '#fff', fontSize: '0.75rem', fontWeight: 700, borderRadius: '50%', width: '20px', height: '20px', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                    1
                  </span>
                  <span style={{ fontSize: '0.875rem', fontWeight: 700, color: 'var(--text-primary)' }}>
                    Verify What Happened
                  </span>
                </div>
                <p style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', margin: 0, lineHeight: 1.45 }}>
                  {selectedPlaybook.whatHappened}
                </p>
              </div>

              {/* Step 2: Stop */}
              <div style={{ background: 'var(--bg-surface)', border: '1px solid rgba(239, 68, 68, 0.3)', borderRadius: '8px', padding: '1rem' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.4rem' }}>
                  <span style={{ background: '#ef4444', color: '#fff', fontSize: '0.75rem', fontWeight: 700, borderRadius: '50%', width: '20px', height: '20px', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                    2
                  </span>
                  <span style={{ fontSize: '0.875rem', fontWeight: 700, color: 'var(--text-primary)' }}>
                    Stop the Attacker (Immediate Action)
                  </span>
                </div>
                <p style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', margin: '0 0 0.5rem 0', lineHeight: 1.45 }}>
                  {selectedPlaybook.howToStop.description}
                </p>

                {/* Command snippets */}
                {selectedPlaybook.howToStop.linuxCommand && (
                  <div style={{ background: 'var(--bg-tertiary)', border: '1px solid var(--border-color)', borderRadius: '6px', padding: '0.5rem 0.75rem', marginTop: '0.5rem' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.2rem' }}>
                      <span style={{ fontSize: '0.6875rem', color: 'var(--text-muted)' }}>Linux Command:</span>
                      <button
                        onClick={() => handleCopy(selectedPlaybook.howToStop.linuxCommand!, 'linux')}
                        style={{ background: 'transparent', border: 'none', color: copiedKey === 'linux' ? '#10b981' : 'var(--text-secondary)', fontSize: '0.6875rem', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '0.2rem' }}
                      >
                        {copiedKey === 'linux' ? <Check size={12} /> : <Copy size={12} />}
                        {copiedKey === 'linux' ? 'Copied' : 'Copy'}
                      </button>
                    </div>
                    <pre style={{ margin: 0, fontSize: '0.75rem', color: '#0284c7', fontFamily: 'monospace', whiteSpace: 'pre-wrap' }}>
                      {selectedPlaybook.howToStop.linuxCommand}
                    </pre>
                  </div>
                )}
              </div>

              {/* Step 3: Recover & Prevent */}
              <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border-color)', borderRadius: '8px', padding: '1rem' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.4rem' }}>
                  <span style={{ background: '#10b981', color: '#fff', fontSize: '0.75rem', fontWeight: 700, borderRadius: '50%', width: '20px', height: '20px', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                    3
                  </span>
                  <span style={{ fontSize: '0.875rem', fontWeight: 700, color: 'var(--text-primary)' }}>
                    Recover & Prevent Recurrence
                  </span>
                </div>
                <p style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', margin: '0 0 0.35rem 0', lineHeight: 1.45 }}>
                  <strong>Recovery:</strong> {selectedPlaybook.howToRecover}
                </p>
                <p style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', margin: 0, lineHeight: 1.45 }}>
                  <strong>Prevention:</strong> {selectedPlaybook.howToPrevent}
                </p>
              </div>
            </div>

            {/* Modal Footer Actions */}
            <div style={{ padding: '0.875rem 1.25rem', background: 'var(--bg-elevated)', borderTop: '1px solid var(--border-color)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <button
                onClick={() => setSelectedPlaybook(null)}
                style={{ padding: '0.45rem 0.85rem', background: 'var(--bg-tertiary)', color: 'var(--text-primary)', border: '1px solid var(--border-color)', borderRadius: '6px', fontSize: '0.8125rem', cursor: 'pointer' }}
              >
                Close
              </button>

              <button
                onClick={() => {
                  setSelectedPlaybook(null);
                  navigate('/response');
                }}
                style={{
                  padding: '0.45rem 1rem',
                  background: 'var(--color-primary)',
                  color: '#ffffff',
                  border: 'none',
                  borderRadius: '6px',
                  fontSize: '0.8125rem',
                  fontWeight: 600,
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.35rem',
                }}
              >
                <Zap size={14} />
                Open Response Console
              </button>
            </div>
          </div>
        </div>
      )}

      {/* =================================================================== */}
      {/* TAB 2: INCIDENT REPORT BUILDER (CLEAN & DIRECT)                    */}
      {/* =================================================================== */}
      {activeTab === 'report' && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))', gap: '1.25rem' }}>
          {/* Input details */}
          <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border-color)', borderRadius: '10px', padding: '1.25rem', display: 'flex', flexDirection: 'column', gap: '0.875rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <h3 style={{ fontSize: '0.9375rem', fontWeight: 600, color: 'var(--text-primary)', margin: 0 }}>
                Incident Details
              </h3>

              {incidents.length > 0 && (
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                  <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>Load:</span>
                  <select
                    value={selectedIncId}
                    onChange={(e) => {
                      const inc = incidents.find((i) => i.incident_id === e.target.value);
                      if (inc) loadIncidentData(inc);
                    }}
                    style={{ background: 'var(--bg-input)', color: 'var(--text-primary)', border: '1px solid var(--border-input)', borderRadius: '4px', fontSize: '0.75rem', padding: '0.2rem 0.4rem' }}
                  >
                    {incidents.map((inc) => (
                      <option key={inc.incident_id} value={inc.incident_id}>
                        {inc.incident_id} - {inc.title.slice(0, 24)}
                      </option>
                    ))}
                  </select>
                </div>
              )}
            </div>

            <div>
              <label style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', display: 'block', marginBottom: '0.2rem' }}>Title:</label>
              <input
                type="text"
                value={irSummary.title}
                onChange={(e) => setIrSummary({ ...irSummary, title: e.target.value })}
                style={{ width: '100%', background: 'var(--bg-input)', border: '1px solid var(--border-input)', color: 'var(--text-primary)', borderRadius: '4px', padding: '0.4rem 0.6rem', fontSize: '0.8125rem' }}
              />
            </div>

            <div>
              <label style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', display: 'block', marginBottom: '0.2rem' }}>Attacker IP / Origin:</label>
              <input
                type="text"
                value={irSummary.attacker}
                onChange={(e) => setIrSummary({ ...irSummary, attacker: e.target.value })}
                style={{ width: '100%', background: 'var(--bg-input)', border: '1px solid var(--border-input)', color: 'var(--text-primary)', borderRadius: '4px', padding: '0.4rem 0.6rem', fontSize: '0.8125rem' }}
              />
            </div>

            <div>
              <label style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', display: 'block', marginBottom: '0.2rem' }}>Target Assets:</label>
              <input
                type="text"
                value={irSummary.target}
                onChange={(e) => setIrSummary({ ...irSummary, target: e.target.value })}
                style={{ width: '100%', background: 'var(--bg-input)', border: '1px solid var(--border-input)', color: 'var(--text-primary)', borderRadius: '4px', padding: '0.4rem 0.6rem', fontSize: '0.8125rem' }}
              />
            </div>

            <div>
              <label style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', display: 'block', marginBottom: '0.2rem' }}>Immediate Actions Taken:</label>
              <textarea
                rows={3}
                value={irSummary.actions}
                onChange={(e) => setIrSummary({ ...irSummary, actions: e.target.value })}
                style={{ width: '100%', background: 'var(--bg-input)', border: '1px solid var(--border-input)', color: 'var(--text-primary)', borderRadius: '4px', padding: '0.4rem 0.6rem', fontSize: '0.8125rem', resize: 'vertical' }}
              />
            </div>
          </div>

          {/* Generated Markdown Preview */}
          <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border-color)', borderRadius: '10px', padding: '1.25rem', display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <span style={{ fontSize: '0.8125rem', fontWeight: 600, color: 'var(--text-primary)' }}>
                Preview Document (.md)
              </span>

              <div style={{ display: 'flex', gap: '0.35rem' }}>
                <button
                  onClick={() => {
                    navigator.clipboard.writeText(generateReportText());
                    setCopiedReport(true);
                    setTimeout(() => setCopiedReport(false), 2000);
                  }}
                  style={{
                    padding: '0.3rem 0.65rem',
                    background: copiedReport ? '#10b981' : 'var(--bg-tertiary)',
                    color: copiedReport ? '#ffffff' : 'var(--text-primary)',
                    border: '1px solid var(--border-color)',
                    borderRadius: '4px',
                    fontSize: '0.75rem',
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.25rem',
                  }}
                >
                  {copiedReport ? <Check size={13} /> : <Copy size={13} />}
                  {copiedReport ? 'Copied' : 'Copy'}
                </button>

                <button
                  onClick={() => {
                    const blob = new Blob([generateReportText()], { type: 'text/markdown' });
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = `Incident_${selectedIncId || 'Report'}.md`;
                    a.click();
                    URL.revokeObjectURL(url);
                  }}
                  style={{
                    padding: '0.3rem 0.65rem',
                    background: '#7c3aed',
                    color: '#ffffff',
                    border: 'none',
                    borderRadius: '4px',
                    fontSize: '0.75rem',
                    fontWeight: 600,
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.25rem',
                  }}
                >
                  <Download size={13} />
                  Download
                </button>
              </div>
            </div>

            <pre
              style={{
                flex: 1,
                minHeight: '260px',
                background: 'var(--bg-tertiary)',
                padding: '0.75rem',
                borderRadius: '6px',
                fontSize: '0.75rem',
                color: 'var(--text-primary)',
                fontFamily: 'monospace',
                whiteSpace: 'pre-wrap',
                margin: 0,
                lineHeight: 1.45,
                border: '1px solid var(--border-color)',
              }}
            >
              {generateReportText()}
            </pre>
          </div>
        </div>
      )}
    </div>
  );
};

export default PlaybooksPage;
