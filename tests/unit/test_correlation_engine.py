"""Unit tests for IncidentCorrelator: positive multi-stage correlation and false-correlation prevention."""

import pytest
from backend.correlation.config import CorrelationConfig
from backend.correlation.correlator import IncidentCorrelator
from backend.correlation.risk import calculate_incident_risk
from backend.detection.schemas import Alert


def make_alert(
    rule_id: str,
    first_obs: str,
    last_obs: str,
    ip: str = None,
    user: str = None,
    host: str = "srv1",
    severity: str = "medium",
    event_ids: list = None,
) -> Alert:
    """Helper to synthesize test Alert."""
    entities = {}
    if ip:
        entities["source_ip"] = ip
    if user:
        entities["username"] = user
    if host:
        entities["host"] = host

    return Alert.create(
        rule_id=rule_id,
        rule_name=f"Rule {rule_id}",
        severity=severity,
        first_observed=first_obs,
        last_observed=last_obs,
        related_event_ids=event_ids or [f"ev_{rule_id}_{first_obs}"],
        explanation=f"Alert for {rule_id}",
        supporting_evidence={"rule": rule_id},
        entities=entities,
        confidence=0.85,
        risk_score=50.0,
    )


# ==============================================================================
# Positive Correlation Scenarios
# ==============================================================================


def test_positive_correlation_multistage_attack():
    """Multi-stage attack: Brute Force (RULE-001) -> Success (RULE-002) -> Privileged Exec (RULE-004)."""
    correlator = IncidentCorrelator(config=CorrelationConfig(correlation_window_seconds=3600))

    # Stage 1: Brute force from IP 192.168.1.100 targeting user 'admin'
    alert_bf = make_alert(
        "RULE-001",
        "2026-10-15T02:00:00Z",
        "2026-10-15T02:05:00Z",
        ip="192.168.1.100",
        user="admin",
        host="web-srv",
        severity="medium",
    )
    # Stage 2: Successful login for 'admin' from 192.168.1.100 (5 mins later)
    alert_success = make_alert(
        "RULE-002",
        "2026-10-15T02:06:00Z",
        "2026-10-15T02:06:30Z",
        ip="192.168.1.100",
        user="admin",
        host="web-srv",
        severity="high",
    )
    # Stage 3: Privileged command execution (/etc/shadow) by user 'admin' on web-srv (10 mins later)
    alert_priv = make_alert(
        "RULE-004",
        "2026-10-15T02:16:00Z",
        "2026-10-15T02:16:30Z",
        ip=None,  # Local sudo execution
        user="admin",
        host="web-srv",
        severity="high",
    )

    incidents = correlator.correlate_alerts([alert_bf, alert_success, alert_priv])

    assert len(incidents) == 1
    inc = incidents[0]
    assert inc.severity in {"critical", "high"}
    assert inc.risk_score >= 80.0  # High base + multi-technique + kill chain progression bonus
    assert set(inc.distinct_rules) == {"RULE-001", "RULE-002", "RULE-004"}
    assert "192.168.1.100" in inc.entities["source_ips"]
    assert "admin" in inc.entities["usernames"]
    assert "web-srv" in inc.entities["hosts"]
    assert len(inc.timeline) == 3
    assert "Multi-Stage" in inc.title


def test_positive_transitive_entity_correlation():
    """Transitive bridging: Alert A connects to Alert B via IP; Alert B connects to Alert C via User."""
    correlator = IncidentCorrelator(config=CorrelationConfig(correlation_window_seconds=3600))

    # Alert A: IP 10.10.10.50 (no user identified yet, e.g., reconnaissance)
    alert_a = make_alert(
        "RULE-005",
        "2026-10-15T03:00:00Z",
        "2026-10-15T03:02:00Z",
        ip="10.10.10.50",
        user=None,
        host="db-srv",
    )
    # Alert B: IP 10.10.10.50 targeting user 'service_account'
    alert_b = make_alert(
        "RULE-001",
        "2026-10-15T03:05:00Z",
        "2026-10-15T03:07:00Z",
        ip="10.10.10.50",
        user="service_account",
        host="db-srv",
    )
    # Alert C: user 'service_account' on db-srv running privileged command (no remote IP recorded)
    alert_c = make_alert(
        "RULE-004",
        "2026-10-15T03:15:00Z",
        "2026-10-15T03:15:30Z",
        ip=None,
        user="service_account",
        host="db-srv",
    )

    incidents = correlator.correlate_alerts([alert_a, alert_b, alert_c])

    assert len(incidents) == 1
    inc = incidents[0]
    assert set(inc.distinct_rules) == {"RULE-001", "RULE-004", "RULE-005"}
    assert "10.10.10.50" in inc.entities["source_ips"]
    assert "service_account" in inc.entities["usernames"]


# ==============================================================================
# False-Correlation Prevention (Negative Scenarios)
# ==============================================================================


def test_false_correlation_prevention_disjoint_entities():
    """Unrelated attacks from different IPs against different users must NOT merge."""
    correlator = IncidentCorrelator(config=CorrelationConfig(correlation_window_seconds=3600))

    # Attacker 1 targeting Alice from 1.1.1.1
    alert_1 = make_alert(
        "RULE-001",
        "2026-10-15T04:00:00Z",
        "2026-10-15T04:05:00Z",
        ip="1.1.1.1",
        user="alice",
        host="srv-alpha",
    )
    # Attacker 2 targeting Bob from 2.2.2.2
    alert_2 = make_alert(
        "RULE-001",
        "2026-10-15T04:02:00Z",
        "2026-10-15T04:06:00Z",
        ip="2.2.2.2",
        user="bob",
        host="srv-beta",
    )

    incidents = correlator.correlate_alerts([alert_1, alert_2])

    assert len(incidents) == 2
    inc_ips = [inc.entities["source_ips"] for inc in incidents]
    assert ["1.1.1.1"] in inc_ips
    assert ["2.2.2.2"] in inc_ips


def test_false_correlation_prevention_time_window_exceeded():
    """Same attacker IP and user occurring hours apart (outside correlation window) must NOT merge."""
    # 1 hour correlation window (3600s)
    correlator = IncidentCorrelator(config=CorrelationConfig(correlation_window_seconds=3600))

    # Morning attempt at 02:00 UTC
    alert_morning = make_alert(
        "RULE-001",
        "2026-10-15T02:00:00Z",
        "2026-10-15T02:05:00Z",
        ip="192.168.1.75",
        user="charlie",
        host="srv1",
    )
    # Afternoon attempt at 14:00 UTC (12 hours later)
    alert_afternoon = make_alert(
        "RULE-001",
        "2026-10-15T14:00:00Z",
        "2026-10-15T14:05:00Z",
        ip="192.168.1.75",
        user="charlie",
        host="srv1",
    )

    incidents = correlator.correlate_alerts([alert_morning, alert_afternoon])

    assert len(incidents) == 2


def test_false_correlation_prevention_generic_ignored_entities():
    """Generic/ambient placeholders ('unknown', 'system', '') must never correlate unrelated alerts."""
    correlator = IncidentCorrelator(config=CorrelationConfig(correlation_window_seconds=3600))

    # Alert A with unknown user and unknown IP
    alert_a = make_alert(
        "RULE-001",
        "2026-10-15T05:00:00Z",
        "2026-10-15T05:02:00Z",
        ip="unknown",
        user="unknown",
        host="srv-a",
    )
    # Alert B with different host, also unknown user
    alert_b = make_alert(
        "RULE-001",
        "2026-10-15T05:01:00Z",
        "2026-10-15T05:03:00Z",
        ip="unknown",
        user="unknown",
        host="srv-b",
    )

    incidents = correlator.correlate_alerts([alert_a, alert_b])

    assert len(incidents) == 2


def test_false_correlation_prevention_shared_host_only():
    """Two independent attacks on the same server from different IPs & users must NOT merge by default."""
    correlator = IncidentCorrelator(
        config=CorrelationConfig(
            correlation_window_seconds=3600,
            allow_host_only_correlation=False,  # default safe configuration
        )
    )

    # Attack on Alice from IP 5.5.5.5 on host 'bastion'
    alert_1 = make_alert(
        "RULE-001",
        "2026-10-15T06:00:00Z",
        "2026-10-15T06:03:00Z",
        ip="5.5.5.5",
        user="alice",
        host="bastion",
    )
    # Attack on Dave from IP 9.9.9.9 on host 'bastion'
    alert_2 = make_alert(
        "RULE-001",
        "2026-10-15T06:01:00Z",
        "2026-10-15T06:04:00Z",
        ip="9.9.9.9",
        user="dave",
        host="bastion",
    )

    incidents = correlator.correlate_alerts([alert_1, alert_2])

    assert len(incidents) == 2


# ==============================================================================
# Risk Prioritization Formula Verification
# ==============================================================================


def test_risk_prioritization_formula():
    """Verify deterministic risk scoring formula accurately matches specification."""
    # 1. Empty alerts
    score, sev = calculate_incident_risk([], {})
    assert score == 0.0
    assert sev == "low"

    # 2. Single low severity alert
    alert_low = make_alert("RULE-001", "2026-10-15T01:00:00Z", "2026-10-15T01:01:00Z", severity="low")
    score, sev = calculate_incident_risk([alert_low], {})
    assert score == 15.0
    assert sev == "low"

    # 3. High severity multi-stage kill chain progression
    alert_recon = make_alert("RULE-001", "2026-10-15T01:00:00Z", "2026-10-15T01:01:00Z", severity="high")
    alert_esc = make_alert("RULE-004", "2026-10-15T01:05:00Z", "2026-10-15T01:06:00Z", severity="high")
    score, sev = calculate_incident_risk([alert_recon, alert_esc], {"usernames": ["alice"], "hosts": ["srv1"]})
    # Base: 50.0 + Diversity (1 extra rule): 10.0 + KillChain progression: 15.0 + Volume bonus (2 alerts): 2.0 = 77.0
    assert score == 77.0
    assert sev == "high"

    # 4. Critical severity capped at 100
    alert_crit = make_alert("RULE-004", "2026-10-15T01:00:00Z", "2026-10-15T01:01:00Z", severity="critical")
    score, sev = calculate_incident_risk(
        [alert_recon, alert_esc, alert_crit],
        {"usernames": ["alice", "bob", "root"], "hosts": ["srv1", "srv2"]},
    )
    # Base: 70.0 + Diversity (2 extra): 20.0 + KillChain: 15.0 + Target diversity (3 users + 2 hosts): 10.0 = 115 -> clamped to 100.0
    assert score == 100.0
    assert sev == "critical"
