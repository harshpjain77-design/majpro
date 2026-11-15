"""Entity profile aggregation, multi-tab explorer, and forensic breakdown endpoints."""

from datetime import datetime, timezone
import ipaddress
import json
import logging
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from backend.api.dependencies import incident_repo, response_repo, storage_sink, verify_api_key
from collectors.common.schemas import SecurityEvent

logger = logging.getLogger("EntitiesAPI")

router = APIRouter(
    prefix="/api/v1/entities",
    tags=["Entities"],
    dependencies=[Depends(verify_api_key)],
)


# ---------------------------------------------------------------------------
# Pydantic Schemas
# ---------------------------------------------------------------------------

class EntitySummaryMetrics(BaseModel):
    total_entities: int = Field(..., description="Total distinct entities across users, IPs, and hosts")
    high_risk_entities: int = Field(..., description="Count of entities with high or critical risk")
    attack_ips: int = Field(..., description="Count of external threat IP entities")
    privileged_accounts: int = Field(..., description="Count of privileged user accounts")
    endpoint_hosts: int = Field(..., description="Count of monitored endpoint hosts")
    total_events: int = Field(..., description="Total events ingested across the system")


class UserEntity(BaseModel):
    username: str
    account_type: str = Field(..., description="privileged | service | invalid | standard")
    total_events: int
    failed_logins: int
    successful_logins: int
    failure_ratio: float
    risk_score: float
    risk_tier: str = Field(..., description="low | medium | high | critical")
    hosts: List[str]
    ips: List[str]
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    incident_count: int = 0
    incident_ids: List[str] = []
    highest_severity: Optional[str] = None
    containment_status: str = Field("uncontained", description="contained | pending | uncontained")


class IPEntity(BaseModel):
    ip: str
    scope: str = Field(..., description="external | internal | loopback")
    total_events: int
    target_users_count: int
    target_users: List[str]
    target_hosts_count: int
    target_hosts: List[str]
    threat_tag: str
    risk_score: float
    risk_tier: str = Field(..., description="low | medium | high | critical")
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    incident_count: int = 0
    incident_ids: List[str] = []
    highest_severity: Optional[str] = None
    containment_status: str = Field("uncontained", description="contained | pending | uncontained")


class HostEntity(BaseModel):
    hostname: str
    os_type: str = Field(..., description="windows | linux | other")
    source_types: List[str]
    total_events: int
    users_count: int
    users: List[str]
    ips_count: int
    ips: List[str]
    status: str = Field(..., description="online | idle | offline")
    risk_score: float
    risk_tier: str = Field(..., description="low | medium | high | critical")
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    incident_count: int = 0
    incident_ids: List[str] = []
    highest_severity: Optional[str] = None
    containment_status: str = Field("uncontained", description="contained | pending | uncontained")


class EntitiesExplorerResponse(BaseModel):
    summary: EntitySummaryMetrics
    users: List[UserEntity]
    ips: List[IPEntity]
    hosts: List[HostEntity]


class EntityDetailResponse(BaseModel):
    entity_type: str
    identifier: str
    metrics: Dict[str, Any]
    recent_events: List[SecurityEvent]
    incidents: List[Dict[str, Any]]
    actions: List[Dict[str, Any]]
    recommended_actions: List[Dict[str, Any]]


# ---------------------------------------------------------------------------
# Helper Classifiers and Risk Scorers
# ---------------------------------------------------------------------------

def classify_ip_scope(ip_str: str) -> str:
    """Classify IP address into loopback, internal (RFC 1918), or external."""
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        if ip.is_loopback:
            return "loopback"
        is_rfc1918 = (
            ip in ipaddress.ip_network("10.0.0.0/8")
            or ip in ipaddress.ip_network("172.16.0.0/12")
            or ip in ipaddress.ip_network("192.168.0.0/16")
            or ip in ipaddress.ip_network("169.254.0.0/16")
        )
        if is_rfc1918:
            return "internal"
        return "external"
    except ValueError:
        return "external"


def classify_account_type(username: str) -> str:
    """Classify username into privileged, service, invalid, or standard account."""
    u = username.lower().strip()
    if u.endswith("_svc") or u.endswith("$") or u in ["sshd", "lightdm", "daemon", "www-data"]:
        return "service"
    if any(p in u for p in ["root", "admin", "system", "local service", "network service"]):
        return "privileged"
    if any(w in u for w in ["fake", "invalid", "unknown", "victim_user"]):
        return "invalid"
    return "standard"


def classify_host_os(hostname: str, source_types: List[str]) -> str:
    """Identify host operating system from hostname and source event types."""
    h = hostname.lower().strip()
    sources = " ".join(source_types).lower()
    if "win" in h or "workstation" in h or "windows" in sources:
        return "windows"
    if "kali" in h or "linux" in h or "systemd" in sources or "journal" in sources:
        return "linux"
    return "other"


def compute_risk_tier(score: float) -> str:
    if score >= 80.0:
        return "critical"
    if score >= 60.0:
        return "high"
    if score >= 30.0:
        return "medium"
    return "low"


# ---------------------------------------------------------------------------
# Route Handlers
# ---------------------------------------------------------------------------

@router.get("", response_model=EntitiesExplorerResponse)
async def get_entities_explorer(
    q: Optional[str] = Query(None, description="Search filter substring across entity names"),
    tier: Optional[str] = Query(None, description="Risk tier filter: all, critical, high, medium, low"),
) -> EntitiesExplorerResponse:
    """Aggregate all entities (users, IPs, hosts) with live database statistics and risk tiers."""
    conn = storage_sink._get_connection()
    cursor = conn.cursor()

    # 1. Index incidents by entity (safely handle if incidents table not yet initialized)
    user_inc: Dict[str, List[Dict[str, Any]]] = {}
    ip_inc: Dict[str, List[Dict[str, Any]]] = {}
    host_inc: Dict[str, List[Dict[str, Any]]] = {}
    try:
        cursor.execute("SELECT incident_id, title, severity, risk_score, entities_json FROM incidents;")
        incident_rows = cursor.fetchall()
        for r in incident_rows:
            inc_data = {
                "incident_id": r["incident_id"],
                "title": r["title"],
                "severity": r["severity"],
                "risk_score": float(r["risk_score"] or 0.0),
            }
            ent = json.loads(r["entities_json"] or "{}")
            for u in ent.get("usernames", []):
                user_inc.setdefault(u.lower().strip(), []).append(inc_data)
            for ip in ent.get("source_ips", []):
                ip_inc.setdefault(ip.strip(), []).append(inc_data)
            for h in ent.get("hosts", []):
                host_inc.setdefault(h.lower().strip(), []).append(inc_data)
    except Exception:
        pass

    # 2. Index response actions by target (safely handle if table not yet initialized)
    actions_by_target: Dict[str, List[Dict[str, Any]]] = {}
    try:
        cursor.execute("SELECT action_id, incident_id, action_type, target, status FROM response_actions;")
        action_rows = cursor.fetchall()
        for a in action_rows:
            t = str(a["target"]).strip().lower()
            actions_by_target.setdefault(t, []).append(dict(a))
    except Exception:
        pass

    def get_containment_status(target: str) -> str:
        acts = actions_by_target.get(target.lower().strip(), [])
        if any(act.get("status") in ["EXECUTED", "ENFORCED"] for act in acts):
            return "contained"
        if any(act.get("status") in ["PENDING", "PROPOSED", "APPROVED"] for act in acts):
            return "pending"
        return "uncontained"

    # 3. Users Aggregation
    cursor.execute("""
        SELECT 
            username,
            COUNT(*) as total_events,
            SUM(CASE WHEN event_type IN ('authentication_failure', 'auth_failure') OR windows_event_id IN (4625, 4771) OR raw_event LIKE '%Failed password%' THEN 1 ELSE 0 END) as failed_logins,
            SUM(CASE WHEN event_type IN ('authentication_success', 'auth_success') OR windows_event_id IN (4624) OR raw_event LIKE '%Accepted password%' THEN 1 ELSE 0 END) as successful_logins,
            GROUP_CONCAT(DISTINCT source_host) as hosts_str,
            GROUP_CONCAT(DISTINCT source_ip) as ips_str,
            MIN(timestamp) as first_seen,
            MAX(timestamp) as last_seen
        FROM events
        WHERE username IS NOT NULL AND TRIM(username) != ''
        GROUP BY username
        ORDER BY total_events DESC;
    """)
    user_rows = cursor.fetchall()
    user_entities: List[UserEntity] = []

    for row in user_rows:
        uname = row["username"].strip()
        u_lower = uname.lower()
        acct_type = classify_account_type(uname)
        total_evts = int(row["total_events"] or 0)
        failed = int(row["failed_logins"] or 0)
        successful = int(row["successful_logins"] or 0)
        fail_ratio = round(failed / max(1, failed + successful), 3)

        hosts = [h.strip() for h in (row["hosts_str"] or "").split(",") if h.strip()]
        ips = [ip.strip() for ip in (row["ips_str"] or "").split(",") if ip.strip()]

        inc_list = user_inc.get(u_lower, [])
        inc_ids = [i["incident_id"] for i in inc_list]
        highest_sev = None
        max_inc_risk = 0.0
        sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        cur_rank = 0
        for i in inc_list:
            s = str(i["severity"]).lower()
            if sev_rank.get(s, 0) > cur_rank:
                cur_rank = sev_rank.get(s, 0)
                highest_sev = s
            max_inc_risk = max(max_inc_risk, i["risk_score"])

        # Compute dynamic risk score
        base_risk = 15.0 if acct_type == "privileged" else 5.0
        fail_penalty = min(35.0, failed * 4.0)
        ratio_penalty = 15.0 if fail_ratio > 0.5 and failed > 2 else 0.0
        inc_penalty = min(40.0, len(inc_list) * 20.0)
        calculated_risk = min(100.0, max(base_risk + fail_penalty + ratio_penalty + inc_penalty, max_inc_risk))
        risk_tier = compute_risk_tier(calculated_risk)

        user_entities.append(UserEntity(
            username=uname,
            account_type=acct_type,
            total_events=total_evts,
            failed_logins=failed,
            successful_logins=successful,
            failure_ratio=fail_ratio,
            risk_score=round(calculated_risk, 1),
            risk_tier=risk_tier,
            hosts=hosts,
            ips=ips,
            first_seen=row["first_seen"],
            last_seen=row["last_seen"],
            incident_count=len(inc_ids),
            incident_ids=inc_ids,
            highest_severity=highest_sev,
            containment_status=get_containment_status(uname),
        ))

    # 4. IPs Aggregation
    cursor.execute("""
        SELECT 
            source_ip,
            COUNT(*) as total_events,
            SUM(CASE WHEN event_type IN ('authentication_failure', 'auth_failure') OR windows_event_id IN (4625, 4771) OR raw_event LIKE '%Failed password%' THEN 1 ELSE 0 END) as failed_logins,
            GROUP_CONCAT(DISTINCT username) as users_str,
            GROUP_CONCAT(DISTINCT source_host) as hosts_str,
            MIN(timestamp) as first_seen,
            MAX(timestamp) as last_seen
        FROM events
        WHERE source_ip IS NOT NULL AND TRIM(source_ip) != ''
        GROUP BY source_ip
        ORDER BY total_events DESC;
    """)
    ip_rows = cursor.fetchall()
    ip_entities: List[IPEntity] = []

    for row in ip_rows:
        ip_addr = row["source_ip"].strip()
        scope = classify_ip_scope(ip_addr)
        total_evts = int(row["total_events"] or 0)
        failed = int(row["failed_logins"] or 0)
        users = [u.strip() for u in (row["users_str"] or "").split(",") if u.strip()]
        hosts = [h.strip() for h in (row["hosts_str"] or "").split(",") if h.strip()]

        inc_list = ip_inc.get(ip_addr, [])
        inc_ids = [i["incident_id"] for i in inc_list]
        highest_sev = None
        max_inc_risk = 0.0
        sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        cur_rank = 0
        for i in inc_list:
            s = str(i["severity"]).lower()
            if sev_rank.get(s, 0) > cur_rank:
                cur_rank = sev_rank.get(s, 0)
                highest_sev = s
            max_inc_risk = max(max_inc_risk, i["risk_score"])

        # Determine threat tag
        if scope == "loopback":
            threat_tag = "Local Agent / Loopback"
        elif len(users) >= 3 and failed >= 3:
            threat_tag = "Password Spray Attacker"
        elif failed >= 5:
            threat_tag = "Brute Force Source"
        elif scope == "external" and len(inc_ids) > 0:
            threat_tag = "External Threat Actor"
        elif scope == "external":
            threat_tag = "External Inbound Host"
        else:
            threat_tag = "Internal LAN Endpoint"

        # Compute dynamic risk score
        base_risk = 30.0 if scope == "external" else (10.0 if scope == "internal" else 5.0)
        fail_penalty = min(35.0, failed * 4.0)
        spray_penalty = 20.0 if len(users) >= 3 else 0.0
        inc_penalty = min(40.0, len(inc_list) * 20.0)
        calculated_risk = min(100.0, max(base_risk + fail_penalty + spray_penalty + inc_penalty, max_inc_risk))
        risk_tier = compute_risk_tier(calculated_risk)

        ip_entities.append(IPEntity(
            ip=ip_addr,
            scope=scope,
            total_events=total_evts,
            target_users_count=len(users),
            target_users=users,
            target_hosts_count=len(hosts),
            target_hosts=hosts,
            threat_tag=threat_tag,
            risk_score=round(calculated_risk, 1),
            risk_tier=risk_tier,
            first_seen=row["first_seen"],
            last_seen=row["last_seen"],
            incident_count=len(inc_ids),
            incident_ids=inc_ids,
            highest_severity=highest_sev,
            containment_status=get_containment_status(ip_addr),
        ))

    # 5. Hosts Aggregation
    cursor.execute("""
        SELECT 
            source_host,
            COUNT(*) as total_events,
            GROUP_CONCAT(DISTINCT source_type) as source_types_str,
            GROUP_CONCAT(DISTINCT username) as users_str,
            GROUP_CONCAT(DISTINCT source_ip) as ips_str,
            MIN(timestamp) as first_seen,
            MAX(timestamp) as last_seen
        FROM events
        WHERE source_host IS NOT NULL AND TRIM(source_host) != ''
        GROUP BY source_host
        ORDER BY total_events DESC;
    """)
    host_rows = cursor.fetchall()
    host_entities: List[HostEntity] = []

    for row in host_rows:
        hname = row["source_host"].strip()
        h_lower = hname.lower()
        source_types = [s.strip() for s in (row["source_types_str"] or "").split(",") if s.strip()]
        os_type = classify_host_os(hname, source_types)
        total_evts = int(row["total_events"] or 0)
        users = [u.strip() for u in (row["users_str"] or "").split(",") if u.strip()]
        ips = [ip.strip() for ip in (row["ips_str"] or "").split(",") if ip.strip()]

        inc_list = host_inc.get(h_lower, [])
        inc_ids = [i["incident_id"] for i in inc_list]
        highest_sev = None
        max_inc_risk = 0.0
        sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        cur_rank = 0
        for i in inc_list:
            s = str(i["severity"]).lower()
            if sev_rank.get(s, 0) > cur_rank:
                cur_rank = sev_rank.get(s, 0)
                highest_sev = s
            max_inc_risk = max(max_inc_risk, i["risk_score"])

        # Determine host ingestion status based on last seen activity
        host_status = "idle"
        if row["last_seen"]:
            try:
                # ISO-8601 parsing
                clean_ts = row["last_seen"].replace("Z", "+00:00")
                last_dt = datetime.fromisoformat(clean_ts)
                now_dt = datetime.now(timezone.utc)
                diff_hours = (now_dt - last_dt).total_seconds() / 3600.0
                if diff_hours <= 48:
                    host_status = "online"
                else:
                    host_status = "idle"
            except Exception:
                host_status = "online"

        base_risk = 10.0
        inc_penalty = min(50.0, len(inc_list) * 25.0)
        calculated_risk = min(100.0, max(base_risk + inc_penalty, max_inc_risk))
        risk_tier = compute_risk_tier(calculated_risk)

        host_entities.append(HostEntity(
            hostname=hname,
            os_type=os_type,
            source_types=source_types,
            total_events=total_evts,
            users_count=len(users),
            users=users,
            ips_count=len(ips),
            ips=ips,
            status=host_status,
            risk_score=round(calculated_risk, 1),
            risk_tier=risk_tier,
            first_seen=row["first_seen"],
            last_seen=row["last_seen"],
            incident_count=len(inc_ids),
            incident_ids=inc_ids,
            highest_severity=highest_sev,
            containment_status=get_containment_status(hname),
        ))

    # Overall Summary
    total_events = storage_sink.count_events()
    total_entities_count = len(user_entities) + len(ip_entities) + len(host_entities)
    high_risk_count = (
        sum(1 for u in user_entities if u.risk_tier in ["high", "critical"])
        + sum(1 for ip in ip_entities if ip.risk_tier in ["high", "critical"])
        + sum(1 for h in host_entities if h.risk_tier in ["high", "critical"])
    )
    attack_ips_count = sum(1 for ip in ip_entities if ip.scope == "external" or ip.risk_tier in ["high", "critical"])
    privileged_accounts_count = sum(1 for u in user_entities if u.account_type == "privileged")
    endpoint_hosts_count = len(host_entities)

    summary = EntitySummaryMetrics(
        total_entities=total_entities_count,
        high_risk_entities=high_risk_count,
        attack_ips=attack_ips_count,
        privileged_accounts=privileged_accounts_count,
        endpoint_hosts=endpoint_hosts_count,
        total_events=total_events,
    )

    # Optional query filters
    filtered_users = user_entities
    filtered_ips = ip_entities
    filtered_hosts = host_entities

    if q:
        query_str = q.strip().lower()
        filtered_users = [u for u in filtered_users if query_str in u.username.lower()]
        filtered_ips = [ip for ip in filtered_ips if query_str in ip.ip.lower() or query_str in ip.threat_tag.lower()]
        filtered_hosts = [h for h in filtered_hosts if query_str in h.hostname.lower()]

    if tier and tier.lower() != "all":
        target_tier = tier.strip().lower()
        filtered_users = [u for u in filtered_users if u.risk_tier == target_tier]
        filtered_ips = [ip for ip in filtered_ips if ip.risk_tier == target_tier]
        filtered_hosts = [h for h in filtered_hosts if h.risk_tier == target_tier]

    return EntitiesExplorerResponse(
        summary=summary,
        users=filtered_users,
        ips=filtered_ips,
        hosts=filtered_hosts,
    )


@router.get("/{entity_type}/{identifier}", response_model=EntityDetailResponse)
async def get_entity_detail(
    entity_type: str,
    identifier: str,
    limit: int = Query(25, ge=1, le=100, description="Max recent events to return"),
) -> EntityDetailResponse:
    """Retrieve deep forensic profile, recent raw security events, associated incidents, and containment actions."""
    e_type = entity_type.strip().lower()
    ident = identifier.strip()

    if e_type not in ["user", "ip", "host"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid entity type '{entity_type}'. Must be 'user', 'ip', or 'host'.",
        )

    conn = storage_sink._get_connection()
    cursor = conn.cursor()

    # Query matching events
    if e_type == "user":
        where_cond = "LOWER(username) = LOWER(?)"
        target_param = ident
    elif e_type == "ip":
        where_cond = "(source_ip = ? OR destination_ip = ?)"
        target_param = ident
    else:  # host
        where_cond = "LOWER(source_host) = LOWER(?)"
        target_param = ident

    if e_type == "ip":
        cursor.execute(
            f"SELECT * FROM events WHERE {where_cond} ORDER BY timestamp DESC LIMIT ?;",
            (target_param, target_param, limit),
        )
    else:
        cursor.execute(
            f"SELECT * FROM events WHERE {where_cond} ORDER BY timestamp DESC LIMIT ?;",
            (target_param, limit),
        )

    recent_events = [storage_sink._row_to_event(row) for row in cursor.fetchall()]

    # Query matching incidents (safely handle if incidents table not yet initialized)
    matching_incidents: List[Dict[str, Any]] = []
    try:
        cursor.execute("SELECT * FROM incidents ORDER BY risk_score DESC;")
        for row in cursor.fetchall():
            ent = json.loads(row["entities_json"] or "{}")
            matched = False
            if e_type == "user" and any(u.lower() == ident.lower() for u in ent.get("usernames", [])):
                matched = True
            elif e_type == "ip" and ident in ent.get("source_ips", []):
                matched = True
            elif e_type == "host" and any(h.lower() == ident.lower() for h in ent.get("hosts", [])):
                matched = True

            if matched:
                matching_incidents.append({
                    "incident_id": row["incident_id"],
                    "title": row["title"],
                    "severity": row["severity"],
                    "status": row["status"],
                    "risk_score": row["risk_score"],
                    "created_at": row["created_at"],
                })
    except Exception:
        pass

    # Query matching response actions (safely handle if table not yet initialized)
    matching_actions: List[Dict[str, Any]] = []
    try:
        cursor.execute(
            "SELECT * FROM response_actions WHERE LOWER(target) = LOWER(?) ORDER BY created_at DESC;",
            (ident,),
        )
        matching_actions = [dict(r) for r in cursor.fetchall()]
    except Exception:
        pass

    # Generate context-aware containment recommendations
    recommended_actions: List[Dict[str, Any]] = []
    if e_type == "ip":
        recommended_actions.append({
            "action_type": "block_ip",
            "target": ident,
            "priority": "HIGH",
            "parameters": {"ip_address": ident, "direction": "inbound"},
            "reason": f"Contain inbound network access from threat IP {ident}",
            "reversible": True,
        })
        recommended_actions.append({
            "action_type": "isolate_host",
            "target": ident,
            "priority": "MEDIUM",
            "parameters": {"ip_address": ident},
            "reason": f"Network quarantine for suspected host with IP {ident}",
            "reversible": True,
        })
    elif e_type == "user":
        recommended_actions.append({
            "action_type": "lock_account",
            "target": ident,
            "priority": "HIGH",
            "parameters": {"username": ident},
            "reason": f"Disable compromised or targeted account '{ident}' to stop unauthorized lateral movement",
            "reversible": True,
        })
    elif e_type == "host":
        recommended_actions.append({
            "action_type": "isolate_host",
            "target": ident,
            "priority": "HIGH",
            "parameters": {"hostname": ident},
            "reason": f"Sever network adapter connectivity on compromised endpoint '{ident}'",
            "reversible": True,
        })
        recommended_actions.append({
            "action_type": "review_audit",
            "target": ident,
            "priority": "LOW",
            "parameters": {"hostname": ident},
            "reason": f"Initiate forensic memory collection and audit log export for '{ident}'",
            "reversible": False,
        })

    metrics = {
        "event_count": len(recent_events),
        "incident_count": len(matching_incidents),
        "action_count": len(matching_actions),
    }

    return EntityDetailResponse(
        entity_type=e_type,
        identifier=ident,
        metrics=metrics,
        recent_events=recent_events,
        incidents=matching_incidents,
        actions=matching_actions,
        recommended_actions=recommended_actions,
    )
