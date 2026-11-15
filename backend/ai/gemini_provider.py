"""Google Gemini AI integration for explainable incident investigation and interactive SOC chat."""

import json
import logging
import os
from typing import Any, Dict, List, Optional
import httpx

from collectors.common.schemas import SecurityEvent
from backend.correlation.schemas import Incident

logger = logging.getLogger("GeminiAIProvider")


class GeminiAIProvider:
    """Provides evidence-grounded incident analysis and conversational reasoning via Google Gemini API."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        timeout: float = 20.0,
    ):
        self.api_key = api_key or os.getenv("GEMINI_API_KEY", "").strip()
        self.model = model or os.getenv("GEMINI_MODEL", "gemini-2.5-flash").strip()
        self.timeout = timeout
        self.base_url = "https://generativelanguage.googleapis.com/v1beta/models"

    def is_configured(self) -> bool:
        """Return True if an API key is present."""
        return bool(self.api_key and len(self.api_key) > 5)

    def _call_gemini(
        self,
        system_instruction: str,
        user_prompt: str,
        response_json: bool = True,
    ) -> Optional[str]:
        """Make a POST request to Google Gemini generateContent endpoint."""
        if not self.is_configured():
            logger.info("Gemini API key not configured. Using local synthesizer.")
            return None

        url = f"{self.base_url}/{self.model}:generateContent?key={self.api_key}"

        payload: Dict[str, Any] = {
            "contents": [
                {
                    "parts": [{"text": user_prompt}]
                }
            ],
            "generationConfig": {
                "temperature": 0.2,
                "topP": 0.8,
            },
        }

        if system_instruction:
            payload["systemInstruction"] = {
                "parts": [{"text": system_instruction}]
            }

        if response_json:
            payload["generationConfig"]["responseMimeType"] = "application/json"

        try:
            with httpx.Client(timeout=self.timeout) as client:
                res = client.post(url, json=payload)
                if res.status_code == 200:
                    data = res.json()
                    candidates = data.get("candidates", [])
                    if candidates and "content" in candidates[0]:
                        parts = candidates[0]["content"].get("parts", [])
                        if parts:
                            return parts[0].get("text", "")
                else:
                    err_msg = res.json().get("error", {}).get("message", res.text[:200])
                    logger.warning(
                        f"Gemini API returned HTTP {res.status_code}: {err_msg}. "
                        "Falling back to local SOC engine."
                    )
                    return None
        except Exception as e:
            logger.warning(f"Failed to communicate with Gemini API: {e}. Falling back to local synthesizer.")
            return None

        return None

    def analyze_incident(
        self,
        incident: Incident,
        evidence_events: List[SecurityEvent],
    ) -> Optional[Dict[str, Any]]:
        """Generate structured investigation report using Gemini grounded in log evidence."""
        if not self.is_configured():
            return None

        # Build evidence context block
        event_lines: List[str] = []
        for ev in evidence_events[:25]:
            event_lines.append(
                f"- Event ID [{ev.event_id}] at {ev.timestamp} on host '{ev.source_host}': "
                f"type='{ev.event_type}', user='{ev.username or 'none'}', ip='{ev.source_ip or 'none'}', raw='{ev.raw_event}'"
            )
        evidence_context = "\n".join(event_lines) if event_lines else "No raw events attached."

        system_instruction = (
            "You are an expert Security Operations Center (SOC) Tier-3 Lead Investigator for the AI Cyber Defense Platform. "
            "You must synthesize an evidence-grounded incident analysis report. "
            "CRITICAL INSTRUCTION: Every statement in verified_facts and threat_hypotheses MUST cite valid event IDs "
            "(e.g. evt_...) or alert IDs (e.g. alt_...) present in the provided evidence. DO NOT hallucinate IDs. "
            "Output must be valid JSON matching this exact structure: "
            "{"
            "  \"executive_summary\": \"string\","
            "  \"verified_facts\": [{\"fact\": \"string\", \"citations\": [\"id1\", \"id2\"]}],"
            "  \"threat_hypotheses\": [{\"hypothesis\": \"string\", \"mitre_technique\": \"string\", \"confidence\": 0.95, \"supporting_citations\": [\"id1\"]}],"
            "  \"actionable_recommendations\": [{\"recommendation\": \"string\", \"priority\": \"critical|high|medium|low\", \"reversible\": true, \"action_type\": \"block_ip|lock_account|isolate_host|review_audit\", \"parameters\": {}}]"
            "}"
        )

        user_prompt = f"""
Analyze the following correlated security incident:
Incident ID: {incident.incident_id}
Title: {incident.title}
Severity: {incident.severity}
Risk Score: {incident.risk_score} / 100
First Seen: {incident.first_seen}
Last Seen: {incident.last_seen}
Target Users: {incident.entities.get('usernames', [])}
Source IPs: {incident.entities.get('source_ips', [])}
Target Hosts: {incident.entities.get('hosts', [])}
Triggered Detection Rules: {incident.distinct_rules}
Related Alert IDs: {incident.related_alert_ids}

VERIFIED FORENSIC EVIDENCE:
{evidence_context}
"""

        raw_json = self._call_gemini(system_instruction, user_prompt, response_json=True)
        if not raw_json:
            return None

        try:
            return json.loads(raw_json)
        except Exception as e:
            logger.warning(f"Could not parse Gemini JSON response: {e}")
            return None

    def chat_about_incident(
        self,
        incident: Incident,
        evidence_events: List[SecurityEvent],
        user_query: str,
        history: Optional[List[Dict[str, str]]] = None,
    ) -> Dict[str, Any]:
        """Conduct an interactive analyst Q&A session about the given incident."""
        source_ips = incident.entities.get("source_ips", [])
        usernames = incident.entities.get("usernames", [])
        hosts = incident.entities.get("hosts", [])

        # Try Gemini cloud inference first if key configured
        if self.is_configured():
            system_instruction = (
                "You are the ThreadGrid SIEM AI Copilot, a senior cyber defense specialist. "
                "Answer the security analyst's question with precise, evidence-grounded facts. "
                "Cite specific event IDs and alert IDs whenever referring to timeline events. "
                "Be concise, actionable, and reference MITRE ATT&CK tactics where appropriate. "
                "Output JSON with two keys: "
                "{\"answer\": \"string (markdown allowed)\", \"citations\": [\"id1\", \"id2\"], \"suggested_actions\": [\"action1\", \"action2\"]}"
            )

            prompt = f"""
Incident Context:
- ID: {incident.incident_id}
- Title: {incident.title}
- Severity: {incident.severity} (Risk: {incident.risk_score}/100)
- Attack IPs: {source_ips}
- Target Accounts: {usernames}
- Target Hosts: {hosts}
- Rules Triggered: {incident.distinct_rules}
- Evidence Events Count: {len(evidence_events)}

Analyst Question:
{user_query}
"""
            raw_reply = self._call_gemini(system_instruction, prompt, response_json=True)
            if raw_reply:
                try:
                    parsed = json.loads(raw_reply)
                    return {
                        "answer": parsed.get("answer", raw_reply),
                        "citations": parsed.get("citations", incident.related_alert_ids[:2]),
                        "suggested_actions": parsed.get("suggested_actions", []),
                        "model_used": f"Google Gemini ({self.model})",
                        "is_live_gemini": True,
                    }
                except Exception:
                    pass

        # Intelligent Local SOC Engine Fallback
        q_lower = user_query.lower()
        citations = incident.related_alert_ids[:3] + incident.related_event_ids[:2]
        suggested_actions: List[str] = []

        if "narrative" in q_lower or "explain" in q_lower or "what happened" in q_lower or "story" in q_lower:
            ip_str = ", ".join(source_ips) if source_ips else "an unknown IP"
            user_str = ", ".join(usernames) if usernames else "the targeted identity"
            host_str = ", ".join(hosts) if hosts else "the monitored endpoints"

            rules_desc = []
            if "RULE-001" in incident.distinct_rules:
                rules_desc.append("sustained authentication brute-forcing")
            if "RULE-002" in incident.distinct_rules:
                rules_desc.append("credential stuffing leading to a successful logon")
            if "RULE-003" in incident.distinct_rules:
                rules_desc.append("distributed password spraying across multiple targets")
            if "RULE-004" in incident.distinct_rules:
                rules_desc.append("privileged command execution and local escalation")
            if "RULE-005" in incident.distinct_rules:
                rules_desc.append("account reconnaissance enumeration")

            actions_text = " and ".join(rules_desc) if rules_desc else "anomalous security events"

            answer = (
                f"### Incident Attack Narrative\n\n"
                f"**Initial Access & Reconnaissance**: Between **{incident.first_seen}** and **{incident.last_seen}**, "
                f"threat actor activity was recorded from source IP(s) `{ip_str}` targeting account(s) `{user_str}` on host `{host_str}`.\n\n"
                f"**Technique Breakdown**:\n"
                f"- Activity triggered **{len(incident.distinct_rules)} detection rule(s)**: `{', '.join(incident.distinct_rules)}`.\n"
                f"- The attack pattern corresponds to **{actions_text}**.\n\n"
                f"**Forensic Impact**: This incident achieved a risk score of **{incident.risk_score:.1f}/100** ({incident.severity.upper()}), "
                f"requiring containment actions before lateral traversal expands to secondary subnets."
            )
            suggested_actions = ["Block Source IP at Firewall", "Lock Target Account", "Review Host Audit Logs"]

        elif "ciso" in q_lower or "executive" in q_lower or "summary" in q_lower:
            answer = (
                f"### Executive Incident Briefing (CISO Level)\n\n"
                f"- **Incident Status**: {incident.status} ({incident.severity.upper()} Severity - Risk {incident.risk_score:.1f}/100)\n"
                f"- **Target Asset**: Host `{', '.join(hosts) or 'Internal Endpoint'}` | Targeted User: `{', '.join(usernames) or 'Local Account'}`\n"
                f"- **Attacker Footprint**: `{', '.join(source_ips) or 'Inbound Actor'}`\n"
                f"- **Current Containment**: Automated response safeguards staged in Response Console awaiting sign-off.\n"
                f"- **Immediate Action**: Firewall boundary block recommended with reversible account lock."
            )
            suggested_actions = ["Export Executive PDF", "Notify SOC Incident Commander"]

        elif "contain" in q_lower or "action" in q_lower or "remediat" in q_lower:
            actions_list = []
            for ip in source_ips:
                actions_list.append(f"- **Block Inbound IP**: Execute firewall drop rule for `{ip}` via Response Console.")
            for u in usernames:
                if u not in ["root", "unknown"]:
                    actions_list.append(f"- **Revoke & Reset**: Temporarily lock account `{u}` and revoke Kerberos/SSH session tokens.")
            for h in hosts:
                actions_list.append(f"- **Quarantine Endpoint**: Sever network adapter connectivity on `{h}` except SOC telemetry.")

            answer = (
                f"### Recommended Containment Playbook\n\n"
                + "\n".join(actions_list) + "\n\n"
                f"*All response actions support 1-click dry-run execution with automatic rollback capability.*"
            )
            suggested_actions = ["Stage All Actions to Response Console", "Trigger Endpoint Isolation"]

        else:
            answer = (
                f"Based on verified forensic evidence for incident **{incident.incident_id}**:\n\n"
                f"- **Entities**: IP `{', '.join(source_ips)}`, User `{', '.join(usernames)}`, Host `{', '.join(hosts)}`\n"
                f"- **Risk Calculation**: Base severity + rule correlation multiplier yields **{incident.risk_score:.1f}/100**.\n"
                f"- **Evidence Correlation**: Linked across {len(incident.related_alert_ids)} alerts and {len(incident.related_event_ids)} raw events.\n\n"
                f"What specific dimension would you like to explore? (e.g., Attack narrative, MITRE ATT&CK mapping, or Containment plan)."
            )
            suggested_actions = ["Explain Attack Narrative", "Draft CISO Summary", "Recommend Containment Plan"]

        return {
            "answer": answer,
            "citations": citations,
            "suggested_actions": suggested_actions,
            "model_used": "ThreadGrid XAI Synthesizer (Local Fallback)",
            "is_live_gemini": False,
        }
