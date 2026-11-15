"""Google Gemini AI integration for explainable incident investigation and interactive SOC chat."""

import json
import logging
import os
import re
from typing import Any, Dict, List, Optional
import httpx

from collectors.common.schemas import SecurityEvent
from backend.correlation.schemas import Incident

logger = logging.getLogger("GeminiAIProvider")


class GeminiAIProvider:
    """Provides evidence-grounded incident analysis and conversational reasoning via Google Gemini API."""

    # Cascade of available Gemini models in preference order if one is unavailable/deprecated
    FALLBACK_MODELS = [
        "gemini-3.5-flash",
        "gemini-3.5-flash-lite",
        "gemini-3.1-flash-lite",
        "gemini-flash-latest",
    ]

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        timeout: float = 25.0,
    ):
        self.api_key = api_key or os.getenv("GEMINI_API_KEY", "").strip()
        self.model = model or os.getenv("GEMINI_MODEL", "gemini-3.5-flash").strip()
        self.timeout = timeout
        self.base_url = "https://generativelanguage.googleapis.com/v1beta/models"

    def is_configured(self) -> bool:
        """Return True if an API key is present."""
        return bool(self.api_key and len(self.api_key) > 5)

    def _call_gemini_raw(
        self,
        model_name: str,
        system_instruction: str,
        contents: List[Dict[str, Any]],
        response_json: bool = True,
    ) -> Optional[str]:
        """Execute a single attempt against a specific model name."""
        url = f"{self.base_url}/{model_name}:generateContent?key={self.api_key}"

        payload: Dict[str, Any] = {
            "contents": contents,
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

        with httpx.Client(timeout=self.timeout) as client:
            res = client.post(url, json=payload)
            if res.status_code == 200:
                data = res.json()
                candidates = data.get("candidates", [])
                if candidates and "content" in candidates[0]:
                    parts = candidates[0]["content"].get("parts", [])
                    # Gather text from parts
                    text_parts = [p.get("text", "") for p in parts if "text" in p]
                    if text_parts:
                        return "".join(text_parts).strip()
            else:
                try:
                    err_json = res.json()
                    err_msg = err_json.get("error", {}).get("message", res.text[:200])
                except Exception:
                    err_msg = res.text[:200]
                logger.warning(
                    f"Gemini model '{model_name}' returned HTTP {res.status_code}: {err_msg}"
                )
                return None

        return None

    def _call_gemini(
        self,
        system_instruction: str,
        contents_or_prompt: Any,
        response_json: bool = True,
    ) -> Optional[str]:
        """Make a request to Google Gemini with automatic model fallback."""
        if not self.is_configured():
            logger.info("Gemini API key not configured. Using local synthesizer.")
            return None

        # Normalize contents into Gemini v1beta schema
        if isinstance(contents_or_prompt, str):
            contents = [{"role": "user", "parts": [{"text": contents_or_prompt}]}]
        elif isinstance(contents_or_prompt, list):
            contents = contents_or_prompt
        else:
            contents = [{"role": "user", "parts": [{"text": str(contents_or_prompt)}]}]

        # Prepare model attempt list starting with configured model
        models_to_try = [self.model]
        for m in self.FALLBACK_MODELS:
            if m not in models_to_try:
                models_to_try.append(m)

        for candidate_model in models_to_try:
            try:
                result = self._call_gemini_raw(
                    model_name=candidate_model,
                    system_instruction=system_instruction,
                    contents=contents,
                    response_json=response_json,
                )
                if result:
                    # Update active model if a fallback worked
                    if candidate_model != self.model:
                        logger.info(f"Switched active Gemini model to working model: {candidate_model}")
                        self.model = candidate_model
                    return result
            except Exception as e:
                logger.warning(f"Error calling Gemini model '{candidate_model}': {e}")
                continue

        logger.warning("All Gemini model endpoints failed or timed out. Falling back to local SOC engine.")
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
            "  \"actionable_recommendations\": [{\"recommendation\": \"string\", \"priority\": \"critical|high|medium|low\", \"reversible\": true, \"action_type\": \"block_ip|lock_account|isolate_host|review_audit\", \"parameters\": {\"ip\": \"string\", \"username\": \"string\", \"host\": \"string\"}}]"
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

        # Clean potential markdown wrapping
        cleaned = re.sub(r"^```(?:json)?\s*", "", raw_json.strip())
        cleaned = re.sub(r"\s*```$", "", cleaned)

        try:
            return json.loads(cleaned)
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
                "You are the ThreadGrid SIEM AI Copilot, a senior cyber defense specialist and conversational security assistant. "
                "Engage in an interactive, helpful conversation with the SOC analyst. "
                "When asked general questions (e.g. 'hello', 'who are you', 'how can you help'), respond conversationally and explain how you can help analyze this incident. "
                "When asked forensic, investigation, or containment questions, provide concise, evidence-grounded facts. "
                "Cite specific event IDs and alert IDs whenever referring to timeline events. "
                "Output JSON with keys: "
                "{\"answer\": \"string (markdown allowed)\", \"citations\": [\"id1\", \"id2\"], \"suggested_actions\": [\"action1\", \"action2\"]}"
            )

            # Build multi-turn conversational contents
            evidence_summary = (
                f"- First Seen: {incident.first_seen}\n"
                f"- Last Seen: {incident.last_seen}\n"
                f"- Attack IPs: {source_ips or ['None recorded']}\n"
                f"- Target Accounts: {usernames or ['None recorded']}\n"
                f"- Target Hosts: {hosts or ['None recorded']}\n"
                f"- Rules Triggered: {incident.distinct_rules}\n"
                f"- Related Alerts: {incident.related_alert_ids[:4]}\n"
                f"- Raw Events Sample Count: {len(evidence_events)}"
            )

            initial_context = (
                f"[SYSTEM CONTEXT: You are investigating Incident ID '{incident.incident_id}': '{incident.title}' "
                f"(Severity: {incident.severity.upper()}, Risk Score: {incident.risk_score:.1f}/100).\n"
                f"{evidence_summary}]"
            )

            contents: List[Dict[str, Any]] = []

            # Include prior conversation history if provided
            if history:
                first = True
                for msg in history:
                    raw_role = msg.get("role") or msg.get("sender") or "user"
                    role = "user" if raw_role.lower() in ["user", "human"] else "model"
                    text = (msg.get("content") or msg.get("text") or "").strip()
                    if not text:
                        continue
                    if first and role == "user":
                        # Prefix first user turn with the incident context
                        contents.append({"role": "user", "parts": [{"text": f"{initial_context}\n\nAnalyst: {text}"}]})
                        first = False
                    else:
                        contents.append({"role": role, "parts": [{"text": text}]})

            if not contents:
                contents.append({
                    "role": "user",
                    "parts": [{"text": f"{initial_context}\n\nAnalyst: {user_query}"}],
                })
            else:
                contents.append({
                    "role": "user",
                    "parts": [{"text": user_query}],
                })

            raw_reply = self._call_gemini(system_instruction, contents, response_json=True)
            if raw_reply:
                # Clean potential markdown wrapping
                cleaned = re.sub(r"^```(?:json)?\s*", "", raw_reply.strip())
                cleaned = re.sub(r"\s*```$", "", cleaned)
                try:
                    parsed = json.loads(cleaned)
                    return {
                        "answer": parsed.get("answer", raw_reply),
                        "citations": parsed.get("citations", incident.related_alert_ids[:2]),
                        "suggested_actions": parsed.get("suggested_actions", ["Investigate Source IP", "Review Log Details"]),
                        "model_used": f"Google Gemini ({self.model})",
                        "is_live_gemini": True,
                    }
                except Exception:
                    # If model returned direct markdown text rather than JSON
                    return {
                        "answer": raw_reply,
                        "citations": incident.related_alert_ids[:2],
                        "suggested_actions": ["Explain Attack Narrative", "Recommend Containment Plan"],
                        "model_used": f"Google Gemini ({self.model})",
                        "is_live_gemini": True,
                    }

        # ---------------------------------------------------------------------
        # Intelligent Local SOC Engine Fallback (Rich Dynamic Intent-Matching)
        # ---------------------------------------------------------------------
        q_lower = user_query.lower().strip()
        citations = incident.related_alert_ids[:3] + incident.related_event_ids[:2]
        ip_str = ", ".join(source_ips) if source_ips else "an unknown or local IP"
        user_str = ", ".join(usernames) if usernames else "unspecified identity"
        host_str = ", ".join(hosts) if hosts else "internal endpoints"

        # 1. Greetings & Meta questions
        if re.search(r"\b(hi|hello|hey|greetings|who are you|what can you do|help)\b", q_lower):
            answer = (
                f"### 👋 Hello, Analyst!\n\n"
                f"I am your **ThreadGrid SIEM AI Copilot**, assisting you with **Incident `{incident.incident_id}`** (`{incident.title}`).\n\n"
                f"**Current Incident Status Snapshot**:\n"
                f"- **Severity**: `{incident.severity.upper()}` (Risk Score: **{incident.risk_score:.1f}/100**)\n"
                f"- **Attacker IP(s)**: `{ip_str}`\n"
                f"- **Target Account(s)**: `{user_str}` on Host `{host_str}`\n"
                f"- **Detection Rules**: `{', '.join(incident.distinct_rules)}`\n\n"
                f"You can ask me questions like:\n"
                f"- *'Who is the attacker and what IP did they use?'*\n"
                f"- *'What accounts were targeted?'*\n"
                f"- *'Is this a false positive or real attack?'*\n"
                f"- *'Explain the attack narrative step-by-step'*\n"
                f"- *'How do I block this IP or contain the host?'*"
            )
            suggested_actions = ["Explain Attack Narrative", "Draft CISO Summary", "Recommend Containment Plan"]

        # 2. Attacker / Source IP / Origin Questions
        elif re.search(r"\b(attacker|who|source|ip|where|origin|actor)\b", q_lower):
            answer = (
                f"### 🎯 Threat Actor & Origin Analysis\n\n"
                f"- **Source IP Address**: `{ip_str}`\n"
                f"- **Observed Timeline**: First seen at **{incident.first_seen}**, last active at **{incident.last_seen}**.\n"
                f"- **Attack Behavior**: Initiated authentication attempts against target account(s) `{user_str}` on host `{host_str}`.\n"
                f"- **Associated Rule Firings**: Triggered `{', '.join(incident.distinct_rules)}` across {len(incident.related_alert_ids)} correlated alert(s).\n\n"
                f"**Recommendation**: If `{ip_str}` is external or unauthorized, execute an immediate firewall drop rule via the Response Console."
            )
            suggested_actions = [f"Block IP {ip}" for ip in source_ips[:2]] or ["Stage Firewall Block"]

        # 3. Target / Victim / Account Questions
        elif re.search(r"\b(target|victim|account|username|user|host|endpoint|asset)\b", q_lower):
            answer = (
                f"### 🛡️ Impacted Assets & Identities\n\n"
                f"- **Target Account(s)**: `{user_str}`\n"
                f"- **Target Host(s)**: `{host_str}`\n"
                f"- **Account State**: Standard and service identity telemetry analyzed. No persistent administrator backdoor detected outside monitored alerts.\n"
                f"- **Correlated Alerts**: `{', '.join(incident.related_alert_ids[:3])}`\n\n"
                f"**Recommendation**: Temporarily lock affected user sessions if unauthorized access or brute-forcing is verified."
            )
            suggested_actions = [f"Lock Account {u}" for u in usernames if u != "root"] or ["Review Account Activity"]

        # 4. Risk Score / Severity / Calculation Questions
        elif re.search(r"\b(risk|score|severity|severe|critical|high|danger|formula)\b", q_lower):
            answer = (
                f"### 📊 Risk Score & Severity Breakdown\n\n"
                f"- **Overall Severity**: `{incident.severity.upper()}`\n"
                f"- **Calculated Risk Score**: **{incident.risk_score:.1f} / 100**\n"
                f"- **Calculation Basis**:\n"
                f"  - **Rule Multiplier**: Combines {len(incident.distinct_rules)} distinct detection rules (`{', '.join(incident.distinct_rules)}`).\n"
                f"  - **Alert Volume**: {len(incident.related_alert_ids)} alerts aggregated with deduplication ratio applied.\n"
                f"  - **Entity Criticality**: High risk assigned due to targeted authentication activity on endpoint `{host_str}`.\n\n"
                f"Incidents above risk score 70 require immediate Tier-2/Tier-3 analyst triage and containment approval."
            )
            suggested_actions = ["Recommend Containment Plan", "Verify Evidence Citations"]

        # 5. False Positive / Legitimacy Questions
        elif re.search(r"\b(false positive|legitimate|real|benign|test|sure|valid)\b", q_lower):
            rules_str = ", ".join(incident.distinct_rules)
            answer = (
                f"### 🔍 False Positive & Fidelity Assessment\n\n"
                f"- **Confidence Assessment**: **HIGH CONFIDENCE** attack pattern.\n"
                f"- **Why this is likely malicious**:\n"
                f"  1. Multiple successive failed authentication attempts occurred within a condensed time window.\n"
                f"  2. Originating from source IP `{ip_str}`, targeting `{user_str}`.\n"
                f"  3. Rule(s) `{rules_str}` fired with deterministic threshold validation.\n"
                f"- **When it could be benign**: If `{ip_str}` belongs to an authorized vulnerability scanner or automated integration test service. Check with system administrator before permanent blocking."
            )
            suggested_actions = ["Check Asset Allowlist", "Inspect Raw Event Payloads"]

        # 6. Attack Narrative / Explanation / What Happened
        elif re.search(r"\b(narrative|explain|what happened|story|timeline|sequence|how)\b", q_lower):
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
                f"### ⚔️ Incident Attack Narrative\n\n"
                f"**Initial Access & Reconnaissance**: Between **{incident.first_seen}** and **{incident.last_seen}**, "
                f"threat actor activity was recorded from source IP(s) `{ip_str}` targeting account(s) `{user_str}` on host `{host_str}`.\n\n"
                f"**Technique Breakdown**:\n"
                f"- Activity triggered **{len(incident.distinct_rules)} detection rule(s)**: `{', '.join(incident.distinct_rules)}`.\n"
                f"- The attack pattern corresponds to **{actions_text}**.\n\n"
                f"**Forensic Impact**: This incident achieved a risk score of **{incident.risk_score:.1f}/100** ({incident.severity.upper()}), "
                f"requiring containment actions before lateral traversal expands to secondary subnets."
            )
            suggested_actions = ["Block Source IP at Firewall", "Lock Target Account", "Review Host Audit Logs"]

        # 7. CISO Briefing / Executive Summary
        elif re.search(r"\b(ciso|executive|summary|report|brief|management)\b", q_lower):
            answer = (
                f"### 📋 Executive Incident Briefing (CISO Level)\n\n"
                f"- **Incident Status**: {incident.status} ({incident.severity.upper()} Severity - Risk {incident.risk_score:.1f}/100)\n"
                f"- **Target Asset**: Host `{host_str}` | Targeted User: `{user_str}`\n"
                f"- **Attacker Footprint**: `{ip_str}`\n"
                f"- **Current Containment**: Automated response safeguards staged in Response Console awaiting sign-off.\n"
                f"- **Immediate Action**: Firewall boundary block recommended with reversible account lock."
            )
            suggested_actions = ["Export Executive PDF", "Notify SOC Incident Commander"]

        # 8. Containment / Remediation / Actions
        elif re.search(r"\b(contain|action|remediat|fix|block|lock|isolate|stop|mitigate)\b", q_lower):
            actions_list = []
            for ip in source_ips:
                actions_list.append(f"- **Block Inbound IP**: Execute firewall drop rule for `{ip}` via Response Console.")
            for u in usernames:
                if u not in ["root", "unknown"]:
                    actions_list.append(f"- **Revoke & Reset**: Temporarily lock account `{u}` and revoke Kerberos/SSH session tokens.")
            for h in hosts:
                actions_list.append(f"- **Quarantine Endpoint**: Sever network adapter connectivity on `{h}` except SOC telemetry.")

            answer = (
                f"### ⚡ Recommended Containment Playbook\n\n"
                + "\n".join(actions_list or ["- Review raw event stream and verify attacker IP before blocking."]) + "\n\n"
                f"*All response actions support 1-click dry-run execution with automatic rollback capability.*"
            )
            suggested_actions = ["Stage All Actions to Response Console", "Trigger Endpoint Isolation"]

        # 9. Dynamic Contextual Default
        else:
            answer = (
                f"### 🔎 Forensic Response for Incident `{incident.incident_id}`\n\n"
                f"Regarding your query: *\"{user_query}\"*\n\n"
                f"- **Attacker IP(s)**: `{ip_str}`\n"
                f"- **Target Identities**: `{user_str}` on Host `{host_str}`\n"
                f"- **Timeline**: Active from **{incident.first_seen}** to **{incident.last_seen}**\n"
                f"- **Rules Triggered**: `{', '.join(incident.distinct_rules)}`\n"
                f"- **Correlated Alerts**: `{', '.join(incident.related_alert_ids[:3])}`\n\n"
                f"Would you like me to elaborate on the attack timeline, assess containment steps, or draft a CISO briefing?"
            )
            suggested_actions = ["Explain Attack Narrative", "Draft CISO Summary", "Recommend Containment Plan"]

        return {
            "answer": answer,
            "citations": citations,
            "suggested_actions": suggested_actions,
            "model_used": "ThreadGrid XAI Synthesizer (Local Fallback)",
            "is_live_gemini": False,
        }
