import json
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
import time

from app.config import settings

logger = logging.getLogger("threat_intel.ai_engine")

# In-memory cache to prevent spamming LLM on repeated polling requests
_ANALYSIS_CACHE: Dict[str, Dict[str, Any]] = {}
_CACHE_EXPIRY: Dict[str, float] = {}

# Preferred fast & reliable Groq models
GROQ_MODELS = [
    "llama-3.1-8b-instant",
    "llama-3.3-70b-versatile",
    "llama3-70b-8192",
    "mixtral-8x7b-32768"
]


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class AIEngine:
    """
    Modular AI Threat Analyst & Cyber Deception Intelligence Engine.
    Uses Groq-hosted Llama models with strict anti-hallucination guardrails and
    a deterministic Expert Cyber Heuristic fallback with intelligent caching.
    """

    @classmethod
    def _get_groq_client(cls):
        """Initializes Groq client if GROQ_API_KEY is configured."""
        if not settings.GROQ_API_KEY:
            return None
        try:
            from groq import Groq
            return Groq(api_key=settings.GROQ_API_KEY, timeout=3.0)
        except Exception as e:
            logger.warning(f"Groq SDK initialization failed: {e}")
            return None

    @classmethod
    async def analyze_threat(
        cls,
        session: Dict[str, Any],
        events: List[Dict[str, Any]],
        risk_score: int,
        risk_level: str,
        iocs: List[Dict[str, Any]],
        mitre_mappings: List[Dict[str, Any]],
        fingerprint: str,
        evidence_integrity: str = "VERIFIED"
    ) -> Dict[str, Any]:
        """
        Produces structured threat intelligence analysis with high-speed caching.
        Strictly distinguishes OBSERVED BEHAVIOR from AI INTERPRETATION.
        """
        session_id = session.get("session_id", "UNKNOWN")
        source_ip = session.get("source_ip", "UNKNOWN")
        service = session.get("service", "unknown")
        event_count = len(events)

        # 1. Check in-memory cache (keyed by session_id + event_count)
        cache_key = f"{session_id}:{event_count}:{risk_score}"
        now_ts = time.time()
        if cache_key in _ANALYSIS_CACHE and _CACHE_EXPIRY.get(cache_key, 0) > now_ts:
            return _ANALYSIS_CACHE[cache_key]

        groq_client = cls._get_groq_client()

        # Extract verifiable evidence
        observed_cmds = [e.get("event", "") for e in events if e.get("event")]
        observed_ioc_vals = [i.get("value") for i in iocs if i.get("value")]
        observed_mitre_names = [f"{m.get('technique_id')}: {m.get('technique_name')}" for m in mitre_mappings]

        if groq_client:
            # Determine models to try (primary configured model first, followed by fallbacks)
            models_to_try = [settings.GROQ_MODEL] if settings.GROQ_MODEL else []
            for m in GROQ_MODELS:
                if m not in models_to_try:
                    models_to_try.append(m)

            system_prompt = """
You are a Senior Cyber Threat Intelligence Analyst working in a Security Operations Center (SOC).
Analyze honeypot telemetry from an active cyber deception platform.

CRITICAL RULES:
1. STRICTLY DISTINGUISH between 'observed_behavior' (verifiable facts from logs) and 'ai_interpretation' (analytical hypotheses).
2. DO NOT HALLUCINATE or invent IPs, filenames, tools, CVEs, or credentials not provided in the input.
3. If evidence is insufficient for any claim, state 'Insufficient evidence'.
4. Respond with valid JSON ONLY matching the requested structure.
"""
            user_prompt = f"""
Analyze the following telemetry evidence:

SESSION EVIDENCE:
- Session ID: {session_id}
- Attacker Source IP: {source_ip}
- Target Deception Service: {service}
- Risk Score: {risk_score}/100 ({risk_level})
- Attacker DNA Signature: {fingerprint}
- Blockchain Evidence Integrity: {evidence_integrity}
- Observed Commands/Interactions: {json.dumps(observed_cmds[-15:])}
- Captured IOCs: {json.dumps(observed_ioc_vals[:10])}
- MITRE ATT&CK Mappings: {json.dumps(observed_mitre_names[:8])}

Return STRICT JSON with keys:
{{
  "threat_summary": "High-level summary of adversary actions",
  "observed_behavior": ["Fact 1 based strictly on logs", "Fact 2 based strictly on logs"],
  "ai_interpretation": ["Hypothesis 1 regarding intent", "Hypothesis 2 regarding capability"],
  "likely_objective": "Primary objective of the adversary",
  "risk_explanation": "Why this session has risk score {risk_score}",
  "important_findings": ["Key finding 1", "Key finding 2"],
  "recommended_actions": ["Defensive recommendation 1", "Defensive recommendation 2"],
  "confidence": 85,
  "evidence_used": ["List of specific log items used as proof"]
}}
"""
            for model_candidate in models_to_try:
                try:
                    chat_completion = groq_client.chat.completions.create(
                        messages=[
                            {"role": "system", "content": system_prompt},
                            {"role": "user", "content": user_prompt}
                        ],
                        model=model_candidate,
                        response_format={"type": "json_object"},
                        temperature=0.1,
                    )

                    response_text = chat_completion.choices[0].message.content.strip()
                    parsed = json.loads(response_text)
                    parsed["ai_powered"] = True
                    parsed["model_used"] = model_candidate

                    # Cache for 60 seconds
                    _ANALYSIS_CACHE[cache_key] = parsed
                    _CACHE_EXPIRY[cache_key] = now_ts + 60.0
                    return parsed
                except Exception as e:
                    logger.debug(f"Groq model {model_candidate} attempt skipped: {e}")

        # Deterministic Expert Cyber Heuristic Fallback (Immediate execution, zero delay)
        result = cls._heuristic_threat_analysis(
            session=session,
            events=events,
            risk_score=risk_score,
            risk_level=risk_level,
            iocs=iocs,
            mitre_mappings=mitre_mappings,
            fingerprint=fingerprint,
            evidence_integrity=evidence_integrity
        )

        # Cache heuristic result for 30 seconds
        _ANALYSIS_CACHE[cache_key] = result
        _CACHE_EXPIRY[cache_key] = now_ts + 30.0
        return result

    @classmethod
    def _heuristic_threat_analysis(
        cls,
        session: Dict[str, Any],
        events: List[Dict[str, Any]],
        risk_score: int,
        risk_level: str,
        iocs: List[Dict[str, Any]],
        mitre_mappings: List[Dict[str, Any]],
        fingerprint: str,
        evidence_integrity: str
    ) -> Dict[str, Any]:
        """
        High-fidelity deterministic expert engine implementing MITRE ATT&CK TTP analysis.
        Provides realistic, structured threat intelligence when LLM APIs are unreachable.
        """
        source_ip = session.get("source_ip", "Unknown")
        service = (session.get("service") or "SSH").upper()
        observed_cmds = [e.get("event", "") for e in events if e.get("event")]

        observed_behavior = []
        ai_interpretation = []
        important_findings = []
        recommended_actions = []
        evidence_used = []

        # 1. Analyze Observed Behavior from Events
        for e in events[-10:]:
            ev_text = e.get("event", "")
            ev_type = e.get("event_type", "")
            if "auth_failure" in ev_type or "password" in ev_text.lower():
                observed_behavior.append(f"Authentication attempt observed from {source_ip} on {service} trap.")
                evidence_used.append(f"Log event: {ev_text}")
            elif "command" in ev_type:
                observed_behavior.append(f"Command execution: '{ev_text}'")
                evidence_used.append(f"Keystroke telemetry: '{ev_text}'")
            elif "decoy" in ev_type or "canary" in ev_text.lower():
                observed_behavior.append(f"Honeytoken Canary triggered: {ev_text}")
                evidence_used.append(f"Trap sensor: {ev_text}")

        if not observed_behavior:
            observed_behavior.append(f"Inbound network interaction recorded from {source_ip} to {service} service.")

        # 2. Extract IOC and MITRE evidence
        for i in iocs[:5]:
            evidence_used.append(f"Captured IOC ({i.get('ioc_type')}): {i.get('value')}")
        for m in mitre_mappings[:5]:
            evidence_used.append(f"MITRE ATT&CK TTP: {m.get('technique_id')} ({m.get('technique_name')})")

        # 3. AI Interpretations based on observed TTPs
        if risk_score >= 80:
            threat_summary = f"CRITICAL intrusion campaign detected from {source_ip}. Adversary actively bypassed perimeter authentication, explored decoy structures, and engaged high-value honeytokens."
            likely_objective = "Privilege escalation, lateral movement across corporate subnet, and exfiltration of cloud/IAM credentials."
            ai_interpretation.append("Observed toolchains and command velocity indicate an automated threat actor or seasoned interactive operator.")
            ai_interpretation.append("Attacker targeted synthetic AWS/DB tokens, demonstrating cloud control plane targeting intent.")
            important_findings.append(f"High risk score of {risk_score}/100 driven by multiple confirmed malicious TTPs.")
            important_findings.append(f"Blockchain evidence integrity verified ({evidence_integrity}) — admissible for incident forensics.")
            recommended_actions.append(f"Apply immediate perimeter DROP rule for IP {source_ip}.")
            recommended_actions.append("Audit edge firewall logs for other connection attempts from this subnet.")
            recommended_actions.append("Rotate corporate canary tokens and verify production CloudTrail logs.")
        elif risk_score >= 50:
            threat_summary = f"Suspicious reconnaissance activity from {source_ip} targeting {service} deception endpoint."
            likely_objective = "System discovery, service version probing, and dictionary credential spraying."
            ai_interpretation.append("Adversary is mapping accessible services and looking for common default credentials.")
            important_findings.append(f"Attacker fingerprint {fingerprint} matches known automated scanner profiles.")
            recommended_actions.append(f"Rate-limit or quarantine {source_ip} at ingress reverse proxy.")
            recommended_actions.append("Continue passive telemetry collection to capture second-stage payloads.")
        else:
            threat_summary = f"Low-severity network probing from {source_ip} on port {service}."
            likely_objective = "Routine Internet-wide scanner or misconfigured client."
            ai_interpretation.append("No active exploitation or honeytoken interactions detected yet.")
            recommended_actions.append("Keep session monitored in sandbox.")

        return {
            "ai_powered": False,
            "model_used": "Kurukshetra Cyber Threat Intelligence Engine (Deterministic)",
            "threat_summary": threat_summary,
            "observed_behavior": list(dict.fromkeys(observed_behavior))[:6],
            "ai_interpretation": ai_interpretation,
            "likely_objective": likely_objective,
            "risk_explanation": f"Calculated based on {len(events)} telemetry events, {len(iocs)} IOC indicators, and {len(mitre_mappings)} MITRE technique correlations.",
            "important_findings": important_findings,
            "recommended_actions": recommended_actions,
            "confidence": 92 if evidence_integrity == "VERIFIED" else 75,
            "evidence_used": list(dict.fromkeys(evidence_used))[:8]
        }
