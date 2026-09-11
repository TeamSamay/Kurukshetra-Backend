import json
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

from app.config import settings

logger = logging.getLogger("threat_intel.ai_engine")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class AIEngine:
    """
    Modular AI Threat Analyst & Cyber Deception Intelligence Engine.
    Uses Groq-hosted Llama models with strict anti-hallucination guardrails and
    a deterministic Expert Cyber Heuristic fallback.
    """

    @classmethod
    def _get_groq_client(cls):
        """Initializes Groq client if GROQ_API_KEY is configured."""
        if not settings.GROQ_API_KEY:
            return None
        try:
            from groq import Groq
            return Groq(api_key=settings.GROQ_API_KEY)
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
        Produces structured threat intelligence analysis.
        Strictly distinguishes OBSERVED BEHAVIOR from AI INTERPRETATION.
        """
        groq_client = cls._get_groq_client()

        # Extract verifiable evidence
        observed_cmds = [e.get("event", "") for e in events if e.get("event")]
        observed_ioc_vals = [i.get("value") for i in iocs if i.get("value")]
        observed_mitre_names = [f"{m.get('technique_id')}: {m.get('technique_name')}" for m in mitre_mappings]
        session_id = session.get("session_id", "UNKNOWN")
        source_ip = session.get("source_ip", "UNKNOWN")
        service = session.get("service", "unknown")

        if groq_client:
            try:
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
                chat_completion = groq_client.chat.completions.create(
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt}
                    ],
                    model=settings.GROQ_MODEL,
                    response_format={"type": "json_object"},
                    temperature=0.1,
                )

                response_text = chat_completion.choices[0].message.content.strip()
                parsed = json.loads(response_text)
                parsed["ai_powered"] = True
                parsed["model_used"] = settings.GROQ_MODEL
                return parsed
            except Exception as e:
                logger.warning(f"Groq LLM call failed or timed out, activating Expert Cyber Heuristic Engine: {e}")

        # Deterministic Expert Cyber Heuristic Fallback
        return cls._heuristic_threat_analysis(
            session=session,
            events=events,
            risk_score=risk_score,
            risk_level=risk_level,
            iocs=iocs,
            mitre_mappings=mitre_mappings,
            fingerprint=fingerprint,
            evidence_integrity=evidence_integrity
        )

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
        evidence_integrity: str = "VERIFIED"
    ) -> Dict[str, Any]:
        """High-precision deterministic cybersecurity reasoning engine."""
        src_ip = session.get("source_ip", "Unknown IP")
        service = (session.get("service") or "unknown").upper()
        tactics = [m.get("tactic") for m in mitre_mappings if m.get("tactic")]
        raw_cmds = [e.get("event", "") for e in events]
        all_text = " ".join(raw_cmds).lower()

        has_recon = any("Discovery" in t for t in tactics) or "whoami" in all_text or "uname" in all_text
        has_decoy = any("DECOY" in f for f in session.get("risk_breakdown", [])) or "fake" in all_text or ".env" in all_text
        has_privesc = any("Privilege Escalation" in t for t in tactics) or "sudo" in all_text
        has_c2 = any("Command and Control" in t for t in tactics) or "wget" in all_text or "curl" in all_text

        # Observed behaviors (verifiable)
        observed = []
        if events:
            observed.append(f"Recorded {len(events)} telemetry interactions targeting the {service} deception interface.")
        if has_recon:
            observed.append("Executed system discovery and environment discovery commands.")
        if has_decoy:
            observed.append("Attempted access to deployed decoy tokens and configuration assets.")
        if has_c2:
            observed.append("Attempted external ingress payload retrieval via network tooling.")
        if has_privesc:
            observed.append("Attempted privileged binary execution and elevation checks.")

        if not observed:
            observed.append("Initial connection handshake and perimeter probe recorded.")

        # AI Interpretation (Analytical hypotheses)
        interpretations = []
        if has_privesc:
            interpretations.append("Adversary demonstrates intent to achieve administrative execution on host.")
        if has_decoy:
            interpretations.append("Targeted pursuit of high-value decoy credentials indicates targeted post-exploitation.")
        if has_recon and not has_privesc:
            interpretations.append("Activity is consistent with automated or semi-automated initial environment reconnaissance.")
        if not interpretations:
            interpretations.append("Behavior is consistent with perimeter port scanning and credential exploration.")

        # Likely objective
        if has_privesc:
            likely_obj = "Host takeover, credential dumping, and administrative persistence."
        elif has_c2:
            likely_obj = "Stage external malicious payload delivery and establish secondary persistence."
        elif has_decoy:
            likely_obj = "Credential harvesting and lateral movement preparation using discovered secrets."
        elif has_recon:
            likely_obj = "Host environment reconnaissance and identifying vulnerable configuration surfaces."
        else:
            likely_obj = "Opportunistic service reconnaissance and automated authentication probing."

        # Summary
        summary = (
            f"Adversary from {src_ip} engaged the {service} deception honeypot across {len(events)} events. "
            f"Observed tactics align with {', '.join(set(tactics)) if tactics else 'initial reconnaissance'}."
        )

        # Risk explanation
        risk_exp = (
            f"Session evaluated as {risk_level} (Score: {risk_score}/100). "
            f"Key risk drivers: {'; '.join(session.get('risk_breakdown', ['observed honeypot interactions']))}."
        )

        # Findings
        findings = [
            f"Source IP {src_ip} interacted with {service} honeypot decoy.",
            f"Attacker DNA Signature: {fingerprint}",
            f"Cryptographic Evidence Status: {evidence_integrity}"
        ]

        # Recommended defensive actions
        recs = [
            f"Review firewall rules at edge gateway for source IP {src_ip}.",
            f"Verify production {service} servers have hardened authentication and no public administrative exposure.",
            "Retain cryptographic blockchain evidence for incident reporting and compliance verification.",
            "Ensure sensitive files (e.g. .env, private keys) are inaccessible on public routes."
        ]

        return {
            "threat_summary": summary,
            "observed_behavior": observed,
            "ai_interpretation": interpretations,
            "likely_objective": likely_obj,
            "risk_explanation": risk_exp,
            "important_findings": findings,
            "recommended_actions": recs,
            "confidence": 90,
            "evidence_used": raw_cmds[-5:] if raw_cmds else [f"Connection to {service}"],
            "ai_powered": False,
            "model_used": "Kurukshetra Cyber Threat Intelligence Engine"
        }

    @classmethod
    async def explain_event(cls, event_dict: Dict[str, Any]) -> Dict[str, Any]:
        """
        Explains a single telemetry event with strict separation of
        Observed Behavior vs AI Interpretation.
        """
        raw_cmd = str(event_dict.get("event", ""))
        event_type = str(event_dict.get("event_type", ""))
        service = str(event_dict.get("service", ""))
        src_ip = str(event_dict.get("source_ip", ""))

        groq_client = cls._get_groq_client()
        if groq_client:
            try:
                prompt = f"""
Explain this cyber event captured by an active deception honeypot:
Event Type: {event_type}
Service: {service}
Payload/Command: {raw_cmd}
Source IP: {src_ip}

Return STRICT JSON with keys:
{{
  "observed_behavior": "Strict factual statement of what the session executed",
  "ai_interpretation": "Analytical explanation of what the adversary is likely attempting",
  "threat_context": "MITRE technique or attack stage context",
  "defensive_note": "Human-reviewed defensive takeaway"
}}
"""
                chat = groq_client.chat.completions.create(
                    messages=[
                        {"role": "system", "content": "You are a cyber threat analyst. Distinguish observed behavior from interpretation. Never invent facts."},
                        {"role": "user", "content": prompt}
                    ],
                    model=settings.GROQ_MODEL,
                    response_format={"type": "json_object"},
                    temperature=0.1
                )
                res = json.loads(chat.choices[0].message.content.strip())
                res["ai_powered"] = True
                return res
            except Exception as e:
                logger.warning(f"Groq explain_event fallback: {e}")

        # Deterministic explanation heuristics
        cmd_lower = raw_cmd.lower()
        if ".env" in cmd_lower:
            observed = f"The session requested resource '{raw_cmd}' on the {service} service."
            interp = "This behavior is consistent with an attempt to discover exposed application configuration and environment secrets."
            context = "T1552.001 - Unsecured Credentials in Configuration Files"
            defensive = "Ensure .env and sensitive configuration files are outside the web root and blocked by web server configuration."
        elif "cat /etc/passwd" in cmd_lower or "/etc/shadow" in cmd_lower:
            observed = f"The session executed command '{raw_cmd}' attempting to read system account definitions."
            interp = "Adversary is performing local account discovery to identify valid usernames and privileged accounts."
            context = "T1087.001 - Account Discovery: Local Account"
            defensive = "Verify permissions on sensitive account files and audit privileged user memberships."
        elif "whoami" in cmd_lower or "uname" in cmd_lower or "id" in cmd_lower:
            observed = f"The session executed system discovery command '{raw_cmd}'."
            interp = "Adversary is determining active privilege level and operating system details."
            context = "T1033 - System Owner/User Discovery"
            defensive = "Maintain principle of least privilege and restrict interactive shell access for service accounts."
        elif "wget" in cmd_lower or "curl" in cmd_lower:
            observed = f"The session attempted network retrieval command '{raw_cmd}'."
            interp = "Adversary is attempting to download external tooling or secondary stage payload."
            context = "T1105 - Ingress Tool Transfer"
            defensive = "Restrict outbound egress network access from application and database servers."
        elif "sudo" in cmd_lower:
            observed = f"The session executed privilege elevation command '{raw_cmd}'."
            interp = "Adversary is attempting to gain root/administrative privileges."
            context = "T1548.003 - Abuse Elevation Control Mechanism: Sudo"
            defensive = "Audit sudoers configuration and require strict multi-factor authentication for administrative commands."
        else:
            observed = f"The session initiated interaction '{raw_cmd}' on {service}."
            interp = "Adversary is interacting with perimeter services to probe for interactive execution."
            context = "Discovery & Reconnaissance Stage"
            defensive = "Monitor perimeter logs and rate-limit repeated anomalous requests."

        return {
            "observed_behavior": observed,
            "ai_interpretation": interp,
            "threat_context": context,
            "defensive_note": defensive,
            "ai_powered": False
        }

    @classmethod
    async def analyze_vulnerability_guard(
        cls,
        recent_events: List[Dict[str, Any]],
        iocs: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Defensive Exposure Guard:
        Analyzes honeypot telemetry observations to determine what attackers are hunting for,
        and provides human-reviewed defensive remediation recommendations for real production servers.
        """
        all_cmds = [e.get("event", "") for e in recent_events]
        all_text = " ".join(all_cmds).lower()

        exposures = []

        # 1. Config / .env Hunter
        if ".env" in all_text or "config" in all_text or "settings.json" in all_text:
            exposures.append({
                "target_interest": "Exposed Environment & Config Files",
                "observed_pattern": "GET /.env, /config.php, /settings.json",
                "potential_exposure": "Adversaries actively scanning perimeter for exposed environment credentials and secret keys.",
                "risk_severity": "HIGH",
                "defensive_recommendation": "Configure web servers (Nginx/Apache) to return 404/403 for hidden files (.env, .git) and place secrets in environment variables rather than web-accessible directories.",
                "remediation_guide": "location ~ /\\.(env|git|htaccess) { deny all; return 404; }"
            })

        # 2. Administrative Portal Discovery
        if "/admin" in all_text or "/phpmyadmin" in all_text or "/wp-admin" in all_text:
            exposures.append({
                "target_interest": "Administrative Management Portals",
                "observed_pattern": "GET /admin, /phpmyadmin, /wp-login.php",
                "potential_exposure": "Automated scanners hunting for unauthenticated or default-credential admin dashboards.",
                "risk_severity": "MEDIUM",
                "defensive_recommendation": "Place admin endpoints behind a VPN, IP allowlist, or SSO gateway with mandatory Multi-Factor Authentication.",
                "remediation_guide": "Allow only trusted corporate subnet IPs on /admin routes."
            })

        # 3. SSH Credential Probing
        if any("ssh" in (e.get("service") or "").lower() for e in recent_events):
            exposures.append({
                "target_interest": "SSH Perimeter Authentication",
                "observed_pattern": "Automated SSH brute-force & credential stuffing",
                "potential_exposure": "Attackers attempting dictionary attacks on standard SSH Port 22.",
                "risk_severity": "HIGH",
                "defensive_recommendation": "Disable root password logins, enforce Ed25519 SSH keys only, change standard port 22, and deploy Fail2Ban.",
                "remediation_guide": "echo 'PermitRootLogin prohibit-password' >> /etc/ssh/sshd_config && systemctl reload sshd"
            })

        # 4. Ingress Tool Transfer / Binary Staging
        if "wget" in all_text or "curl" in all_text or "chmod +x" in all_text:
            exposures.append({
                "target_interest": "Remote Code Execution & Binary Staging",
                "observed_pattern": "wget http://... -O /tmp/x.sh && chmod +x",
                "potential_exposure": "Adversaries attempting to drop external binaries into /tmp or world-writable directories.",
                "risk_severity": "CRITICAL",
                "defensive_recommendation": "Mount /tmp and /var/tmp with 'noexec,nosuid,nodev' options in /etc/fstab to prevent direct execution of staged scripts.",
                "remediation_guide": "mount -o remount,noexec /tmp"
            })

        # Fallback general hygiene item if no events yet
        if not exposures:
            exposures.append({
                "target_interest": "Perimeter Port Scanning & Reconnaissance",
                "observed_pattern": "SYN scans and service version identification",
                "potential_exposure": "Broad reconnaissance identifying exposed ports.",
                "risk_severity": "LOW",
                "defensive_recommendation": "Maintain minimal public attack surface; close all non-essential perimeter ports.",
                "remediation_guide": "ufw default deny incoming && ufw default allow outgoing"
            })

        return exposures
