import re
import hashlib
import json
import logging
from typing import List, Dict, Any, Tuple
from app.config import settings

logger = logging.getLogger("threat_intel.engines")

# =========================================================================
# 1. IOC ENGINE (Deterministic / Regex & Lexical)
# =========================================================================
class IOCEngine:
    """Extracts Indicators of Compromise (IPs, domains, URLs, hashes, files, tools)."""

    IPV4_REGEX = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    URL_REGEX = re.compile(r'(https?://[^\s\'"<>]+|ftp://[^\s\'"<>]+|tftp://[^\s\'"<>]+)', re.IGNORECASE)
    DOMAIN_REGEX = re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b')
    MD5_REGEX = re.compile(r'\b[a-fA-F0-9]{32}\b')
    SHA1_REGEX = re.compile(r'\b[a-fA-F0-9]{40}\b')
    SHA256_REGEX = re.compile(r'\b[a-fA-F0-9]{64}\b')

    SUSPICIOUS_FILES = [
        "/etc/shadow", "/etc/passwd", "/etc/sudoers", "/root/.ssh",
        "id_rsa", ".env", "config.php", "passwords.txt", "canary",
        "database.yml", "authorized_keys", "/dev/tcp"
    ]

    OFFENSIVE_TOOLS = [
        "nmap", "hydra", "sqlmap", "nikto", "masscan", "linpeas", "winpeas",
        "mimikatz", "netcat", "nc", "socat", "chisel", "metasploit",
        "wget", "curl", "meterpreter"
    ]

    @classmethod
    def extract_iocs(cls, event_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        raw_text = f"{event_data.get('event', '')} {json.dumps(event_data.get('metadata', {}))}"
        source_ip = event_data.get("source_ip")
        session_id = event_data.get("session_id")
        iocs = []
        seen = set()

        def add_ioc(ioc_type: str, val: str, threat_cat: str = "SUSPICIOUS", confidence: str = "HIGH"):
            key = (ioc_type, val)
            if key not in seen and val:
                seen.add(key)
                iocs.append({
                    "ioc_type": ioc_type,
                    "value": val,
                    "threat_category": threat_cat,
                    "confidence": confidence,
                    "session_id": session_id,
                    "source_ip": source_ip
                })

        # 1. Source IP
        if source_ip and source_ip not in ["127.0.0.1", "localhost", "0.0.0.0"]:
            add_ioc("ip", source_ip, threat_cat="ATTACKER_SOURCE", confidence="VERY_HIGH")

        # 2. URLs in payload
        for url in cls.URL_REGEX.findall(raw_text):
            add_ioc("url", url, threat_cat="PAYLOAD_DELIVERY")

        # 3. Hashes
        for h in cls.SHA256_REGEX.findall(raw_text):
            add_ioc("hash", h.lower(), threat_cat="MALWARE_PAYLOAD")
        for h in cls.MD5_REGEX.findall(raw_text):
            add_ioc("hash", h.lower(), threat_cat="MALWARE_PAYLOAD")

        # 4. Embedded IPs
        for ip in cls.IPV4_REGEX.findall(raw_text):
            if ip not in ["127.0.0.1", "0.0.0.0", "255.255.255.255", source_ip, event_data.get("target_ip")]:
                add_ioc("ip", ip, threat_cat="C2_OR_DOWNLOAD")

        # 5. Suspicious Decoy / System Files
        raw_lower = raw_text.lower()
        for f in cls.SUSPICIOUS_FILES:
            if f in raw_lower:
                add_ioc("file", f, threat_cat="DECOY_TARGET")

        # 6. Offensive Tools
        for t in cls.OFFENSIVE_TOOLS:
            # Word boundary check for tools
            if re.search(r'\b' + re.escape(t) + r'\b', raw_lower):
                add_ioc("tool", t, threat_cat="OFFENSIVE_TOOL")

        return iocs


# =========================================================================
# 2. RISK ENGINE (Deterministic & Explainable)
# =========================================================================
class RiskEngine:
    """Calculates deterministic cumulative risk scores (0-100) with explainable factor breakdown."""

    RECON_PATTERNS = ["whoami", "uname", "id", "hostname", "netstat", "ps aux", "ip a", "ifconfig", "w", "last", "uptime"]
    DECOY_PATTERNS = ["canary", "honey", "fake", "decoy", "passwords.txt", ".env", "id_rsa", "secret", "shadow", "credentials"]
    FILE_ACTIVITY_PATTERNS = ["wget", "curl", "chmod +x", "chmod 777", "tar -x", "unzip", "touch", "mv ", "cp "]
    PRIVESC_PATTERNS = ["sudo", "su root", "pkexec", "setuid", "/etc/sudoers", "visudo", "chown"]
    PERSISTENCE_PATTERNS = ["crontab", "systemctl enable", ".bashrc", "/etc/cron", "init.d"]
    REVERSE_SHELL_PATTERNS = ["nc -e", "/bin/sh", "/bin/bash", "/dev/tcp", "mkfifo", "python -c import socket", "perl -e"]

    @classmethod
    def calculate_event_risk(cls, event: Dict[str, Any], session_events: List[Dict[str, Any]] = None) -> Tuple[int, List[str]]:
        """Calculates risk delta and factors for a specific event."""
        delta = 0
        factors = []
        raw_cmd = (event.get("event") or "").lower()
        event_type = (event.get("event_type") or "").lower()

        # Login attempts
        if event_type == "login" or "login" in raw_cmd:
            delta += 10
            factors.append("Authentication attempt (+10)")

        # Reconnaissance
        if any(p in raw_cmd for p in cls.RECON_PATTERNS) or event_type == "recon":
            delta += 20
            factors.append("System reconnaissance behavior detected (+20)")

        # Decoy / Canary resource access
        if any(p in raw_cmd for p in cls.DECOY_PATTERNS) or event.get("metadata", {}).get("is_decoy"):
            delta += 25
            factors.append("Decoy / Honeytoken resource access (+25)")

        # Suspicious file activity / ingress
        if any(p in raw_cmd for p in cls.FILE_ACTIVITY_PATTERNS):
            delta += 20
            factors.append("Suspicious file / ingress tool activity (+20)")

        # Privilege escalation
        if any(p in raw_cmd for p in cls.PRIVESC_PATTERNS):
            delta += 25
            factors.append("Privilege escalation attempt (+25)")

        # Persistence
        if any(p in raw_cmd for p in cls.PERSISTENCE_PATTERNS):
            delta += 20
            factors.append("Persistence mechanism tampering (+20)")

        # Reverse Shell / Lateral
        if any(p in raw_cmd for p in cls.REVERSE_SHELL_PATTERNS):
            delta += 30
            factors.append("Reverse shell / interactive payload execution (+30)")

        # Default fallback for unclassified command
        if delta == 0 and event_type == "command":
            delta += 5
            factors.append("Unclassified shell command execution (+5)")

        return delta, factors

    @classmethod
    def compute_session_risk(cls, events: List[Dict[str, Any]]) -> Tuple[int, str, List[str]]:
        """Recomputes aggregate session risk, level, and unique breakdown."""
        score = 0
        breakdown = []
        seen_factors = set()

        login_count = 0
        behaviors_seen = set()

        for ev in events:
            delta, factors = cls.calculate_event_risk(ev)
            score += delta

            raw_cmd = (ev.get("event") or "").lower()
            ev_type = (ev.get("event_type") or "").lower()

            if ev_type == "login" or "login" in raw_cmd:
                login_count += 1
                behaviors_seen.add("LOGIN")
            if any(p in raw_cmd for p in cls.RECON_PATTERNS):
                behaviors_seen.add("RECON")
            if any(p in raw_cmd for p in cls.DECOY_PATTERNS):
                behaviors_seen.add("DECOY")
            if any(p in raw_cmd for p in cls.FILE_ACTIVITY_PATTERNS):
                behaviors_seen.add("FILE_ACTIVITY")
            if any(p in raw_cmd for p in cls.PRIVESC_PATTERNS):
                behaviors_seen.add("PRIVESC")

            for f in factors:
                if f not in seen_factors:
                    seen_factors.add(f)
                    breakdown.append(f)

        # Repeated login attempts bonus
        if login_count >= 3:
            score += 15
            f_brute = "Repeated / Brute-force authentication attempts (+15)"
            if f_brute not in seen_factors:
                breakdown.append(f_brute)

        # Multiple distinct behaviors bonus
        if len(behaviors_seen) >= 3:
            score += 10
            f_multi = "Multi-stage attack pattern observed (+10)"
            if f_multi not in seen_factors:
                breakdown.append(f_multi)

        # Cap between 0 and 100
        score = max(0, min(100, score))

        # Level mapping
        if score <= 30:
            level = "LOW"
        elif score <= 60:
            level = "MEDIUM"
        elif score <= 80:
            level = "HIGH"
        else:
            level = "CRITICAL"

        return score, level, breakdown


# =========================================================================
# 3. ATTACKER FINGERPRINT ENGINE (Behavioral DNA)
# =========================================================================
class FingerprintEngine:
    """Computes behavioral DNA signatures based on observed actions and service, not merely IP."""

    @classmethod
    def generate_fingerprint(cls, service: str, events: List[Dict[str, Any]]) -> Tuple[str, List[str]]:
        service_tag = (service or "SRV").upper()
        tactics = []

        all_text = " ".join([f"{e.get('event', '')} {e.get('event_type', '')}" for e in events]).lower()

        if any(p in all_text for p in ["login", "password", "auth", "admin"]):
            tactics.append("CRED")
        if any(p in all_text for p in RiskEngine.RECON_PATTERNS):
            tactics.append("RECON")
        if any(p in all_text for p in RiskEngine.DECOY_PATTERNS):
            tactics.append("DECOY")
        if any(p in all_text for p in RiskEngine.FILE_ACTIVITY_PATTERNS):
            tactics.append("DOWNLOAD")
        if any(p in all_text for p in RiskEngine.PRIVESC_PATTERNS):
            tactics.append("PRIVESC")
        if any(p in all_text for p in RiskEngine.REVERSE_SHELL_PATTERNS):
            tactics.append("EXPLOIT")

        if not tactics:
            tactics.append("PROBE")

        # Construct DNA signature string, e.g. SSH-RECON-CRED-01
        tactic_str = "-".join(tactics[:3])
        # Compute deterministic sequence version
        seq_hash = hashlib.md5(tactic_str.encode()).hexdigest()[:2].upper()
        fingerprint = f"{service_tag}-{tactic_str}-{seq_hash}"

        return fingerprint, tactics


# =========================================================================
# 4. MITRE ATT&CK MAPPING ENGINE (Controlled & Traceable)
# =========================================================================
class MitreEngine:
    """Maps observed commands and telemetry strictly to verified MITRE ATT&CK techniques."""

    MAPPINGS = [
        {
            "id": "T1033",
            "name": "System Owner/User Discovery",
            "tactic": "Discovery",
            "keywords": ["whoami", "id", "who", "users", "lastlog"]
        },
        {
            "id": "T1082",
            "name": "System Information Discovery",
            "tactic": "Discovery",
            "keywords": ["uname -a", "uname", "/proc/version", "/etc/os-release", "hostname", "sysinfo", "ver"]
        },
        {
            "id": "T1087.001",
            "name": "Account Discovery: Local Account",
            "tactic": "Discovery",
            "keywords": ["/etc/passwd", "/etc/shadow", "getent passwd", "cut -d: -f1 /etc/passwd", "net user"]
        },
        {
            "id": "T1552.001",
            "name": "Unsecured Credentials: Credentials In Files",
            "tactic": "Credential Access",
            "keywords": [".env", "id_rsa", "passwords.txt", "credentials", "wp-config.php", "settings.json"]
        },
        {
            "id": "T1110.001",
            "name": "Brute Force: Password Guessing",
            "tactic": "Credential Access",
            "keywords": ["failed login", "password attempt", "brute", "hydra", "invalid user"]
        },
        {
            "id": "T1105",
            "name": "Ingress Tool Transfer",
            "tactic": "Command and Control",
            "keywords": ["wget", "curl", "tftp", "ftp -s", "certutil", "invoke-webrequest"]
        },
        {
            "id": "T1222.002",
            "name": "File and Directory Permissions Modification: Linux Permissions",
            "tactic": "Defense Evasion",
            "keywords": ["chmod +x", "chmod 777", "chmod 755", "chown", "attrib"]
        },
        {
            "id": "T1053.003",
            "name": "Scheduled Task/Job: Cron",
            "tactic": "Persistence",
            "keywords": ["crontab", "/etc/cron", "cron.d", "at now"]
        },
        {
            "id": "T1548.003",
            "name": "Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
            "tactic": "Privilege Escalation",
            "keywords": ["sudo -l", "sudo su", "pkexec", "su root", "sudo /bin/"]
        },
        {
            "id": "T1059.004",
            "name": "Command and Scripting Interpreter: Unix Shell",
            "tactic": "Execution",
            "keywords": ["/bin/sh", "/bin/bash", "bash -i", "/dev/tcp", "python -c", "nc -e"]
        },
        {
            "id": "T1046",
            "name": "Network Service Discovery",
            "tactic": "Discovery",
            "keywords": ["nmap", "netstat", "ss -tulpn", "arp -a", "ip route", "route print"]
        },
        {
            "id": "T1083",
            "name": "File and Directory Discovery",
            "tactic": "Discovery",
            "keywords": ["ls -la", "ls", "dir", "find /", "find .", "tree"]
        },
        {
            "id": "T1057",
            "name": "Process Discovery",
            "tactic": "Discovery",
            "keywords": ["ps aux", "ps -ef", "tasklist", "top -b", "pstree"]
        }
    ]

    @classmethod
    def map_event(cls, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        raw_cmd = (event.get("event") or "").lower()
        matched = []

        for m in cls.MAPPINGS:
            for kw in m["keywords"]:
                if kw in raw_cmd:
                    matched.append({
                        "technique_id": m["id"],
                        "technique_name": m["name"],
                        "tactic": m["tactic"],
                        "matched_command": event.get("event"),
                        "evidence": f"Matched pattern '{kw}' in telemetry payload",
                        "timestamp": event.get("timestamp")
                    })
                    break  # match once per technique

        return matched


# =========================================================================
# 5. AI THREAT ANALYSIS ENGINE (Structured, Zero-Failure)
# =========================================================================
class AIEngine:
    """Structured Threat Intelligence analysis with fallback expert threat modeling."""

    @classmethod
    async def analyze_threat(
        cls,
        session: Dict[str, Any],
        events: List[Dict[str, Any]],
        risk_score: int,
        risk_level: str,
        iocs: List[Dict[str, Any]],
        mitre_mappings: List[Dict[str, Any]],
        fingerprint: str
    ) -> Dict[str, Any]:
        """Produces structured AI threat report. Uses LLM if available, otherwise runs expert heuristic."""

        # Attempt Gemini API if key is present
        if settings.GEMINI_API_KEY:
            try:
                from google import genai
                client = genai.Client(api_key=settings.GEMINI_API_KEY)
                prompt = f"""
                You are a Senior Cyber Threat Intelligence Analyst. Analyze this cyber attack on a honeypot decoy system.
                Respond with STRICT JSON containing only keys: "summary", "likely_objective", "risk_explanation", "observed_behavior_explanation", "recommended_defensive_action".

                SESSION DATA:
                Session ID: {session.get('session_id')}
                Attacker IP: {session.get('source_ip')}
                Target: {session.get('target_ip')} (Service: {session.get('service')})
                Risk: {risk_score} ({risk_level})
                Attacker DNA Fingerprint: {fingerprint}
                Events: {[e.get('event') for e in events[-10:]]}
                IOCs: {[i.get('value') for i in iocs[:5]]}
                MITRE Techniques: {[m.get('technique_id') + ': ' + m.get('technique_name') for m in mitre_mappings[:5]]}
                """
                response = client.models.generate_content(
                    model='gemini-2.5-flash',
                    contents=prompt
                )
                txt = response.text.strip()
                if "```json" in txt:
                    txt = txt.split("```json")[1].split("```")[0].strip()
                elif "```" in txt:
                    txt = txt.split("```")[1].split("```")[0].strip()
                parsed = json.loads(txt)
                return parsed
            except Exception as e:
                logger.warning(f"Gemini AI API call failed or timed out, falling back to Expert Engine: {e}")

        # Built-in Cyber Threat Intelligence Expert Heuristic Engine
        tactics = [m.get("tactic") for m in mitre_mappings]
        services = session.get("service", "unknown")
        src_ip = session.get("source_ip", "unknown")
        cmd_count = len(events)
        
        has_recon = any("Discovery" in t for t in tactics) or "RECON" in fingerprint
        has_decoy = any("DECOY" in f for f in session.get("risk_breakdown", []))
        has_privesc = any("Privilege Escalation" in t for t in tactics) or "PRIVESC" in fingerprint
        has_payload = any("Command and Control" in t for t in tactics) or "DOWNLOAD" in fingerprint

        # 1. Summary
        summary = (
            f"Adversary from {src_ip} initiated a targeted interaction with the {services.upper()} decoy service. "
            f"Activity spans {cmd_count} telemetry events displaying {', '.join(set(tactics)) if tactics else 'initial probing'} tactics."
        )

        # 2. Likely Objective
        if has_privesc:
            likely_obj = "Privilege escalation and host takeover to gain root-level administrative persistence."
        elif has_payload:
            likely_obj = "Stage external malicious payload delivery and establish command-and-control access."
        elif has_decoy:
            likely_obj = "Credential harvesting and accessing high-value decoy assets for lateral pivot."
        elif has_recon:
            likely_obj = "Host and environment reconnaissance to discover installed services, users, and vulnerable binaries."
        else:
            likely_obj = "Automated opportunistic scanning and credential brute-forcing against perimeter services."

        # 3. Risk Explanation
        risk_exp = (
            f"The session was classified as {risk_level} (Score: {risk_score}/100) due to "
            f"{'; '.join(session.get('risk_breakdown', ['observed malicious interactions']))}."
        )

        # 4. Observed Behavior Explanation
        behavior_steps = []
        if any("login" in (e.get("event") or "").lower() for e in events):
            behavior_steps.append("1. Authenticated or brute-forced access through honeypot service.")
        if has_recon:
            behavior_steps.append("2. Executed reconnaissance commands inspecting host identity, OS, and user environment.")
        if has_decoy:
            behavior_steps.append("3. Interacted with deployed honey tokens and decoy configuration files.")
        if has_payload:
            behavior_steps.append("4. Attempted ingress tool transfer to retrieve external binaries.")
        if has_privesc:
            behavior_steps.append("5. Attempted privilege escalation via privileged binaries or sudo abuse.")
        
        observed_behavior_exp = " ".join(behavior_steps) if behavior_steps else "Initial service discovery and interactive command execution."

        # 5. Defensive Recommendation
        rec_actions = [
            f"Safely contain session '{session.get('session_id')}' to disconnect attacker connection.",
            f"Block or rate-limit source IP {src_ip} at edge gateway.",
            "Preserve honeypot execution logs and extracted IOCs for threat hunting correlation.",
            "Verify real production servers for any queries matching the extracted file/tool patterns."
        ]

        return {
            "summary": summary,
            "likely_objective": likely_obj,
            "risk_explanation": risk_exp,
            "observed_behavior_explanation": observed_behavior_exp,
            "recommended_defensive_action": " ".join(rec_actions)
        }
