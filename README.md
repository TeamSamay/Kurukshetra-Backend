# Adaptive Cyber Deception & Threat Intelligence Platform - Backend (Member 3)

Backend and real-time Threat Intelligence Processing pipeline built using **FastAPI** and **MongoDB / MongoDB Atlas**.

---

## 1. Pipeline Overview

```
HONEYPOT EVENTS (Member 1)
       │
       ▼
   FASTAPI (POST /api/events)
       │
       ▼
    MONGODB (events, attack_sessions, iocs, attackers, mitre, reports)
       │
       ▼
 PROCESSING ENGINE (IOC Extraction + Deterministic Risk 0-100 + Attacker DNA Fingerprint + MITRE ATT&CK + AI Threat Analysis)
       │
       ▼
 WEBSOCKET BROADCAST (/ws/attacks) ──► DASHBOARD (Member 4)
```

---

## 2. Quickstart (Local)

### Prerequisites
- Python 3.10+
- MongoDB Server running locally on `mongodb://127.0.0.1:27017` OR MongoDB Atlas URI

### Run the Backend
```bash
cd backend

# 1. Activate virtual environment
.\venv\Scripts\activate   # Windows
# or source venv/bin/activate # Linux/Mac

# 2. Run backend with Uvicorn
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

- Swagger Interactive Documentation: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- Live WebSocket Endpoint: `ws://127.0.0.1:8000/ws/attacks`

---

## 3. Quickstart (Docker)

```bash
cd backend
docker compose up --build
```

---

## 4. Integration Guide for Member 1 (Honeypot)

Whenever an attacker interacts with your honeypot (SSH, HTTP, FTP, etc.), send a POST request:

- **Endpoint**: `POST http://<BACKEND_IP>:8000/api/events`
- **Headers**: `Content-Type: application/json`
- **Request Body Format**:
```json
{
  "event_id": "EVT-001",
  "session_id": "ATK-001",
  "source_ip": "192.168.1.15",
  "target_ip": "192.168.1.20",
  "service": "ssh",
  "timestamp": "2026-09-11T10:30:00Z",
  "event_type": "command",
  "event": "whoami",
  "metadata": {}
}
```

- **Response Format**:
```json
{
  "status": "success",
  "message": "Event ingested and processed successfully",
  "event_id": "EVT-001",
  "session_id": "ATK-001",
  "current_session_risk": 30,
  "risk_level": "LOW",
  "fingerprint": "SSH-RECON-A1"
}
```

---

## 5. Integration Guide for Member 4 (Dashboard)

### A. Live WebSocket Updates
Connect your dashboard to:
`ws://<BACKEND_IP>:8000/ws/attacks`

When any honeypot event occurs, the server immediately pushes:
```json
{
  "type": "NEW_EVENT",
  "data": {
    "event": {
      "event_id": "EVT-001",
      "session_id": "ATK-001",
      "source_ip": "192.168.1.15",
      "service": "ssh",
      "event": "whoami"
    },
    "session": {
      "session_id": "ATK-001",
      "risk_score": 75,
      "risk_level": "HIGH",
      "fingerprint": "SSH-RECON-CRED-E4",
      "status": "ACTIVE"
    },
    "extracted_iocs": [...],
    "mitre_matches": [...]
  }
}
```

When an analyst triggers containment:
```json
{
  "type": "SESSION_CONTAINED",
  "data": {
    "session_id": "ATK-001",
    "containment_info": {
      "status": "CONTAINED",
      "action": "ISOLATE",
      "timestamp": "2026-09-11T10:35:00Z"
    }
  }
}
```

### B. REST API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/dashboard/summary` | Live metrics card counts, top MITRE techniques, recent attacks |
| `GET` | `/api/attacks` | List all attack sessions with risk and fingerprints |
| `GET` | `/api/sessions/{session_id}` | Detailed session telemetry and event sequence |
| `GET` | `/api/iocs` | Extracted Indicators of Compromise (IPs, Hashes, Domains, Tools) |
| `GET` | `/api/attackers` | Attacker behavior DNA profiles |
| `GET` | `/api/mitre/{session_id}` | MITRE ATT&CK techniques observed in session |
| `GET` | `/api/reports/{session_id}` | Comprehensive threat intelligence report with AI analysis |
| `POST` | `/api/sessions/{session_id}/contain` | Safely isolate and contain an attack session |

---

## 6. Testing & Simulation Script

Run the built-in attack simulator to generate sample telemetry and see live risk score evolution:
```bash
cd backend
python simulate.py
```
