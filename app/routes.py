import uuid
from datetime import datetime, timezone
from typing import List, Optional
from fastapi import APIRouter, HTTPException, Query

from app.database import (
    get_events_col,
    get_sessions_col,
    get_iocs_col,
    get_attackers_col,
    get_mitre_col,
    get_reports_col
)
from app.schemas import (
    EventCreate,
    IngestSuccessResponse,
    SessionResponse,
    SessionDetailResponse,
    IOCResponse,
    AttackerResponse,
    MitreTechniqueResponse,
    ThreatReportResponse,
    ContainmentRequest,
    ContainmentResponse,
    DashboardSummaryResponse
)
from app.engines import IOCEngine, RiskEngine, FingerprintEngine, MitreEngine, AIEngine
from app.websocket import ws_manager

router = APIRouter()

# Helper for current UTC string
def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# -------------------------------------------------------------------------
# 1. EVENT INGESTION (Member 1 Honeypot Interface)
# -------------------------------------------------------------------------
@router.post("/events", response_model=IngestSuccessResponse)
async def ingest_event(payload: EventCreate):
    """
    Ingests honeypot telemetry, processes IOCs, calculates deterministic risk,
    maps MITRE techniques, updates attacker DNA, and streams live via WebSocket.
    """
    events_col = get_events_col()
    sessions_col = get_sessions_col()
    iocs_col = get_iocs_col()
    attackers_col = get_attackers_col()
    mitre_col = get_mitre_col()

    event_dict = payload.model_dump()
    if not event_dict.get("timestamp"):
        event_dict["timestamp"] = now_iso()
    event_dict["processed_at"] = now_iso()

    # 1. IOC Extraction
    extracted_iocs = IOCEngine.extract_iocs(event_dict)
    event_dict["extracted_iocs"] = extracted_iocs

    # 2. MITRE ATT&CK Mapping
    mitre_matches = MitreEngine.map_event(event_dict)
    event_dict["mitre_techniques"] = mitre_matches

    # 3. Store Event in MongoDB (upsert by event_id)
    await events_col.update_one(
        {"event_id": payload.event_id},
        {"$set": event_dict},
        upsert=True
    )

    # 4. Upsert Extracted IOCs in MongoDB
    for ioc in extracted_iocs:
        await iocs_col.update_one(
            {"ioc_type": ioc["ioc_type"], "value": ioc["value"]},
            {
                "$set": {
                    "last_seen": event_dict["timestamp"],
                    "confidence": ioc["confidence"],
                    "threat_category": ioc["threat_category"]
                },
                "$setOnInsert": {
                    "first_seen": event_dict["timestamp"]
                },
                "$addToSet": {
                    "session_ids": payload.session_id,
                    "source_ips": payload.source_ip
                }
            },
            upsert=True
        )

    # 5. Store MITRE Mappings in MongoDB
    for mm in mitre_matches:
        await mitre_col.update_one(
            {"session_id": payload.session_id, "technique_id": mm["technique_id"]},
            {
                "$set": {
                    "technique_name": mm["technique_name"],
                    "tactic": mm["tactic"],
                    "matched_command": mm["matched_command"],
                    "evidence": mm["evidence"],
                    "timestamp": mm["timestamp"]
                }
            },
            upsert=True
        )

    # 6. Retrieve all events for this session to compute aggregate risk & fingerprint
    cursor = events_col.find({"session_id": payload.session_id}).sort("timestamp", 1)
    all_session_events = await cursor.to_list(length=1000)

    # 7. Compute Session Risk
    risk_score, risk_level, risk_breakdown = RiskEngine.compute_session_risk(all_session_events)

    # 8. Compute Attacker DNA Fingerprint
    fingerprint, tactics = FingerprintEngine.generate_fingerprint(payload.service, all_session_events)

    # 9. Upsert Attack Session
    existing_session = await sessions_col.find_one({"session_id": payload.session_id})
    start_time = existing_session.get("start_time") if existing_session else event_dict["timestamp"]
    status = existing_session.get("status", "ACTIVE") if existing_session else "ACTIVE"
    containment_info = existing_session.get("containment_info") if existing_session else None

    # Count distinct iocs and mitre techniques for session
    ioc_count = await iocs_col.count_documents({"session_ids": payload.session_id})
    mitre_count = await mitre_col.count_documents({"session_id": payload.session_id})

    session_doc = {
        "session_id": payload.session_id,
        "source_ip": payload.source_ip,
        "target_ip": payload.target_ip,
        "service": payload.service,
        "start_time": start_time,
        "last_seen": event_dict["timestamp"],
        "status": status,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "risk_breakdown": risk_breakdown,
        "fingerprint": fingerprint,
        "event_count": len(all_session_events),
        "iocs_count": ioc_count,
        "mitre_techniques_count": mitre_count,
        "containment_info": containment_info
    }

    await sessions_col.update_one(
        {"session_id": payload.session_id},
        {"$set": session_doc},
        upsert=True
    )

    # 10. Update Attacker DNA Profile (keyed by fingerprint or primary source_ip)
    attacker_id = f"ATK-PROFILE-{fingerprint}"
    await attackers_col.update_one(
        {"attacker_id": attacker_id},
        {
            "$set": {
                "last_seen": event_dict["timestamp"],
            },
            "$max": {"max_risk_score": risk_score},
            "$inc": {"total_events": 1},
            "$addToSet": {
                "fingerprints": fingerprint,
                "source_ips": payload.source_ip,
                "session_ids": payload.session_id,
                "primary_tactics": {"$each": tactics}
            },
            "$setOnInsert": {
                "first_seen": event_dict["timestamp"]
            }
        },
        upsert=True
    )

    # 11. WebSocket Broadcast to Dashboard
    ws_payload = {
        "type": "NEW_EVENT",
        "data": {
            "event": event_dict,
            "session": session_doc,
            "extracted_iocs": extracted_iocs,
            "mitre_matches": mitre_matches
        },
        "event": event_dict,
        "session": session_doc
    }
    await ws_manager.broadcast(ws_payload)

    return IngestSuccessResponse(
        event_id=payload.event_id,
        session_id=payload.session_id,
        current_session_risk=risk_score,
        risk_level=risk_level,
        fingerprint=fingerprint
    )


# -------------------------------------------------------------------------
# 2. SESSIONS / ATTACKS ENDPOINTS
# -------------------------------------------------------------------------
@router.get("/attacks", response_model=List[SessionResponse])
async def list_attacks(
    limit: int = Query(50, ge=1, le=200),
    status: Optional[str] = None,
    risk_level: Optional[str] = None
):
    """List all attack sessions with risk levels and behavior signatures."""
    query = {}
    if status:
        query["status"] = status.upper()
    if risk_level:
        query["risk_level"] = risk_level.upper()

    cursor = get_sessions_col().find(query, {"_id": 0}).sort("last_seen", -1).limit(limit)
    sessions = await cursor.to_list(length=limit)
    return sessions


@router.get("/sessions/{session_id}", response_model=SessionDetailResponse)
async def get_session_detail(session_id: str):
    """Retrieve deep session telemetry, timeline events, IOCs, and MITRE techniques."""
    session = await get_sessions_col().find_one({"session_id": session_id}, {"_id": 0})
    if not session:
        raise HTTPException(status_code=404, detail=f"Session '{session_id}' not found.")

    # Fetch events
    events_cur = get_events_col().find({"session_id": session_id}, {"_id": 0}).sort("timestamp", 1)
    events = await events_cur.to_list(length=1000)

    # Fetch IOCs
    iocs_cur = get_iocs_col().find({"session_ids": session_id}, {"_id": 0})
    iocs = await iocs_cur.to_list(length=100)

    # Fetch MITRE
    mitre_cur = get_mitre_col().find({"session_id": session_id}, {"_id": 0})
    mitre = await mitre_cur.to_list(length=100)

    # Generate or reuse AI analysis
    ai_analysis = await AIEngine.analyze_threat(
        session=session,
        events=events,
        risk_score=session.get("risk_score", 0),
        risk_level=session.get("risk_level", "LOW"),
        iocs=iocs,
        mitre_mappings=mitre,
        fingerprint=session.get("fingerprint", "UNKNOWN")
    )

    return SessionDetailResponse(
        **session,
        events=events,
        iocs=iocs,
        mitre_mappings=mitre,
        ai_analysis=ai_analysis
    )


# -------------------------------------------------------------------------
# 3. IOCs ENDPOINT
# -------------------------------------------------------------------------
@router.get("/iocs", response_model=List[IOCResponse])
async def list_iocs(
    ioc_type: Optional[str] = None,
    session_id: Optional[str] = None,
    limit: int = Query(100, ge=1, le=500)
):
    """Get extracted Indicators of Compromise (IP, Domain, URL, Hash, File, Tool)."""
    query = {}
    if ioc_type:
        query["ioc_type"] = ioc_type.lower()
    if session_id:
        query["session_ids"] = session_id

    cursor = get_iocs_col().find(query, {"_id": 0}).sort("last_seen", -1).limit(limit)
    return await cursor.to_list(length=limit)


# -------------------------------------------------------------------------
# 4. ATTACKERS (BEHAVIOR DNA) ENDPOINT
# -------------------------------------------------------------------------
@router.get("/attackers", response_model=List[AttackerResponse])
async def list_attackers(limit: int = Query(50, ge=1, le=200)):
    """Get unique attacker profiles grouped by behavioral DNA fingerprints."""
    cursor = get_attackers_col().find({}, {"_id": 0}).sort("last_seen", -1).limit(limit)
    return await cursor.to_list(length=limit)


# -------------------------------------------------------------------------
# 5. MITRE ATT&CK ENDPOINTS
# -------------------------------------------------------------------------
@router.get("/mitre", response_model=List[MitreTechniqueResponse])
async def list_all_mitre(limit: int = Query(100, ge=1, le=500)):
    """Get all observed MITRE ATT&CK techniques across all sessions."""
    cursor = get_mitre_col().find({}, {"_id": 0}).sort("timestamp", -1).limit(limit)
    return await cursor.to_list(length=limit)


@router.get("/mitre/{session_id}", response_model=List[MitreTechniqueResponse])
async def get_session_mitre(session_id: str):
    """Get MITRE ATT&CK techniques identified for a specific session."""
    cursor = get_mitre_col().find({"session_id": session_id}, {"_id": 0})
    return await cursor.to_list(length=100)


# -------------------------------------------------------------------------
# 6. SAFE CONTAINMENT ENDPOINT
# -------------------------------------------------------------------------
@router.post("/sessions/{session_id}/contain", response_model=ContainmentResponse)
async def contain_session(session_id: str, req: ContainmentRequest = ContainmentRequest()):
    """
    Defensively isolates an attack session, preventing further interaction
    and preserving forensic telemetry.
    """
    sessions_col = get_sessions_col()
    session = await sessions_col.find_one({"session_id": session_id})
    if not session:
        raise HTTPException(status_code=404, detail=f"Session '{session_id}' not found.")

    contained_at = now_iso()
    containment_info = {
        "status": "CONTAINED",
        "action": req.action,
        "reason": req.reason,
        "timestamp": contained_at
    }

    await sessions_col.update_one(
        {"session_id": session_id},
        {
            "$set": {
                "status": "CONTAINED",
                "containment_info": containment_info
            }
        }
    )

    # Broadcast containment alert via WebSocket
    await ws_manager.broadcast({
        "type": "SESSION_CONTAINED",
        "session_id": session_id,
        "data": {
            "session_id": session_id,
            "containment_info": containment_info
        }
    })

    return ContainmentResponse(
        status="success",
        session_id=session_id,
        contained_at=contained_at,
        containment_status="CONTAINED",
        message=f"Session {session_id} has been safely isolated via {req.action}."
    )


# -------------------------------------------------------------------------
# 7. THREAT REPORT ENDPOINT
# -------------------------------------------------------------------------
@router.get("/reports/{session_id}", response_model=ThreatReportResponse)
async def get_threat_report(session_id: str):
    """
    Generates or retrieves comprehensive threat intelligence report
    with Executive Summary, Timeline, MITRE, IOCs, and AI threat analysis.
    """
    session = await get_sessions_col().find_one({"session_id": session_id}, {"_id": 0})
    if not session:
        raise HTTPException(status_code=404, detail=f"Session '{session_id}' not found.")

    events = await get_events_col().find({"session_id": session_id}, {"_id": 0}).sort("timestamp", 1).to_list(1000)
    iocs = await get_iocs_col().find({"session_ids": session_id}, {"_id": 0}).to_list(100)
    mitre = await get_mitre_col().find({"session_id": session_id}, {"_id": 0}).to_list(100)

    ai_analysis = await AIEngine.analyze_threat(
        session=session,
        events=events,
        risk_score=session.get("risk_score", 0),
        risk_level=session.get("risk_level", "LOW"),
        iocs=iocs,
        mitre_mappings=mitre,
        fingerprint=session.get("fingerprint", "UNKNOWN")
    )

    # Build timeline summary
    timeline = [
        {
            "time": e.get("timestamp"),
            "event_type": e.get("event_type"),
            "event": e.get("event")
        }
        for e in events
    ]

    report = {
        "report_id": f"RPT-{session_id}-{int(datetime.now().timestamp())}",
        "session_id": session_id,
        "generated_at": now_iso(),
        "executive_summary": ai_analysis.get("summary", "Adversary interaction recorded and analyzed."),
        "attack_source": {
            "source_ip": session.get("source_ip"),
            "service": session.get("service")
        },
        "target": {
            "target_ip": session.get("target_ip"),
            "service": session.get("service")
        },
        "timeline": timeline,
        "observed_behavior": session.get("risk_breakdown", []),
        "iocs": iocs,
        "mitre_mapping": mitre,
        "risk": {
            "score": session.get("risk_score", 0),
            "level": session.get("risk_level", "LOW"),
            "breakdown": session.get("risk_breakdown", [])
        },
        "attacker_fingerprint": session.get("fingerprint"),
        "ai_analysis": ai_analysis,
        "containment_status": session.get("containment_info") or {"status": session.get("status", "ACTIVE")}
    }

    # Save report snapshot in MongoDB
    await get_reports_col().update_one(
        {"session_id": session_id},
        {"$set": report},
        upsert=True
    )

    return ThreatReportResponse(**report)


# -------------------------------------------------------------------------
# 8. DASHBOARD SUMMARY ENDPOINT (Member 4 Integration)
# -------------------------------------------------------------------------
@router.get("/dashboard/summary", response_model=DashboardSummaryResponse)
async def get_dashboard_summary():
    """Aggregated real-time metrics for Dashboard cards and charts."""
    sessions_col = get_sessions_col()
    events_col = get_events_col()
    iocs_col = get_iocs_col()
    mitre_col = get_mitre_col()

    total_sessions = await sessions_col.count_documents({})
    active_sessions = await sessions_col.count_documents({"status": "ACTIVE"})
    contained_sessions = await sessions_col.count_documents({"status": "CONTAINED"})
    critical_risk_sessions = await sessions_col.count_documents({"risk_level": "CRITICAL"})
    high_risk_sessions = await sessions_col.count_documents({"risk_level": "HIGH"})
    total_events = await events_col.count_documents({})
    total_iocs = await iocs_col.count_documents({})

    # Top MITRE techniques aggregation
    pipeline = [
        {"$group": {"_id": "$technique_id", "name": {"$first": "$technique_name"}, "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$limit": 5}
    ]
    top_mitre_raw = await mitre_col.aggregate(pipeline).to_list(5)
    top_mitre = [
        {"technique_id": item["_id"], "name": item["name"], "count": item["count"]}
        for item in top_mitre_raw
    ]

    # Recent attacks
    recent_cur = sessions_col.find({}, {"_id": 0}).sort("last_seen", -1).limit(6)
    recent_attacks = await recent_cur.to_list(6)

    # Service distribution
    srv_pipeline = [
        {"$group": {"_id": "$service", "count": {"$sum": 1}}}
    ]
    srv_raw = await sessions_col.aggregate(srv_pipeline).to_list(10)
    service_distribution = {item["_id"]: item["count"] for item in srv_raw if item["_id"]}

    return DashboardSummaryResponse(
        total_sessions=total_sessions,
        active_sessions=active_sessions,
        contained_sessions=contained_sessions,
        critical_risk_sessions=critical_risk_sessions,
        high_risk_sessions=high_risk_sessions,
        total_events=total_events,
        total_iocs=total_iocs,
        top_mitre_techniques=top_mitre,
        recent_attacks=recent_attacks,
        service_distribution=service_distribution
    )
