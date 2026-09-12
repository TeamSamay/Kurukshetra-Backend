import asyncio
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
    get_reports_col,
    get_blockchain_col
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
    DashboardSummaryResponse,
    BlockchainEvidenceBlock,
    BlockchainVerifyResponse,
    BlockchainSummaryResponse,
    TamperDemoResponse,
    EventExplainRequest,
    EventExplainResponse,
    VulnerabilityGuardItem
)
from app.config import settings
from app.engines import IOCEngine, RiskEngine, FingerprintEngine, MitreEngine, AIEngine
from app.blockchain import BlockchainEvidenceLedger
from app.websocket import ws_manager

router = APIRouter()

# Sessions/events that are NOT real honeypot attacker traffic
_DEMO_SESSION_PREFIXES = (
    "ATK-SIM-", "ATK-SSH-901", "ATK-WEB-402", "ATK-REDIS-601",
    "ATK-K8S-505", "ATK-RDP-108", "ATK-TELNET-301", "sim-"
)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _is_simulation_event(event_dict: dict) -> bool:
    meta = event_dict.get("metadata") or {}
    if meta.get("simulation") is True:
        return True
    sid = event_dict.get("session_id") or ""
    return any(sid.startswith(p) for p in _DEMO_SESSION_PREFIXES)


def _real_session_query(extra: dict | None = None) -> dict:
    """MongoDB filter: exclude only internal/system noise, plus demo sessions when simulation is disabled."""
    excluded = r"^(SYSTEM-|HEALTH-)"
    if not settings.ALLOW_SIMULATION_EVENTS:
        excluded = r"^(ATK-SIM-|ATK-SSH-901|ATK-WEB-402|ATK-REDIS-601|ATK-K8S-505|ATK-RDP-108|ATK-TELNET-301|sim-|SYSTEM-|HEALTH-)"
    q = {"session_id": {"$not": {"$regex": excluded}}}
    if extra:
        q.update(extra)
    return q


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

    # Reject fake dashboard simulation unless explicitly enabled (production = real honeypot only)
    if _is_simulation_event(event_dict) and not settings.ALLOW_SIMULATION_EVENTS:
        raise HTTPException(
            status_code=403,
            detail="Simulation events disabled. Only real honeypot telemetry is accepted.",
        )

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

    # 11. Blockchain Evidence Ledger (Tamper-evident SHA-256 Chained Block)
    evidence_doc = await BlockchainEvidenceLedger.record_event_evidence(event_dict)

    # 12. WebSocket Broadcast to Dashboard
    ws_payload = {
        "type": "NEW_EVENT",
        "data": {
            "event": event_dict,
            "session": session_doc,
            "extracted_iocs": extracted_iocs,
            "mitre_matches": mitre_matches,
            "blockchain_evidence": evidence_doc
        },
        "event": event_dict,
        "session": session_doc,
        "blockchain_evidence": evidence_doc
    }
    await ws_manager.broadcast(ws_payload)

    # Also broadcast explicit blockchain created event for real-time widgets
    await ws_manager.broadcast({
        "type": "BLOCKCHAIN_EVIDENCE_CREATED",
        "evidence_id": evidence_doc.get("evidence_id"),
        "block_index": evidence_doc.get("block_index"),
        "event_id": payload.event_id,
        "session_id": payload.session_id,
        "event_hash": evidence_doc.get("event_hash"),
        "status": "VERIFIED"
    })

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
    query = _real_session_query()
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
    with Executive Summary, Timeline, MITRE, IOCs, AI threat analysis,
    and Blockchain cryptographic evidence integrity.
    """
    session = await get_sessions_col().find_one({"session_id": session_id}, {"_id": 0})
    if not session:
        raise HTTPException(status_code=404, detail=f"Session '{session_id}' not found.")

    events = await get_events_col().find({"session_id": session_id}, {"_id": 0}).sort("timestamp", 1).to_list(1000)
    iocs = await get_iocs_col().find({"session_ids": session_id}, {"_id": 0}).to_list(100)
    mitre = await get_mitre_col().find({"session_id": session_id}, {"_id": 0}).to_list(100)

    # Fetch latest blockchain proof for this session
    blockchain_col = get_blockchain_col()
    latest_bc = await blockchain_col.find_one({"session_id": session_id}, {"_id": 0}, sort=[("block_index", -1)])
    
    evidence_status = "VERIFIED"
    bc_proof = None
    if latest_bc:
        ver_res = await BlockchainEvidenceLedger.verify_evidence(latest_bc["evidence_id"])
        evidence_status = ver_res.get("status", "VERIFIED")
        bc_proof = latest_bc

    ai_analysis = await AIEngine.analyze_threat(
        session=session,
        events=events,
        risk_score=session.get("risk_score", 0),
        risk_level=session.get("risk_level", "LOW"),
        iocs=iocs,
        mitre_mappings=mitre,
        fingerprint=session.get("fingerprint", "UNKNOWN"),
        evidence_integrity=evidence_status
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
        "executive_summary": ai_analysis.get("threat_summary") or ai_analysis.get("summary", "Adversary interaction recorded and analyzed."),
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
        "containment_status": session.get("containment_info") or {"status": session.get("status", "ACTIVE")},
        "evidence_integrity": evidence_status,
        "blockchain_proof": bc_proof
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
    """Aggregated real-time metrics for Dashboard cards, charts, and blockchain ledger."""
    sessions_col = get_sessions_col()
    events_col = get_events_col()
    iocs_col = get_iocs_col()
    mitre_col = get_mitre_col()

    real_q = _real_session_query()
    mitre_pipeline = [
        {"$group": {"_id": "$technique_id", "name": {"$first": "$technique_name"}, "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$limit": 5}
    ]
    srv_pipeline = [
        {"$match": real_q},
        {"$group": {"_id": "$service", "count": {"$sum": 1}}}
    ]

    # Execute all 11 aggregation and count queries concurrently
    (
        total_sessions,
        active_sessions,
        contained_sessions,
        critical_risk_sessions,
        high_risk_sessions,
        total_events,
        total_iocs,
        top_mitre_raw,
        recent_attacks,
        srv_raw,
        bc_summary
    ) = await asyncio.gather(
        sessions_col.count_documents(real_q),
        sessions_col.count_documents({**real_q, "status": "ACTIVE"}),
        sessions_col.count_documents({**real_q, "status": "CONTAINED"}),
        sessions_col.count_documents({**real_q, "risk_level": "CRITICAL"}),
        sessions_col.count_documents({**real_q, "risk_level": "HIGH"}),
        events_col.count_documents({"session_id": real_q["session_id"]}),
        iocs_col.count_documents({}),
        mitre_col.aggregate(mitre_pipeline).to_list(5),
        sessions_col.find(real_q, {"_id": 0}).sort("last_seen", -1).limit(6).to_list(6),
        sessions_col.aggregate(srv_pipeline).to_list(10),
        BlockchainEvidenceLedger.verify_chain()
    )

    top_mitre = [
        {"technique_id": item["_id"], "name": item["name"], "count": item["count"]}
        for item in top_mitre_raw
    ]

    service_distribution = {item["_id"]: item["count"] for item in srv_raw if item.get("_id")}

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
        service_distribution=service_distribution,
        blockchain_summary=bc_summary
    )


# -------------------------------------------------------------------------
# 9. BLOCKCHAIN EVIDENCE ENDPOINTS (Tamper-Evident Integrity Layer)
# -------------------------------------------------------------------------
@router.get("/blockchain/verify", response_model=BlockchainSummaryResponse)
async def verify_blockchain_chain():
    """
    Validates cryptographic link integrity across all blocks and verifies
    telemetry payload hashes against the database.
    """
    return await BlockchainEvidenceLedger.verify_chain()


@router.get("/blockchain/verify/{evidence_id}", response_model=BlockchainVerifyResponse)
async def verify_blockchain_evidence(evidence_id: str):
    """
    Verifies a specific evidence block against current database event hash.
    Returns VERIFIED or TAMPER_DETECTED.
    """
    res = await BlockchainEvidenceLedger.verify_evidence(evidence_id)
    if res.get("status") == "NOT_FOUND":
        raise HTTPException(status_code=404, detail=res["message"])
    return res


@router.get("/blockchain/blocks", response_model=List[BlockchainEvidenceBlock])
async def list_blockchain_blocks(limit: int = Query(50, ge=1, le=200)):
    """List recent blockchain evidence blocks."""
    blocks = await get_blockchain_col().find({}, {"_id": 0}).sort("block_index", -1).limit(limit).to_list(limit)
    return blocks


@router.post("/blockchain/demo-tamper", response_model=TamperDemoResponse)
async def demo_tamper():
    """
    Safe Demo Only: Alters the database payload of a dedicated test record
    to demonstrate immediate cryptographic mismatch and TAMPER_DETECTED status.
    """
    return await BlockchainEvidenceLedger.tamper_demo_record()


@router.post("/blockchain/demo-restore", response_model=TamperDemoResponse)
async def demo_restore():
    """
    Safe Demo Only: Restores the test record back to its original authentic state,
    returning verification status to VERIFIED.
    """
    return await BlockchainEvidenceLedger.restore_demo_record()


# -------------------------------------------------------------------------
# 10. AI EXPLAIN & VULNERABILITY GUARD ENDPOINTS
# -------------------------------------------------------------------------
@router.post("/ai/explain-event", response_model=EventExplainResponse)
async def explain_event(req: EventExplainRequest):
    """
    Provides structured AI analysis for a specific telemetry event,
    strictly distinguishing Observed Behavior from AI Interpretation.
    """
    return await AIEngine.explain_event(req.model_dump())


@router.get("/ai/vulnerability-guard", response_model=List[VulnerabilityGuardItem])
async def get_vulnerability_guard():
    """
    Defensive Exposure Guard:
    Analyzes honeypot telemetry observations to determine what attackers are hunting for,
    and provides human-reviewed defensive remediation recommendations for real production servers.
    """
    events_col = get_events_col()
    iocs_col = get_iocs_col()

    real_q = _real_session_query()
    recent_events = await events_col.find(real_q, {"_id": 0}).sort("timestamp", -1).limit(50).to_list(50)
    recent_iocs = await iocs_col.find({}, {"_id": 0}).limit(30).to_list(30)

    return await AIEngine.analyze_vulnerability_guard(recent_events, recent_iocs)


# -------------------------------------------------------------------------
# 11. AI / LIVE THREAT LANDSCAPE ANALYSIS (AI Advisory Tab)
# -------------------------------------------------------------------------
@router.get("/ai/threat-analysis")
async def ai_threat_analysis(limit: int = Query(40, ge=1, le=200)):
    """
    Runs the AI threat engine against recent telemetry and returns
    a live threat-landscape analysis (Groq Llama if configured, else heuristic).
    """
    events_col = get_events_col()
    real_q = _real_session_query()
    recent = await events_col.find(real_q, {"_id": 0}).sort("timestamp", -1).limit(limit).to_list(limit)
    if not recent:
        return {
            "ai_powered": bool(settings.GROQ_API_KEY),
            "model_used": settings.GROQ_MODEL if settings.GROQ_API_KEY else "Kurukshetra Cyber Threat Intelligence Engine",
            "executive_summary": "No adversarial telemetry captured yet. Deception sensors are armed and listening.",
            "threat_level": "LOW",
            "threat_score": 0,
            "attack_vectors": [],
            "mitre_techniques": [],
            "recommendations": ["Maintain continuous honeypot monitoring"],
            "analyzed_at": now_iso(),
        }

    top = recent[0]
    sessions_col = get_sessions_col()
    session = await sessions_col.find_one({"session_id": top.get("session_id"), "_id": 0})
    session = session or {
        "session_id": top.get("session_id"),
        "source_ip": top.get("source_ip"),
        "target_ip": top.get("target_ip"),
        "service": top.get("service"),
        "risk_breakdown": [],
    }

    analysis = await AIEngine.analyze_threat(
        session=session,
        events=recent,
        risk_score=session.get("risk_score", 0),
        risk_level=session.get("risk_level", "LOW"),
        iocs=[],
        mitre_mappings=[],
        fingerprint=session.get("fingerprint", "UNKNOWN"),
        evidence_integrity="VERIFIED"
    )
    return {
        "ai_powered": analysis.get("ai_powered", False),
        "model_used": analysis.get("model_used", "Kurukshetra Cyber Threat Intelligence Engine"),
        "executive_summary": analysis.get("threat_summary") or analysis.get("summary", ""),
        "observed_behavior": analysis.get("observed_behavior", []),
        "ai_interpretation": analysis.get("ai_interpretation", []),
        "likely_objective": analysis.get("likely_objective", ""),
        "risk_explanation": analysis.get("risk_explanation", ""),
        "recommendations": analysis.get("recommended_actions", []),
        "threat_level": session.get("risk_level", "LOW"),
        "threat_score": session.get("risk_score", 0),
        "attack_vectors": [svc.strip().upper() + " decoy engagement" for svc in (session.get("service") or "unknown").split(",")],
        "analyzed_at": now_iso(),
    }


# -------------------------------------------------------------------------
# 12. ADMIN — Purge demo/simulation data
# -------------------------------------------------------------------------
@router.post("/admin/purge-demo")
async def purge_demo_data(key: str = Query(..., description="ADMIN_PURGE_KEY")):
    """
    Removes all simulation/test sessions from MongoDB.
    Real honeypot attacker sessions are preserved.
    """
    if key != settings.ADMIN_PURGE_KEY:
        raise HTTPException(status_code=403, detail="Invalid purge key")

    demo_filter = {
        "$or": [
            {"session_id": {"$regex": r"^(ATK-SIM-|ATK-SSH-901|ATK-WEB-402|sim-|SYSTEM-)"}},
            {"metadata.simulation": True},
        ]
    }
    sessions_col = get_sessions_col()
    events_col = get_events_col()
    blockchain_col = get_blockchain_col()

    demo_sessions = await sessions_col.find(demo_filter, {"session_id": 1}).to_list(5000)
    session_ids = [s["session_id"] for s in demo_sessions if s.get("session_id")]

    ev_result = await events_col.delete_many(demo_filter)
    sess_result = await sessions_col.delete_many(demo_filter)
    bc_result = await blockchain_col.delete_many({"session_id": {"$in": session_ids}})

    if session_ids:
        await get_iocs_col().update_many({}, {"$pull": {"session_ids": {"$in": session_ids}}})
        await get_mitre_col().delete_many({"session_id": {"$in": session_ids}})
        await get_reports_col().delete_many({"session_id": {"$in": session_ids}})

    return {
        "status": "purged",
        "events_deleted": ev_result.deleted_count,
        "sessions_deleted": sess_result.deleted_count,
        "blockchain_evidence_deleted": bc_result.deleted_count,
        "message": "Demo/simulation data removed. Dashboard now shows real honeypot traffic only.",
    }
