from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


# -------------------------------------------------------------------------
# Event Schemas (Member 1 Honeypot Ingestion)
# -------------------------------------------------------------------------
class EventCreate(BaseModel):
    event_id: str = Field(..., description="Unique ID for telemetry event, e.g. EVT-001")
    session_id: str = Field(..., description="Session/Attack ID, e.g. ATK-001")
    source_ip: str = Field(..., description="Attacker source IP address")
    target_ip: str = Field(..., description="Honeypot target IP address")
    service: str = Field(..., description="Target service, e.g. ssh, http, ftp, rdp")
    timestamp: Optional[str] = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="ISO8601 timestamp"
    )
    event_type: str = Field(..., description="Type of event: command, login, file_access, network, etc.")
    event: str = Field(..., description="Command or interaction payload, e.g. whoami, admin login")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Arbitrary metadata from honeypot")


class EventResponse(BaseModel):
    event_id: str
    session_id: str
    source_ip: str
    target_ip: str
    service: str
    timestamp: str
    event_type: str
    event: str
    metadata: Dict[str, Any] = Field(default_factory=dict)
    processed_at: Optional[str] = None
    extracted_iocs: List[Dict[str, Any]] = Field(default_factory=list)
    mitre_techniques: List[Dict[str, Any]] = Field(default_factory=list)
    risk_delta: int = 0


class IngestSuccessResponse(BaseModel):
    status: str = "success"
    message: str = "Event ingested and processed successfully"
    event_id: str
    session_id: str
    current_session_risk: int
    risk_level: str
    fingerprint: Optional[str] = None


# -------------------------------------------------------------------------
# Session Schemas
# -------------------------------------------------------------------------
class SessionResponse(BaseModel):
    session_id: str
    source_ip: str
    target_ip: str
    service: str
    start_time: str
    last_seen: str
    status: str = "ACTIVE"  # ACTIVE, CONTAINED, CLOSED
    risk_score: int = 0
    risk_level: str = "LOW"  # LOW, MEDIUM, HIGH, CRITICAL
    risk_breakdown: List[str] = Field(default_factory=list)
    fingerprint: Optional[str] = None
    event_count: int = 0
    iocs_count: int = 0
    mitre_techniques_count: int = 0
    containment_info: Optional[Dict[str, Any]] = None
    ai_summary: Optional[str] = None


class SessionDetailResponse(SessionResponse):
    events: List[Dict[str, Any]] = Field(default_factory=list)
    iocs: List[Dict[str, Any]] = Field(default_factory=list)
    mitre_mappings: List[Dict[str, Any]] = Field(default_factory=list)
    ai_analysis: Optional[Dict[str, Any]] = None


# -------------------------------------------------------------------------
# IOC Schemas
# -------------------------------------------------------------------------
class IOCResponse(BaseModel):
    ioc_type: str  # ip, domain, url, hash, file, tool
    value: str
    first_seen: str
    last_seen: str
    session_ids: List[str] = Field(default_factory=list)
    source_ips: List[str] = Field(default_factory=list)
    confidence: str = "HIGH"
    threat_category: str = "SUSPICIOUS"


# -------------------------------------------------------------------------
# Attacker Fingerprint / DNA Schemas
# -------------------------------------------------------------------------
class AttackerResponse(BaseModel):
    attacker_id: str
    fingerprints: List[str] = Field(default_factory=list)
    source_ips: List[str] = Field(default_factory=list)
    session_ids: List[str] = Field(default_factory=list)
    total_events: int = 0
    first_seen: str
    last_seen: str
    max_risk_score: int = 0
    primary_tactics: List[str] = Field(default_factory=list)


# -------------------------------------------------------------------------
# MITRE ATT&CK Schemas
# -------------------------------------------------------------------------
class MitreTechniqueResponse(BaseModel):
    technique_id: str
    technique_name: str
    tactic: str
    matched_command: Optional[str] = ""
    evidence: Optional[str] = ""
    timestamp: Optional[str] = None


# -------------------------------------------------------------------------
# Containment Schemas
# -------------------------------------------------------------------------
class ContainmentRequest(BaseModel):
    reason: Optional[str] = "Manual containment triggered by analyst"
    action: Optional[str] = "ISOLATE"  # ISOLATE, HONEY_REDIRECT, BLACKHOLE


class ContainmentResponse(BaseModel):
    status: str
    session_id: str
    contained_at: str
    containment_status: str
    message: str


# -------------------------------------------------------------------------
# Threat Report Schemas
# -------------------------------------------------------------------------
class AIAnalysis(BaseModel):
    summary: str
    likely_objective: str
    risk_explanation: str
    observed_behavior_explanation: str
    recommended_defensive_action: str


class ThreatReportResponse(BaseModel):
    report_id: str
    session_id: str
    generated_at: str
    executive_summary: str
    attack_source: Dict[str, Any]
    target: Dict[str, Any]
    timeline: List[Dict[str, Any]]
    observed_behavior: List[str]
    iocs: List[Dict[str, Any]]
    mitre_mapping: List[Dict[str, Any]]
    risk: Dict[str, Any]
    attacker_fingerprint: Optional[str]
    ai_analysis: Optional[AIAnalysis]
    containment_status: Dict[str, Any]


# -------------------------------------------------------------------------
# Dashboard Summary Schemas (Member 4)
# -------------------------------------------------------------------------
class DashboardSummaryResponse(BaseModel):
    total_sessions: int
    active_sessions: int
    contained_sessions: int
    critical_risk_sessions: int
    high_risk_sessions: int
    total_events: int
    total_iocs: int
    top_mitre_techniques: List[Dict[str, Any]]
    recent_attacks: List[SessionResponse]
    service_distribution: Dict[str, int]
