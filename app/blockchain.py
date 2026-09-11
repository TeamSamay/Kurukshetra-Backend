import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple

from app.config import settings
from app.database import get_blockchain_col, get_events_col

logger = logging.getLogger("threat_intel.blockchain")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def canonical_event_bytes(event_dict: Dict[str, Any]) -> bytes:
    """
    Produces deterministic canonical JSON serialization for cryptographic hashing.
    Excludes non-deterministic or mutable processing flags.
    """
    canonical_data = {
        "event_id": str(event_dict.get("event_id", "")),
        "session_id": str(event_dict.get("session_id", "")),
        "source_ip": str(event_dict.get("source_ip", "")),
        "target_ip": str(event_dict.get("target_ip", "")),
        "service": str(event_dict.get("service", "")),
        "timestamp": str(event_dict.get("timestamp", "")),
        "event_type": str(event_dict.get("event_type", "")),
        "event": str(event_dict.get("event", "")),
        "metadata": event_dict.get("metadata", {})
    }
    return json.dumps(canonical_data, sort_keys=True, separators=(",", ":")).encode("utf-8")


def calculate_event_hash(event_dict: Dict[str, Any]) -> str:
    """Calculates SHA-256 cryptographic digest of a canonical telemetry event."""
    return hashlib.sha256(canonical_event_bytes(event_dict)).hexdigest()


def calculate_block_hash(
    block_index: int,
    timestamp: str,
    evidence_id: str,
    event_id: str,
    event_hash: str,
    previous_hash: str
) -> str:
    """Calculates SHA-256 header hash of the blockchain evidence block."""
    payload = f"{block_index}|{timestamp}|{evidence_id}|{event_id}|{event_hash}|{previous_hash}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class BlockchainEvidenceLedger:
    """
    Tamper-evident cryptographic ledger for security telemetry evidence.
    Ensures mathematical proof of evidence integrity without storing complete raw payloads on-chain.
    """

    @classmethod
    async def record_event_evidence(cls, event_dict: Dict[str, Any]) -> Dict[str, Any]:
        """
        Calculates canonical event hash, determines previous block hash,
        creates a new evidence block, and persists to the blockchain collection.
        """
        blockchain_col = get_blockchain_col()
        event_id = event_dict.get("event_id")
        session_id = event_dict.get("session_id")

        # Check if already registered
        existing = await blockchain_col.find_one({"event_id": event_id}, {"_id": 0})
        if existing:
            return existing

        event_hash = calculate_event_hash(event_dict)

        # Get latest block to link previous_hash
        latest_block = await blockchain_col.find_one(
            sort=[("block_index", -1)]
        )

        if latest_block:
            block_index = latest_block.get("block_index", 0) + 1
            previous_hash = latest_block.get("block_hash", settings.BLOCKCHAIN_GENESIS_HASH)
        else:
            block_index = 1
            previous_hash = settings.BLOCKCHAIN_GENESIS_HASH

        evidence_id = f"EVT-{str(block_index).zfill(4)}"
        timestamp = event_dict.get("timestamp") or now_iso()
        block_hash = calculate_block_hash(
            block_index=block_index,
            timestamp=timestamp,
            evidence_id=evidence_id,
            event_id=event_id,
            event_hash=event_hash,
            previous_hash=previous_hash
        )

        evidence_doc = {
            "evidence_id": evidence_id,
            "event_id": event_id,
            "session_id": session_id,
            "block_index": block_index,
            "event_hash": event_hash,
            "previous_hash": previous_hash,
            "block_hash": block_hash,
            "timestamp": timestamp,
            "verification_status": "VERIFIED"
        }

        await blockchain_col.update_one(
            {"evidence_id": evidence_id},
            {"$set": evidence_doc},
            upsert=True
        )

        logger.info(f"Blockchain evidence registered: Block #{block_index} [{evidence_id}] Hash: {event_hash[:12]}...")
        return evidence_doc

    @classmethod
    async def verify_evidence(cls, evidence_id: str) -> Dict[str, Any]:
        """
        Cryptographically verifies an evidence block:
        1. Compares current MongoDB event hash against the stored blockchain event_hash.
        2. Recomputes block_hash to verify header integrity.
        """
        blockchain_col = get_blockchain_col()
        events_col = get_events_col()

        evidence = await blockchain_col.find_one({"evidence_id": evidence_id}, {"_id": 0})
        if not evidence:
            return {
                "status": "NOT_FOUND",
                "evidence_id": evidence_id,
                "message": f"Evidence ID {evidence_id} not found in blockchain ledger."
            }

        event_id = evidence.get("event_id")
        event = await events_col.find_one({"event_id": event_id}, {"_id": 0})

        if not event:
            return {
                "status": "TAMPER_DETECTED",
                "evidence_id": evidence_id,
                "event_id": event_id,
                "reason": "Associated telemetry event deleted or missing from database.",
                "database_hash": "MISSING",
                "blockchain_hash": evidence.get("event_hash")
            }

        current_db_hash = calculate_event_hash(event)
        stored_bc_hash = evidence.get("event_hash")

        # Recompute block hash
        expected_block_hash = calculate_block_hash(
            block_index=evidence.get("block_index"),
            timestamp=evidence.get("timestamp"),
            evidence_id=evidence_id,
            event_id=event_id,
            event_hash=stored_bc_hash,
            previous_hash=evidence.get("previous_hash")
        )

        block_hash_valid = (expected_block_hash == evidence.get("block_hash"))
        hash_match = (current_db_hash == stored_bc_hash)

        if hash_match and block_hash_valid:
            status = "VERIFIED"
            message = "Cryptographic integrity verified. Database telemetry matches blockchain proof."
        else:
            status = "TAMPER_DETECTED"
            message = "Cryptographic mismatch! Telemetry event has been altered after blockchain registration."

        return {
            "status": status,
            "evidence_id": evidence_id,
            "event_id": event_id,
            "session_id": evidence.get("session_id"),
            "block_index": evidence.get("block_index"),
            "database_hash": current_db_hash,
            "blockchain_hash": stored_bc_hash,
            "previous_hash": evidence.get("previous_hash"),
            "block_hash": evidence.get("block_hash"),
            "hash_match": hash_match,
            "block_hash_valid": block_hash_valid,
            "message": message,
            "timestamp": evidence.get("timestamp")
        }

    @classmethod
    async def verify_chain(cls) -> Dict[str, Any]:
        """
        Validates the entire blockchain from Block #1 to the latest block.
        Checks previous_hash linkage and database telemetry consistency.
        """
        blockchain_col = get_blockchain_col()
        events_col = get_events_col()

        blocks = await blockchain_col.find({}, {"_id": 0}).sort("block_index", 1).to_list(length=10000)

        total_blocks = len(blocks)
        if total_blocks == 0:
            return {
                "chain_status": "VALID",
                "total_evidence_blocks": 0,
                "verified_evidence": 0,
                "integrity_alerts": 0,
                "latest_block": 0,
                "latest_evidence": "NONE",
                "alerts": []
            }

        expected_prev_hash = settings.BLOCKCHAIN_GENESIS_HASH
        verified_count = 0
        integrity_alerts = 0
        alerts = []

        for b in blocks:
            b_idx = b.get("block_index")
            ev_id = b.get("evidence_id")
            ev_id_ref = b.get("event_id")
            prev_h = b.get("previous_hash")
            stored_event_h = b.get("event_hash")
            b_hash = b.get("block_hash")

            # 1. Check previous_hash link
            if prev_h != expected_prev_hash:
                integrity_alerts += 1
                alerts.append({
                    "type": "CHAIN_BROKEN",
                    "block_index": b_idx,
                    "evidence_id": ev_id,
                    "expected_previous_hash": expected_prev_hash,
                    "actual_previous_hash": prev_h
                })

            # 2. Recompute block hash
            expected_b_hash = calculate_block_hash(
                block_index=b_idx,
                timestamp=b.get("timestamp"),
                evidence_id=ev_id,
                event_id=ev_id_ref,
                event_hash=stored_event_h,
                previous_hash=prev_h
            )
            if expected_b_hash != b_hash:
                integrity_alerts += 1
                alerts.append({
                    "type": "BLOCK_CORRUPTED",
                    "block_index": b_idx,
                    "evidence_id": ev_id
                })

            # 3. Check DB Event match
            ev_doc = await events_col.find_one({"event_id": ev_id_ref})
            if ev_doc:
                curr_db_hash = calculate_event_hash(ev_doc)
                if curr_db_hash != stored_event_h:
                    integrity_alerts += 1
                    alerts.append({
                        "type": "PAYLOAD_TAMPERED",
                        "block_index": b_idx,
                        "evidence_id": ev_id,
                        "event_id": ev_id_ref,
                        "database_hash": curr_db_hash,
                        "blockchain_hash": stored_event_h
                    })
                else:
                    verified_count += 1
            else:
                integrity_alerts += 1
                alerts.append({
                    "type": "EVENT_MISSING",
                    "block_index": b_idx,
                    "evidence_id": ev_id
                })

            expected_prev_hash = b_hash

        chain_status = "VALID" if integrity_alerts == 0 else "INTEGRITY_COMPROMISED"
        latest_block = blocks[-1] if blocks else {}

        return {
            "chain_status": chain_status,
            "total_evidence_blocks": total_blocks,
            "verified_evidence": verified_count,
            "integrity_alerts": integrity_alerts,
            "latest_block": latest_block.get("block_index", 0),
            "latest_evidence": latest_block.get("evidence_id", "NONE"),
            "latest_block_hash": latest_block.get("block_hash", ""),
            "alerts": alerts
        }

    # -------------------------------------------------------------------------
    # SAFE DEMO TAMPERING & RESTORATION (Controlled Sandbox Demonstration)
    # -------------------------------------------------------------------------
    DEMO_SESSION_ID = "DEMO-TAMPER-SESSION"
    DEMO_EVENT_ID = "EVT-DEMO-TAMPER-001"
    ORIGINAL_DEMO_PAYLOAD = "cat /etc/passwd"
    TAMPERED_DEMO_PAYLOAD = "cat /etc/passwd # [TAMPERED_INJECTED_STRING]"

    @classmethod
    async def ensure_demo_record(cls) -> Dict[str, Any]:
        """Creates the baseline demo event & blockchain block if not present."""
        events_col = get_events_col()
        existing_ev = await events_col.find_one({"event_id": cls.DEMO_EVENT_ID})
        if not existing_ev:
            demo_ev = {
                "event_id": cls.DEMO_EVENT_ID,
                "session_id": cls.DEMO_SESSION_ID,
                "source_ip": "198.51.100.77",
                "target_ip": "10.0.0.100",
                "service": "ssh",
                "timestamp": now_iso(),
                "event_type": "command",
                "event": cls.ORIGINAL_DEMO_PAYLOAD,
                "metadata": {"simulation": True, "demo_test": True}
            }
            await events_col.insert_one(demo_ev)
            await cls.record_event_evidence(demo_ev)

        blockchain_col = get_blockchain_col()
        return await blockchain_col.find_one({"event_id": cls.DEMO_EVENT_ID}, {"_id": 0})

    @classmethod
    async def tamper_demo_record(cls) -> Dict[str, Any]:
        """
        Controlled demonstration only:
        Silently alters the database payload of the test record while blockchain evidence remains unchanged.
        """
        await cls.ensure_demo_record()
        events_col = get_events_col()

        await events_col.update_one(
            {"event_id": cls.DEMO_EVENT_ID},
            {"$set": {"event": cls.TAMPERED_DEMO_PAYLOAD, "tampered_at": now_iso()}}
        )

        blockchain_col = get_blockchain_col()
        evidence = await blockchain_col.find_one({"event_id": cls.DEMO_EVENT_ID}, {"_id": 0})
        verification = await cls.verify_evidence(evidence["evidence_id"])

        return {
            "message": "Controlled test alteration performed on demo record.",
            "demo_event_id": cls.DEMO_EVENT_ID,
            "altered_payload": cls.TAMPERED_DEMO_PAYLOAD,
            "verification_result": verification
        }

    @classmethod
    async def restore_demo_record(cls) -> Dict[str, Any]:
        """Restores the demo record back to its original state."""
        await cls.ensure_demo_record()
        events_col = get_events_col()

        await events_col.update_one(
            {"event_id": cls.DEMO_EVENT_ID},
            {"$set": {"event": cls.ORIGINAL_DEMO_PAYLOAD}, "$unset": {"tampered_at": ""}}
        )

        blockchain_col = get_blockchain_col()
        evidence = await blockchain_col.find_one({"event_id": cls.DEMO_EVENT_ID}, {"_id": 0})
        verification = await cls.verify_evidence(evidence["evidence_id"])

        return {
            "message": "Demo record restored to original authentic payload.",
            "demo_event_id": cls.DEMO_EVENT_ID,
            "restored_payload": cls.ORIGINAL_DEMO_PAYLOAD,
            "verification_result": verification
        }
