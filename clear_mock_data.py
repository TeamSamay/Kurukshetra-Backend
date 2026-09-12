"""
Purge Mock / Simulated Data from Kurukshetra MongoDB Database
Leaves the database clean so ONLY real incoming honeypot attacker traffic is recorded and displayed.
"""

import asyncio
import os
from dotenv import load_dotenv
from motor.motor_asyncio import AsyncIOMotorClient

load_dotenv()
MONGODB_URI = os.getenv("MONGODB_URI", "mongodb://127.0.0.1:27017")
DB_NAME = os.getenv("MONGODB_DB_NAME", "threat_intelligence")

async def purge_all_mock():
    print(f"Connecting to MongoDB: {DB_NAME}...")
    client = AsyncIOMotorClient(MONGODB_URI)
    db = client[DB_NAME]

    demo_filter = {
        "$or": [
            {"session_id": {"$regex": r"^(ATK-SIM-|ATK-SSH-901|ATK-WEB-402|ATK-REDIS-601|ATK-K8S-505|ATK-RDP-108|ATK-TELNET-301|sim-|SYSTEM-)"}},
            {"metadata.simulation": True},
        ]
    }

    # Find demo sessions
    demo_sessions = await db.attack_sessions.find(demo_filter, {"session_id": 1}).to_list(5000)
    session_ids = [s["session_id"] for s in demo_sessions if s.get("session_id")]

    # Delete mock events & sessions
    ev_del = await db.events.delete_many(demo_filter)
    sess_del = await db.attack_sessions.delete_many(demo_filter)
    
    # Delete mock attacker profiles & reports & mitre & blockchain
    atk_del = await db.attackers.delete_many({"attacker_id": {"$regex": r"^(ACTOR-|ATK-PROFILE-)"}})
    rep_del = await db.threat_reports.delete_many({})
    mitre_del = await db.mitre_mappings.delete_many({})
    bc_del = await db.blockchain_evidence.delete_many({})
    ioc_del = await db.iocs.delete_many({})

    print("=======================================================")
    print("Purged all simulated / mock attack data:")
    print(f"  - Sessions deleted: {sess_del.deleted_count}")
    print(f"  - Events deleted:   {ev_del.deleted_count}")
    print(f"  - IOCs deleted:     {ioc_del.deleted_count}")
    print(f"  - MITRE deleted:    {mitre_del.deleted_count}")
    print(f"  - Attackers reset:  {atk_del.deleted_count}")
    print(f"  - Reports reset:    {rep_del.deleted_count}")
    print(f"  - Blockchain reset: {bc_del.deleted_count}")
    print("=======================================================")
    print("Kurukshetra is now 100% clean and ready for REAL attacker traffic only!")

if __name__ == "__main__":
    asyncio.run(purge_all_mock())
