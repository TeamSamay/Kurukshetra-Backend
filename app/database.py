import logging
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
from app.config import settings

logger = logging.getLogger("threat_intel.database")

class Database:
    client: AsyncIOMotorClient = None
    db: AsyncIOMotorDatabase = None

db_instance = Database()

async def connect_to_mongo():
    logger.info(f"Connecting to MongoDB at: {settings.MONGODB_URI.split('@')[-1] if '@' in settings.MONGODB_URI else settings.MONGODB_URI}")
    try:
        db_instance.client = AsyncIOMotorClient(
            settings.MONGODB_URI,
            serverSelectionTimeoutMS=5000
        )
        db_instance.db = db_instance.client[settings.MONGODB_DB_NAME]
        
        # Test connection with ping
        await db_instance.client.admin.command('ping')
        logger.info(f"Successfully connected to MongoDB database: {settings.MONGODB_DB_NAME}")
        
        # Create helpful indexes
        await init_db_indexes()
    except Exception as e:
        logger.error(f"Failed to connect to MongoDB: {e}")
        raise e

async def close_mongo_connection():
    if db_instance.client:
        db_instance.client.close()
        logger.info("Closed MongoDB connection.")

def get_db() -> AsyncIOMotorDatabase:
    if db_instance.db is None:
        raise RuntimeError("Database not initialized. Call connect_to_mongo first.")
    return db_instance.db

# Collections accessor helpers
def get_events_col():
    return get_db()["events"]

def get_sessions_col():
    return get_db()["attack_sessions"]

def get_iocs_col():
    return get_db()["iocs"]

def get_attackers_col():
    return get_db()["attackers"]

def get_mitre_col():
    return get_db()["mitre_mappings"]

def get_reports_col():
    return get_db()["threat_reports"]

def get_honeypots_col():
    return get_db()["honeypots"]

def get_blockchain_col():
    return get_db()["blockchain_evidence"]

async def init_db_indexes():
    """Ensure indexes exist for high-speed queries and data integrity."""
    try:
        # events indexes
        await get_events_col().create_index("event_id", unique=True)
        await get_events_col().create_index("session_id")
        await get_events_col().create_index("source_ip")
        await get_events_col().create_index("timestamp")
        
        # attack_sessions indexes
        await get_sessions_col().create_index("session_id", unique=True)
        await get_sessions_col().create_index("source_ip")
        await get_sessions_col().create_index("status")
        await get_sessions_col().create_index("risk_score")
        await get_sessions_col().create_index("last_seen")
        
        # iocs indexes
        await get_iocs_col().create_index([("ioc_type", 1), ("value", 1)], unique=True)
        await get_iocs_col().create_index("session_ids")
        
        # attackers indexes
        await get_attackers_col().create_index("attacker_id", unique=True)
        await get_attackers_col().create_index("fingerprints")
        await get_attackers_col().create_index("source_ips")
        
        # mitre indexes
        await get_mitre_col().create_index("session_id")
        await get_mitre_col().create_index("technique_id")
        
        # reports indexes
        await get_reports_col().create_index("session_id", unique=True)
        
        # blockchain_evidence indexes
        await get_blockchain_col().create_index("evidence_id", unique=True)
        await get_blockchain_col().create_index("event_id", unique=True)
        await get_blockchain_col().create_index("session_id")
        await get_blockchain_col().create_index("block_index", unique=True)
        await get_blockchain_col().create_index("block_hash")
        
        logger.info("MongoDB indexes verified successfully.")
    except Exception as e:
        logger.warning(f"Note on MongoDB index initialization: {e}")
