import os
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    PROJECT_NAME: str = "Adaptive Cyber Deception & Threat Intelligence Platform"
    API_V1_STR: str = "/api"
    
    # MongoDB Configuration (Local or MongoDB Atlas)
    # Default to local 127.0.0.1:27017 or Atlas connection string from env
    MONGODB_URI: str = os.getenv("MONGODB_URI", "mongodb://127.0.0.1:27017")
    MONGODB_DB_NAME: str = os.getenv("MONGODB_DB_NAME", "threat_intelligence")
    
    # AI Engine Keys (Optional - fallback rule-based threat engine activates if missing)
    GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "")
    OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")

    # Demo mode: allow dashboard-injected simulation events for hackathon demos.
    # Set ALLOW_SIMULATION_EVENTS=false in production to reject fake telemetry.
    ALLOW_SIMULATION_EVENTS: bool = os.getenv("ALLOW_SIMULATION_EVENTS", "true").lower() in ("1", "true", "yes")
    ADMIN_PURGE_KEY: str = os.getenv("ADMIN_PURGE_KEY", "kurukshetra-purge-demo")
    
    # CORS Origins (Allow frontend Dashboard & Member 4)
    CORS_ORIGINS: list[str] = [
        "http://localhost:3000",
        "http://localhost:5173",
        "http://localhost:8080",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:5173",
        "*"
    ]
    
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")


settings = Settings()
