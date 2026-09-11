import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.database import connect_to_mongo, close_mongo_connection
from app.routes import router as api_router
from app.websocket import ws_manager

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("threat_intel.main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: connect to MongoDB
    logger.info("Initializing Threat Intelligence Backend...")
    await connect_to_mongo()
    
    # Production Mode: Real honeypot telemetry only, no automated mock seeding

    yield
    # Shutdown: close connections
    logger.info("Shutting down Threat Intelligence Backend...")
    await close_mongo_connection()


app = FastAPI(
    title=settings.PROJECT_NAME,
    description="Adaptive Cyber Deception & Threat Intelligence Platform Backend (Member 3)",
    version="1.0.0",
    lifespan=lifespan
)

# CORS Middleware configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount REST API endpoints
app.include_router(api_router, prefix=settings.API_V1_STR)


# Live WebSocket Endpoint for Dashboard
@app.websocket("/ws/attacks")
async def websocket_attacks(websocket: WebSocket):
    """Real-time live telemetry and alerts stream for the Dashboard (Member 4)."""
    await ws_manager.connect(websocket)
    try:
        await websocket.send_json({
            "type": "CONNECTION_ESTABLISHED",
            "message": "Subscribed to live threat intelligence stream"
        })
        while True:
            # Keep-alive receive loop
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception as e:
        logger.warning(f"WebSocket client closed with exception: {e}")
        ws_manager.disconnect(websocket)


@app.get("/")
async def root():
    return {
        "status": "online",
        "service": settings.PROJECT_NAME,
        "database": "MongoDB",
        "docs_url": "/docs",
        "websocket_endpoint": "/ws/attacks"
    }


@app.get("/health")
async def health_check():
    return {"status": "healthy", "database": "connected"}
