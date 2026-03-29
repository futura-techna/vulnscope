"""
VulnScope - FastAPI Application
Main application file for VulnScope REST API
"""

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from contextlib import asynccontextmanager
import logging

from .routes import router
from .auth_routes import router as auth_router
from .websocket import ws_manager
from ..config.settings import get_settings


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager"""
    # Startup
    logger.info("Starting VulnScope API...")
    
    try:
        settings = get_settings()
        logger.info(f"Environment: {settings.environment}")
        logger.info(f"Debug mode: {settings.debug}")
        logger.info(f"Database URL configured: {bool(settings.database.url)}")
        logger.info(f"Redis URL configured: {bool(settings.redis.url)}")
        logger.info(f"Secret key configured: {bool(settings.secret_key)}")
        
        # Initialize database
        try:
            from ..database import init_db
            logger.info("Initializing database...")
            await init_db()
            logger.info("Database initialized successfully")
        except Exception as db_error:
            logger.warning(f"Database initialization failed (using in-memory storage): {db_error}")
        
        # Test Redis connection if configured
        if settings.redis.url:
            try:
                import redis
                params = settings.redis.get_connection_params()
                logger.info(f"Testing Redis connection to {params['host']}:{params['port']}...")
                r = redis.Redis(
                    host=params['host'],
                    port=params['port'],
                    db=params['db'],
                    password=params['password'],
                    socket_connect_timeout=5
                )
                r.ping()
                logger.info("Redis connection successful")
            except Exception as e:
                logger.warning(f"Redis connection failed (rate limiting will be disabled): {e}")
        else:
            logger.info("Redis not configured - rate limiting will be disabled")
            
    except Exception as e:
        logger.error(f"Error during startup: {e}")
        # Don't raise - let the app start anyway
    
    yield
    
    # Shutdown
    logger.info("Shutting down VulnScope API...")


# Create FastAPI application
app = FastAPI(
    title="VulnScope API",
    description="API for VulnScope - Dynamic Application Security Testing Platform",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan,
)

# Add middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(GZipMiddleware, minimum_size=1000)


# Include routers
app.include_router(router, prefix="/api/v1", tags=["v1"])
app.include_router(auth_router)


# Health check endpoint
@app.get("/health", tags=["health"])
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "vulnscope-api",
        "version": "1.0.0"
    }


# WebSocket endpoint for real-time scan updates
@app.websocket("/ws/scans/{scan_id}")
async def websocket_endpoint(websocket: WebSocket, scan_id: str):
    """
    WebSocket endpoint for real-time scan updates
    
    Provides real-time notifications for:
    - Scan progress
    - New findings
    - Endpoints discovered
    - Scan completion
    """
    await ws_manager.connect(websocket)
    try:
        while True:
            # Keep connection alive, receive any client messages if needed
            data = await websocket.receive_text()
            # You could handle ping/pong or client commands here
            # For now, just acknowledge receipt
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"WebSocket error for scan {scan_id}: {e}")
        ws_manager.disconnect(websocket)


# Root endpoint
@app.get("/", tags=["root"])
async def root():
    """Root endpoint"""
    return {
        "name": "VulnScope API",
        "version": "1.0.0",
        "docs": "/docs",
        "health": "/health"
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
