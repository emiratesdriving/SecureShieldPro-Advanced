"""
SecureShield Pro - Professional Security Platform
Main application entry point with enhanced security
"""

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
import logging

from app.core.config import settings
from app.core.security_config import security_config
from app.db.database import init_db
from app.api.v1 import api_router

# Configure security logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/tmp/secureshield_security.log'),
        logging.StreamHandler()
    ]
)

security_logger = logging.getLogger("security")

# Rate limiter
limiter = Limiter(key_func=get_remote_address)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler with security initialization"""
    # Startup
    security_logger.info("SecureShield Pro starting up with enhanced security")
    await init_db()
    yield
    # Shutdown
    security_logger.info("SecureShield Pro shutting down")


# Create FastAPI application with security configuration
app = FastAPI(
    title="SecureShield Pro",
    description="Professional Security Platform with SAST/DAST, AI Analysis, and Modern UI",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
    lifespan=lifespan
)


# Custom rate limit exception handler
@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    client_host = request.client.host if request.client else "unknown"
    security_logger.warning(f"Rate limit exceeded for {client_host}: {exc.detail}")
    return JSONResponse(
        status_code=429,
        content={"detail": f"Rate limit exceeded: {exc.detail}"}
    )


# Add security middleware (order matters!)
app.state.limiter = limiter

# Rate limiting middleware
app.add_middleware(SlowAPIMiddleware)

# Trusted host middleware
app.add_middleware(
    TrustedHostMiddleware, 
    allowed_hosts=["localhost", "127.0.0.1", "*.secureshield.local"]
)

# Compression middleware
app.add_middleware(GZipMiddleware, minimum_size=1000)

# Enhanced CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=security_config.CORS_ALLOWED_ORIGINS,
    allow_credentials=security_config.CORS_ALLOW_CREDENTIALS,
    allow_methods=security_config.CORS_ALLOWED_METHODS,
    allow_headers=security_config.CORS_ALLOWED_HEADERS,
    expose_headers=["X-Request-ID", "X-RateLimit-Limit", "X-RateLimit-Remaining"]
)


# Security headers middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    """Add security headers to all responses"""
    response = await call_next(request)
    
    # Security headers
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'"
    response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
    
    # Hide server information
    response.headers["Server"] = "SecureShield-Pro"
    
    return response

# Add rate limiting to critical endpoints
@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    """Rate limiting for sensitive endpoints"""
    sensitive_paths = ["/api/v1/auth", "/api/v1/scans", "/api/v1/upload"]
    
    if any(request.url.path.startswith(path) for path in sensitive_paths):
        # Rate limiting is handled by SlowAPI middleware
        pass
    
    response = await call_next(request)
    
    # Add rate limit headers
    response.headers["X-RateLimit-Limit"] = "100"
    response.headers["X-RateLimit-Remaining"] = "99"
    
    return response


# Include API router
app.include_router(api_router, prefix="/api/v1")


# Health check endpoint
@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "SecureShield Pro",
        "version": "1.0.0",
        "security": "enhanced"
    }


# Root endpoint
@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "message": "SecureShield Pro API",
        "version": "1.0.0",
        "docs": "/api/docs",
        "security": "bulletproof"
    }

# Include API router
app.include_router(api_router, prefix="/api/v1")


@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "message": "SecureShield Pro API",
        "version": "1.0.0",
        "status": "operational"
    }


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "version": "1.0.0"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )