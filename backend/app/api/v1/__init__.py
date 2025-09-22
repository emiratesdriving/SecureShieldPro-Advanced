"""
API v1 router for SecureShield Pro
"""

from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session
from typing import List

from app.db.database import get_db
from app.db.models import User
from app.api.v1.auth import router as auth_router
from app.api.v1.oauth import router as oauth_router
from app.api.v1.users import router as users_router
from app.api.v1.scans import router as scans_router
from app.api.v1.ai_chat_simple import router as ai_router
# from app.api.v1.assets import router as assets_router  # DISABLED until asset models recreated
from app.api.v1.findings import router as findings_router
from app.api.v1.compliance import router as compliance_router

# Import new security features
try:
    from app.api.v1.ai_remediation import router as ai_remediation_router
    from app.api.v1.threat_hunting import router as threat_hunting_router
    from app.api.v1.soar import router as soar_router
    from app.api.v1.advanced_threat_detection import router as advanced_threat_router
    from app.api.v1.vulnerability_management import router as vulnerability_router
    from app.api.v1.threat_intelligence import router as threat_intelligence_router
    ai_remediation_available = True
    threat_hunting_available = True
    soar_available = True
    advanced_threat_available = True
    vulnerability_management_available = True
    threat_intelligence_available = True
except ImportError:
    ai_remediation_router = None
    threat_hunting_router = None
    soar_router = None
    advanced_threat_router = None
    vulnerability_router = None
    threat_intelligence_router = None
    ai_remediation_available = False
    threat_hunting_available = False
    soar_available = False
    advanced_threat_available = False
    vulnerability_management_available = False
    threat_intelligence_available = False
    soar_router = None
    ai_remediation_available = False
    threat_hunting_available = False
    soar_available = False

# Import stable security features
try:
    from app.api.v1.security_analysis import router as security_analysis_router
    security_analysis_available = True
except ImportError:
    security_analysis_router = None
    security_analysis_available = False

# Import professional security tools
try:
    from app.api.v1.security_tools import router as security_tools_router
    from app.api.v1.reports import router as reports_router
    security_tools_available = True
    reports_available = True
except ImportError:
    security_tools_router = None
    reports_router = None
    security_tools_available = False
    reports_available = False

# Create API router
api_router = APIRouter()

# Include auth routes
api_router.include_router(auth_router, tags=["authentication"])

# Include OAuth routes
api_router.include_router(oauth_router, tags=["oauth"])

# Include user management routes
api_router.include_router(users_router, tags=["users"])

# Include scanning routes
api_router.include_router(scans_router, prefix="/scans", tags=["scanning"])

# Include AI chat routes
api_router.include_router(ai_router, prefix="/ai", tags=["ai-analysis"])

# Include asset management routes - DISABLED until asset models are recreated
# api_router.include_router(assets_router, prefix="/assets", tags=["asset-management"])

# Include findings routes
api_router.include_router(findings_router, tags=["Security Findings"])

# Include compliance routes  
api_router.include_router(compliance_router, tags=["Compliance Reports"])

# Include new security features if available
if ai_remediation_available and ai_remediation_router:
    api_router.include_router(ai_remediation_router, prefix="/ai-remediation", tags=["AI Remediation"])
if threat_hunting_available and threat_hunting_router:
    api_router.include_router(threat_hunting_router, prefix="/threat-hunting", tags=["Threat Hunting"])
if soar_available and soar_router:
    api_router.include_router(soar_router, prefix="/soar", tags=["SOAR Platform"])
if advanced_threat_available and advanced_threat_router:
    api_router.include_router(advanced_threat_router, prefix="/threat-detection", tags=["Advanced Threat Detection"])
if vulnerability_management_available and vulnerability_router:
    api_router.include_router(vulnerability_router, prefix="/vulnerability-management", tags=["Vulnerability Management"])
if threat_intelligence_available and threat_intelligence_router:
    api_router.include_router(threat_intelligence_router, prefix="/threat-intelligence", tags=["Threat Intelligence"])
if security_analysis_available and security_analysis_router:
    api_router.include_router(security_analysis_router, prefix="/analysis", tags=["Enhanced Security Analysis"])

# Include professional security tools
if security_tools_available and security_tools_router:
    api_router.include_router(security_tools_router, prefix="/security-tools", tags=["Professional Security Tools"])
if reports_available and reports_router:
    api_router.include_router(reports_router, prefix="/reports", tags=["Professional Reports"])

@api_router.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "SecureShield Pro API",
        "version": "1.0.0"
    }

@api_router.get("/")
async def root():
    """Root endpoint"""
    return {
        "message": "Welcome to SecureShield Pro API",
        "version": "1.0.0",
        "docs": "/docs"
    }

@api_router.get("/users/me")
async def get_current_user(db: Session = Depends(get_db)):
    """Get current user info - placeholder"""
    return {
        "message": "User endpoint - authentication coming soon"
    }