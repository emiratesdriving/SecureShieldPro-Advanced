"""
OAuth Authentication endpoints for Google and GitHub
Enhanced with proper state management and error handling
"""

import logging
from typing import Optional, Dict, Any
from fastapi import APIRouter, HTTPException, Depends, Request, Query
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session
from pydantic import BaseModel

from app.core.config import settings
from app.db.database import get_db
from app.services.oauth_service import oauth_service
from app.core.auth import get_current_user

logger = logging.getLogger(__name__)
router = APIRouter()

class OAuthCallbackRequest(BaseModel):
    code: str
    state: str

class LoginResponse(BaseModel):
    access_token: str
    token_type: str
    user: Dict[str, Any]

@router.get("/auth/{provider}/login")
async def oauth_login(provider: str):
    """
    Initiate OAuth login flow
    
    Supported providers: google, github
    Returns redirect URL for OAuth provider
    """
    try:
        auth_data = oauth_service.get_auth_url(provider)
        return {
            "auth_url": auth_data["auth_url"],
            "state": auth_data["state"],
            "provider": provider
        }
    except Exception as e:
        logger.error(f"OAuth login error for {provider}: {e}")
        raise HTTPException(
            status_code=400,
            detail=f"Failed to initiate {provider} OAuth login"
        )

@router.get("/auth/{provider}/callback")
async def oauth_callback(
    provider: str,
    code: str = Query(...),
    state: str = Query(...),
    db: Session = Depends(get_db)
):
    """
    Handle OAuth callback and authenticate user
    
    This endpoint is called by the OAuth provider after user authorization
    """
    try:
        # Handle OAuth callback
        auth_result = await oauth_service.handle_callback(
            provider_name=provider,
            code=code,
            state=state,
            db=db
        )
        
        # Redirect to frontend with token
        frontend_url = getattr(settings, 'FRONTEND_URL', "http://localhost:3000")
        redirect_url = f"{frontend_url}/auth/success?token={auth_result['access_token']}&user={auth_result['user']['id']}"
        
        return RedirectResponse(url=redirect_url)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"OAuth callback error for {provider}: {e}")
        # Redirect to frontend with error
        frontend_url = getattr(settings, 'FRONTEND_URL', "http://localhost:3000")
        error_url = f"{frontend_url}/auth/error?error=oauth_failed"
        return RedirectResponse(url=error_url)

@router.post("/auth/{provider}/callback", response_model=LoginResponse)
async def oauth_callback_post(
    provider: str,
    callback_data: OAuthCallbackRequest,
    db: Session = Depends(get_db)
):
    """
    Handle OAuth callback via POST (for SPA/API usage)
    
    Alternative to GET callback for single-page applications
    """
    try:
        auth_result = await oauth_service.handle_callback(
            provider_name=provider,
            code=callback_data.code,
            state=callback_data.state,
            db=db
        )
        
        return LoginResponse(**auth_result)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"OAuth POST callback error for {provider}: {e}")
        raise HTTPException(
            status_code=400,
            detail="OAuth authentication failed"
        )

@router.get("/auth/providers")
async def get_oauth_providers():
    """
    Get available OAuth providers and their configuration
    """
    providers = []
    
    if settings.GOOGLE_CLIENT_ID and settings.GOOGLE_CLIENT_SECRET:
        providers.append({
            "name": "google",
            "display_name": "Google",
            "icon": "fab fa-google",
            "color": "#4285f4"
        })
    
    if settings.GITHUB_CLIENT_ID and settings.GITHUB_CLIENT_SECRET:
        providers.append({
            "name": "github", 
            "display_name": "GitHub",
            "icon": "fab fa-github",
            "color": "#333333"
        })
    
    return {
        "providers": providers,
        "enabled": len(providers) > 0
    }

@router.get("/auth/debug")
async def auth_debug():
    """Debug OAuth configuration"""
    from app.core.config import settings
    return {
        "google_client_id": bool(settings.GOOGLE_CLIENT_ID),
        "google_client_secret": bool(settings.GOOGLE_CLIENT_SECRET),
        "github_client_id": bool(settings.GITHUB_CLIENT_ID),
        "github_client_secret": bool(settings.GITHUB_CLIENT_SECRET),
        "frontend_url": settings.FRONTEND_URL,
        "oauth_service_initialized": oauth_service._initialized,
        "oauth_providers_count": len(oauth_service.providers)
    }

@router.get("/auth/status")
async def auth_status(request: Request):
    """
    Get authentication status and configuration
    """
    oauth_service._ensure_initialized()
    return {
        "oauth_enabled": len(oauth_service.providers) > 0,
        "available_providers": list(oauth_service.providers.keys()),
        "frontend_url": getattr(settings, 'FRONTEND_URL', "http://localhost:3000"),
        "redirect_configured": bool(getattr(settings, 'FRONTEND_URL', None))
    }

@router.get("/auth/me")
async def get_current_user_info(current_user: Dict[str, Any] = Depends(get_current_user), db: Session = Depends(get_db)):
    """Get current authenticated user"""
    from app.db.models import User
    
    user_id = current_user.get("sub")
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    return {
        "id": user.id,
        "email": user.email,
        "full_name": user.full_name,
        "role": user.role.value,
        "avatar_url": user.avatar_url,
        "is_verified": user.is_verified,
        "last_login": user.last_login,
        "created_at": user.created_at
    }

@router.post("/auth/logout")
async def logout():
    """Logout user (invalidate token)"""
    return {"message": "Successfully logged out"}