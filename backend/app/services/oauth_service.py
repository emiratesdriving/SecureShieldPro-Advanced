"""
OAuth Authentication Service for SecureShield Pro
Supports Google and GitHub OAuth providers
"""

import logging
from typing import Optional, Dict, Any
from datetime import datetime, timedelta
import httpx
import secrets
from urllib.parse import urlencode
from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.models import User, UserRole
from app.core.auth import create_access_token

logger = logging.getLogger(__name__)

class OAuthProvider:
    """Base OAuth provider class"""
    
    def __init__(self, client_id: str, client_secret: str):
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = f"{settings.FRONTEND_URL}/auth/callback"
    
    def get_auth_url(self, state: str) -> str:
        """Get authorization URL"""
        raise NotImplementedError
    
    async def get_access_token(self, code: str, state: str) -> str:
        """Exchange code for access token"""
        raise NotImplementedError
    
    async def get_user_info(self, access_token: str) -> Dict[str, Any]:
        """Get user information using access token"""
        raise NotImplementedError

class GoogleOAuth(OAuthProvider):
    """Google OAuth provider"""
    
    def __init__(self):
        super().__init__(
            client_id=settings.GOOGLE_CLIENT_ID,
            client_secret=settings.GOOGLE_CLIENT_SECRET
        )
        self.auth_url = "https://accounts.google.com/o/oauth2/v2/auth"
        self.token_url = "https://oauth2.googleapis.com/token"
        self.user_info_url = "https://www.googleapis.com/oauth2/v2/userinfo"
        self.scope = "openid email profile"
    
    def get_auth_url(self, state: str) -> str:
        """Get Google authorization URL"""
        params = {
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "scope": self.scope,
            "response_type": "code",
            "state": state,
            "access_type": "offline",
            "prompt": "consent"
        }
        return f"{self.auth_url}?{urlencode(params)}"
    
    async def get_access_token(self, code: str, state: str) -> str:
        """Exchange code for Google access token"""
        async with httpx.AsyncClient() as client:
            response = await client.post(
                self.token_url,
                data={
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "code": code,
                    "grant_type": "authorization_code",
                    "redirect_uri": self.redirect_uri,
                }
            )
            response.raise_for_status()
            token_data = response.json()
            return token_data["access_token"]
    
    async def get_user_info(self, access_token: str) -> Dict[str, Any]:
        """Get Google user information"""
        async with httpx.AsyncClient() as client:
            response = await client.get(
                self.user_info_url,
                headers={"Authorization": f"Bearer {access_token}"}
            )
            response.raise_for_status()
            user_data = response.json()
            
            return {
                "id": user_data["id"],
                "email": user_data["email"],
                "name": user_data["name"],
                "avatar_url": user_data.get("picture"),
                "verified": user_data.get("verified_email", False)
            }

class GitHubOAuth(OAuthProvider):
    """GitHub OAuth provider"""
    
    def __init__(self):
        super().__init__(
            client_id=settings.GITHUB_CLIENT_ID,
            client_secret=settings.GITHUB_CLIENT_SECRET
        )
        self.auth_url = "https://github.com/login/oauth/authorize"
        self.token_url = "https://github.com/login/oauth/access_token"
        self.user_info_url = "https://api.github.com/user"
        self.scope = "user:email"
    
    def get_auth_url(self, state: str) -> str:
        """Get GitHub authorization URL"""
        params = {
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "scope": self.scope,
            "state": state,
        }
        return f"{self.auth_url}?{urlencode(params)}"
    
    async def get_access_token(self, code: str, state: str) -> str:
        """Exchange code for GitHub access token"""
        async with httpx.AsyncClient() as client:
            response = await client.post(
                self.token_url,
                data={
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "code": code,
                },
                headers={"Accept": "application/json"}
            )
            response.raise_for_status()
            token_data = response.json()
            return token_data["access_token"]
    
    async def get_user_info(self, access_token: str) -> Dict[str, Any]:
        """Get GitHub user information"""
        async with httpx.AsyncClient() as client:
            # Get user profile
            response = await client.get(
                self.user_info_url,
                headers={"Authorization": f"Bearer {access_token}"}
            )
            response.raise_for_status()
            user_data = response.json()
            
            # Get primary email
            email_response = await client.get(
                "https://api.github.com/user/emails",
                headers={"Authorization": f"Bearer {access_token}"}
            )
            email_response.raise_for_status()
            emails = email_response.json()
            
            primary_email = None
            for email in emails:
                if email.get("primary", False):
                    primary_email = email["email"]
                    break
            
            return {
                "id": str(user_data["id"]),
                "email": primary_email or user_data.get("email"),
                "name": user_data.get("name") or user_data.get("login"),
                "avatar_url": user_data.get("avatar_url"),
                "verified": True  # GitHub emails are verified
            }

class OAuthService:
    """OAuth service manager"""
    
    def __init__(self):
        self.providers = {}
        self._initialized = False
        
        # Store OAuth states temporarily (in production, use Redis)
        self._states = {}
    
    def _ensure_initialized(self):
        """Lazy initialization of OAuth providers"""
        if self._initialized:
            return
            
        if settings.GOOGLE_CLIENT_ID and settings.GOOGLE_CLIENT_SECRET:
            self.providers["google"] = GoogleOAuth()
        if settings.GITHUB_CLIENT_ID and settings.GITHUB_CLIENT_SECRET:
            self.providers["github"] = GitHubOAuth()
        
        self._initialized = True
    
    def generate_state(self) -> str:
        """Generate secure state parameter"""
        state = secrets.token_urlsafe(32)
        self._states[state] = datetime.utcnow()
        return state
    
    def validate_state(self, state: str) -> bool:
        """Validate OAuth state parameter"""
        if state not in self._states:
            return False
        
        # Check if state is not expired (15 minutes)
        created_at = self._states[state]
        if datetime.utcnow() - created_at > timedelta(minutes=15):
            del self._states[state]
            return False
        
        # Remove used state
        del self._states[state]
        return True
    
    def get_provider(self, provider_name: str) -> OAuthProvider:
        """Get OAuth provider by name"""
        self._ensure_initialized()
        if provider_name not in self.providers:
            raise HTTPException(
                status_code=400,
                detail=f"OAuth provider '{provider_name}' not configured"
            )
        return self.providers[provider_name]
    
    def get_auth_url(self, provider_name: str) -> Dict[str, str]:
        """Get authorization URL for provider"""
        self._ensure_initialized()
        provider = self.get_provider(provider_name)
        state = self.generate_state()
        auth_url = provider.get_auth_url(state)
        
        return {
            "auth_url": auth_url,
            "state": state
        }
    
    async def handle_callback(
        self,
        provider_name: str,
        code: str,
        state: str,
        db: Session
    ) -> Dict[str, Any]:
        """Handle OAuth callback and create/update user"""
        
        # Validate state
        if not self.validate_state(state):
            raise HTTPException(status_code=400, detail="Invalid or expired state")
        
        provider = self.get_provider(provider_name)
        
        try:
            # Exchange code for access token
            access_token = await provider.get_access_token(code, state)
            
            # Get user information
            user_info = await provider.get_user_info(access_token)
            
            # Create or update user
            user = await self._create_or_update_user(
                provider_name, user_info, db
            )
            
            # Generate JWT token
            access_token_jwt = create_access_token(
                data={"sub": user.email, "user_id": user.id}
            )
            
            return {
                "access_token": access_token_jwt,
                "token_type": "bearer",
                "user": {
                    "id": user.id,
                    "email": user.email,
                    "full_name": user.full_name,
                    "role": user.role.value,
                    "avatar_url": user.avatar_url
                }
            }
            
        except Exception as e:
            logger.error(f"OAuth callback error: {e}")
            raise HTTPException(
                status_code=400,
                detail="OAuth authentication failed"
            )
    
    async def _create_or_update_user(
        self,
        provider_name: str,
        user_info: Dict[str, Any],
        db: Session
    ) -> User:
        """Create or update user from OAuth data"""
        
        # Check if user exists by email
        user = db.query(User).filter(User.email == user_info["email"]).first()
        
        if user:
            # Update existing user
            if provider_name == "google":
                user.google_id = user_info["id"]
            elif provider_name == "github":
                user.github_id = user_info["id"]
            
            user.avatar_url = user_info.get("avatar_url")
            user.is_verified = user_info.get("verified", True)
            user.last_login = datetime.utcnow()
        else:
            # Create new user
            user = User(
                email=user_info["email"],
                full_name=user_info["name"],
                role=UserRole.VIEWER,  # Default role
                is_active=True,
                is_verified=user_info.get("verified", True),
                avatar_url=user_info.get("avatar_url"),
                last_login=datetime.utcnow()
            )
            
            if provider_name == "google":
                user.google_id = user_info["id"]
            elif provider_name == "github":
                user.github_id = user_info["id"]
            
            db.add(user)
        
        db.commit()
        db.refresh(user)
        return user

# Global OAuth service instance
oauth_service = OAuthService()