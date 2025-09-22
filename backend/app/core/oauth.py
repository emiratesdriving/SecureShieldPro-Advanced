"""
OAuth authentication providers (Google, GitHub)
"""

from typing import Optional, Dict, Any
import httpx
from fastapi import HTTPException, status
from app.core.config import settings
import secrets
import base64
import urllib.parse


class OAuthProvider:
    """Base OAuth provider class"""
    
    def __init__(self, client_id: str, client_secret: str):
        self.client_id = client_id
        self.client_secret = client_secret
    
    def get_authorization_url(self, state: str, redirect_uri: str) -> str:
        """Get OAuth authorization URL"""
        raise NotImplementedError
    
    async def exchange_code_for_token(self, code: str, redirect_uri: str) -> Dict[str, Any]:
        """Exchange authorization code for access token"""
        raise NotImplementedError
    
    async def get_user_info(self, access_token: str) -> Dict[str, Any]:
        """Get user information from OAuth provider"""
        raise NotImplementedError


class GoogleOAuth(OAuthProvider):
    """Google OAuth provider"""
    
    def __init__(self):
        super().__init__(
            client_id=settings.GOOGLE_CLIENT_ID,
            client_secret=settings.GOOGLE_CLIENT_SECRET
        )
        self.auth_url = "https://accounts.google.com/o/oauth2/auth"
        self.token_url = "https://oauth2.googleapis.com/token"
        self.user_info_url = "https://www.googleapis.com/oauth2/v2/userinfo"
        self.scope = "openid email profile"
    
    def get_authorization_url(self, state: str, redirect_uri: str) -> str:
        """Get Google OAuth authorization URL"""
        params = {
            "client_id": self.client_id,
            "redirect_uri": redirect_uri,
            "scope": self.scope,
            "response_type": "code",
            "state": state,
            "access_type": "offline",
            "prompt": "consent"
        }
        
        query_string = urllib.parse.urlencode(params)
        return f"{self.auth_url}?{query_string}"
    
    async def exchange_code_for_token(self, code: str, redirect_uri: str) -> Dict[str, Any]:
        """Exchange authorization code for Google access token"""
        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": redirect_uri
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.post(self.token_url, data=data)
            
            if response.status_code != 200:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Failed to exchange code for token"
                )
            
            return response.json()
    
    async def get_user_info(self, access_token: str) -> Dict[str, Any]:
        """Get user information from Google"""
        headers = {"Authorization": f"Bearer {access_token}"}
        
        async with httpx.AsyncClient() as client:
            response = await client.get(self.user_info_url, headers=headers)
            
            if response.status_code != 200:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Failed to get user information"
                )
            
            return response.json()


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
    
    def get_authorization_url(self, state: str, redirect_uri: str) -> str:
        """Get GitHub OAuth authorization URL"""
        params = {
            "client_id": self.client_id,
            "redirect_uri": redirect_uri,
            "scope": self.scope,
            "state": state,
            "allow_signup": "true"
        }
        
        query_string = urllib.parse.urlencode(params)
        return f"{self.auth_url}?{query_string}"
    
    async def exchange_code_for_token(self, code: str, redirect_uri: str) -> Dict[str, Any]:
        """Exchange authorization code for GitHub access token"""
        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "code": code,
            "redirect_uri": redirect_uri
        }
        
        headers = {"Accept": "application/json"}
        
        async with httpx.AsyncClient() as client:
            response = await client.post(self.token_url, data=data, headers=headers)
            
            if response.status_code != 200:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Failed to exchange code for token"
                )
            
            return response.json()
    
    async def get_user_info(self, access_token: str) -> Dict[str, Any]:
        """Get user information from GitHub"""
        headers = {
            "Authorization": f"token {access_token}",
            "Accept": "application/vnd.github.v3+json"
        }
        
        async with httpx.AsyncClient() as client:
            # Get user profile
            user_response = await client.get(self.user_info_url, headers=headers)
            
            if user_response.status_code != 200:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Failed to get user information"
                )
            
            user_data = user_response.json()
            
            # Get user email (if not public)
            if not user_data.get("email"):
                email_response = await client.get(
                    "https://api.github.com/user/emails",
                    headers=headers
                )
                
                if email_response.status_code == 200:
                    emails = email_response.json()
                    primary_email = next(
                        (email for email in emails if email.get("primary", False)),
                        None
                    )
                    if primary_email:
                        user_data["email"] = primary_email["email"]
            
            return user_data


def generate_oauth_state() -> str:
    """Generate secure OAuth state parameter"""
    return secrets.token_urlsafe(32)


def validate_oauth_state(provided_state: str, stored_state: str) -> bool:
    """Validate OAuth state parameter"""
    return secrets.compare_digest(provided_state, stored_state)


# OAuth provider instances
google_oauth = GoogleOAuth() if settings.GOOGLE_CLIENT_ID and settings.GOOGLE_CLIENT_SECRET else None
github_oauth = GitHubOAuth() if settings.GITHUB_CLIENT_ID and settings.GITHUB_CLIENT_SECRET else None


def get_oauth_provider(provider: str) -> Optional[OAuthProvider]:
    """Get OAuth provider instance"""
    providers = {
        "google": google_oauth,
        "github": github_oauth
    }
    return providers.get(provider)