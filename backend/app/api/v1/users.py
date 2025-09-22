"""
User Management API endpoints for SecureShieclass UserResponse(BaseModel):
    id: int  # Changed from str to int
    email: str
    username: str  # Added username
    full_name: str
    role: str
    is_active: bool
    is_verified: bool
    avatar_url: Optional[str] = None
    created_at: Optional[datetime] = None
    last_login: Optional[datetime] = Noneditional email/password authentication with enhanced security
"""

import logging
from typing import Dict, Any, Optional
from datetime import datetime, timedelta
from fastapi import APIRouter, HTTPException, Depends, status
from fastapi.security import HTTPBearer
from sqlalchemy.orm import Session
from pydantic import BaseModel, EmailStr, validator
import re

from app.db.database import get_db
from app.db.models import User, UserRole
from app.core.auth import (
    verify_password, get_password_hash, create_access_token,
    get_current_user, verify_token
)
from app.core.config import settings

logger = logging.getLogger(__name__)
router = APIRouter()
security = HTTPBearer()

# Password validation regex - allows common special characters
PASSWORD_REGEX = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*(),.?":{}|<>])[A-Za-z\d!@#$%^&*(),.?":{}|<>]{8,}$')

class UserRegistration(BaseModel):
    email: EmailStr
    password: str
    first_name: str
    last_name: str
    
    @validator('password')
    def validate_password(cls, v):
        if not PASSWORD_REGEX.match(v):
            raise ValueError(
                'Password must be at least 8 characters long and contain: '
                'uppercase letter, lowercase letter, number, and special character'
            )
        return v

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class UserResponse(BaseModel):
    id: int  # Changed from str to int to match database
    email: str
    username: str  # Added username field
    full_name: str
    role: str
    is_active: bool
    is_verified: bool
    avatar_url: Optional[str] = None
    created_at: Optional[datetime] = None  # Made optional since it might be None
    last_login: Optional[datetime] = None

class LoginResponse(BaseModel):
    access_token: str
    token_type: str
    user: UserResponse

class PasswordChange(BaseModel):
    current_password: str
    new_password: str
    confirm_new_password: str
    
    @validator('new_password')
    def validate_new_password(cls, v):
        if not PASSWORD_REGEX.match(v):
            raise ValueError(
                'Password must be at least 8 characters long and contain: '
                'uppercase letter, lowercase letter, number, and special character'
            )
        return v
    
    @validator('confirm_new_password')
    def passwords_match(cls, v, values):
        if 'new_password' in values and v != values['new_password']:
            raise ValueError('Passwords do not match')
        return v

class PasswordReset(BaseModel):
    email: EmailStr

class PasswordResetConfirm(BaseModel):
    token: str
    new_password: str
    confirm_new_password: str
    
    @validator('new_password')
    def validate_new_password(cls, v):
        if not PASSWORD_REGEX.match(v):
            raise ValueError(
                'Password must be at least 8 characters long and contain: '
                'uppercase letter, lowercase letter, number, and special character'
            )
        return v
    
    @validator('confirm_new_password')
    def passwords_match(cls, v, values):
        if 'new_password' in values and v != values['new_password']:
            raise ValueError('Passwords do not match')
        return v

@router.post("/users/register", response_model=LoginResponse)
async def register_user(user_data: UserRegistration, db: Session = Depends(get_db)):
    """
    Register a new user with email and password
    """
    try:
        # Check if user already exists
        existing_user = db.query(User).filter(User.email == user_data.email).first()
        if existing_user:
            raise HTTPException(
                status_code=400,
                detail="User with this email already exists"
            )
        
        # Create new user
        hashed_password = get_password_hash(user_data.password)
        full_name = f"{user_data.first_name} {user_data.last_name}".strip()
        username = user_data.email.split('@')[0]  # Use email prefix as username
        new_user = User(
            email=user_data.email,
            username=username,
            hashed_password=hashed_password,
            first_name=user_data.first_name,
            last_name=user_data.last_name,
            full_name=full_name,
            role=UserRole.VIEWER,  # Default role
            is_active=True,
            is_verified=False  # Email verification required
        )
        
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        
        # Create access token
        access_token = create_access_token(
            data={"sub": new_user.id, "email": new_user.email}
        )
        
        logger.info(f"New user registered: {new_user.email}")
        
        return LoginResponse(
            access_token=access_token,
            token_type="bearer",
            user=UserResponse(
                id=new_user.id,
                email=new_user.email,
                username=new_user.username,
                full_name=new_user.full_name,
                role=new_user.role,
                is_active=new_user.is_active,
                is_verified=new_user.is_verified,
                avatar_url=new_user.avatar_url,
                created_at=new_user.created_at,
                last_login=new_user.last_login
            )
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Registration error: {e}")
        raise HTTPException(
            status_code=500,
            detail="Registration failed"
        )

@router.post("/users/login", response_model=LoginResponse)
async def login_user(login_data: UserLogin, db: Session = Depends(get_db)):
    """
    Authenticate user with email and password
    """
    try:
        # Get user by email
        user = db.query(User).filter(User.email == login_data.email).first()
        if not user:
            raise HTTPException(
                status_code=401,
                detail="Invalid email or password"
            )
        
        # Check if user is active
        if not user.is_active:
            raise HTTPException(
                status_code=401,
                detail="Account is deactivated"
            )
        
        # Verify password
        if not verify_password(login_data.password, user.hashed_password):
            raise HTTPException(
                status_code=401,
                detail="Invalid email or password"
            )
        
        # Update last login
        user.last_login = datetime.utcnow()
        db.commit()
        
        # Create access token
        access_token = create_access_token(
            data={"sub": user.id, "email": user.email}
        )
        
        logger.info(f"User logged in: {user.email}")
        
        return LoginResponse(
            access_token=access_token,
            token_type="bearer",
            user=UserResponse(
                id=user.id,
                email=user.email,
                username=user.username,
                full_name=user.full_name,
                role=user.role,
                is_active=user.is_active,
                is_verified=user.is_verified,
                avatar_url=user.avatar_url,
                created_at=user.created_at,
                last_login=user.last_login
            )
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Login error: {e}")
        raise HTTPException(
            status_code=500,
            detail="Login failed"
        )

@router.get("/users/me", response_model=UserResponse)
async def get_current_user_profile(
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get current authenticated user profile
    """
    user_id = current_user.get("sub")
    user = db.query(User).filter(User.id == user_id).first()
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    return UserResponse(
        id=user.id,
        email=user.email,
        username=user.username,
        full_name=user.full_name,
        role=user.role,
        is_active=user.is_active,
        is_verified=user.is_verified,
        avatar_url=user.avatar_url,
        created_at=user.created_at,
        last_login=user.last_login
    )

@router.put("/users/me", response_model=UserResponse)
async def update_user_profile(
    full_name: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Update current user profile
    """
    user_id = current_user.get("sub")
    user = db.query(User).filter(User.id == user_id).first()
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    user.full_name = full_name
    db.commit()
    db.refresh(user)
    
    return UserResponse(
        id=user.id,
        email=user.email,
        username=user.username,
        full_name=user.full_name,
        role=user.role,
        is_active=user.is_active,
        is_verified=user.is_verified,
        avatar_url=user.avatar_url,
        created_at=user.created_at,
        last_login=user.last_login
    )

@router.post("/users/change-password")
async def change_password(
    password_data: PasswordChange,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Change user password
    """
    user_id = current_user.get("sub")
    user = db.query(User).filter(User.id == user_id).first()
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Verify current password
    if not verify_password(password_data.current_password, user.hashed_password):
        raise HTTPException(
            status_code=400,
            detail="Current password is incorrect"
        )
    
    # Update password
    user.hashed_password = get_password_hash(password_data.new_password)
    db.commit()
    
    logger.info(f"Password changed for user: {user.email}")
    
    return {"message": "Password changed successfully"}

@router.post("/users/reset-password")
async def request_password_reset(
    reset_data: PasswordReset,
    db: Session = Depends(get_db)
):
    """
    Request password reset (sends email with reset token)
    """
    user = db.query(User).filter(User.email == reset_data.email).first()
    
    # Always return success to prevent email enumeration
    if user and user.is_active:
        # In a real implementation, generate a reset token and send email
        # For now, we'll just log it
        logger.info(f"Password reset requested for: {user.email}")
        # TODO: Generate token, save to database, send email
    
    return {"message": "If the email exists, a password reset link has been sent"}

@router.post("/users/reset-password/confirm")
async def confirm_password_reset(
    reset_data: PasswordResetConfirm,
    db: Session = Depends(get_db)
):
    """
    Confirm password reset with token
    """
    # TODO: Verify reset token and update password
    # For now, return an error
    raise HTTPException(
        status_code=501,
        detail="Password reset not implemented yet"
    )

@router.post("/users/logout")
async def logout_user():
    """
    Logout user (client should discard token)
    """
    return {"message": "Successfully logged out"}

@router.get("/users/test")
async def test_users_db(db: Session = Depends(get_db)):
    """Test database connectivity"""
    try:
        count = db.query(User).count()
        return {"status": "ok", "user_count": count}
    except Exception as e:
        logger.error(f"Database test error: {e}")
        return {"status": "error", "error": str(e)}

@router.get("/users/stats")
async def get_user_stats(db: Session = Depends(get_db)):
    """
    Get user registration statistics
    """
    total_users = db.query(User).count()
    active_users = db.query(User).filter(User.is_active == True).count()
    verified_users = db.query(User).filter(User.is_verified == True).count()
    
    # Users by role
    admin_count = db.query(User).filter(User.role == UserRole.ADMIN).count()
    analyst_count = db.query(User).filter(User.role == UserRole.ANALYST).count()
    viewer_count = db.query(User).filter(User.role == UserRole.VIEWER).count()
    
    return {
        "total_users": total_users,
        "active_users": active_users,
        "verified_users": verified_users,
        "users_by_role": {
            "admin": admin_count,
            "analyst": analyst_count,
            "viewer": viewer_count
        }
    }