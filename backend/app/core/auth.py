"""
Enhanced Authentication utilities with security hardening
Implements NIST SP 800-63B guidelines for secure authentication
"""

from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, List
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import HTTPException, status, Request, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from app.core.config import settings
from app.core.security_config import security_config
import secrets
import pyotp
import qrcode
import io
import base64
import re
import hashlib
import time
import logging

# Security logging
auth_logger = logging.getLogger("auth")

# Enhanced password hashing with higher cost factor
pwd_context = CryptContext(
    schemes=["bcrypt"], 
    deprecated="auto",
    bcrypt__rounds=security_config.PASSWORD_SALT_ROUNDS
)

# Token blacklist (in production, use Redis or database)
token_blacklist = set()

# Failed login attempts tracking
failed_attempts = {}
locked_accounts = {}


def validate_password_strength(password: str) -> tuple[bool, List[str]]:
    """
    Validate password strength according to NIST SP 800-63B
    Returns (is_valid, list_of_errors)
    """
    errors = []
    
    # Length check
    if len(password) < security_config.PASSWORD_MIN_LENGTH:
        errors.append(f"Password must be at least {security_config.PASSWORD_MIN_LENGTH} characters long")
    
    if len(password) > security_config.PASSWORD_MAX_LENGTH:
        errors.append(f"Password must not exceed {security_config.PASSWORD_MAX_LENGTH} characters")
    
    # Complexity requirements
    if security_config.PASSWORD_REQUIRE_UPPERCASE and not re.search(r'[A-Z]', password):
        errors.append("Password must contain at least one uppercase letter")
    
    if security_config.PASSWORD_REQUIRE_LOWERCASE and not re.search(r'[a-z]', password):
        errors.append("Password must contain at least one lowercase letter")
    
    if security_config.PASSWORD_REQUIRE_NUMBERS and not re.search(r'\d', password):
        errors.append("Password must contain at least one number")
    
    if security_config.PASSWORD_REQUIRE_SPECIAL_CHARS and not re.search(r'[!@#$%^&*()_+\-=\[\]{};:"\\|,.<>\?]', password):
        errors.append("Password must contain at least one special character")
    
    # Common password patterns (basic check)
    common_patterns = [
        "password", "123456", "qwerty", "admin", "letmein", 
        "welcome", "monkey", "dragon", "master", "shadow"
    ]
    
    password_lower = password.lower()
    for pattern in common_patterns:
        if pattern in password_lower:
            errors.append("Password contains common patterns and is not secure")
            break
    
    # Sequential characters check
    if re.search(r'(012|123|234|345|456|567|678|789|890|abc|bcd|cde|def)', password_lower):
        errors.append("Password should not contain sequential characters")
    
    return len(errors) == 0, errors


def check_account_lockout(username: str) -> bool:
    """Check if account is locked due to failed attempts"""
    if username in locked_accounts:
        lock_time = locked_accounts[username]
        if time.time() - lock_time < security_config.ACCOUNT_LOCKOUT_DURATION_MINUTES * 60:
            return True
        else:
            # Unlock account after lockout period
            del locked_accounts[username]
            if username in failed_attempts:
                del failed_attempts[username]
    return False


def record_failed_login(username: str) -> bool:
    """
    Record failed login attempt and lock account if necessary
    Returns True if account should be locked
    """
    current_time = time.time()
    
    if username not in failed_attempts:
        failed_attempts[username] = []
    
    # Remove old attempts (older than 1 hour)
    failed_attempts[username] = [
        attempt_time for attempt_time in failed_attempts[username]
        if current_time - attempt_time < 3600
    ]
    
    # Add current failed attempt
    failed_attempts[username].append(current_time)
    
    # Check if account should be locked
    if len(failed_attempts[username]) >= security_config.MAX_LOGIN_ATTEMPTS:
        locked_accounts[username] = current_time
        auth_logger.warning(f"Account locked due to multiple failed attempts: {username}")
        return True
    
    return False


def is_token_blacklisted(token: str) -> bool:
    """Check if token is blacklisted"""
    # Create token hash for storage efficiency
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    return token_hash in token_blacklist


def blacklist_token(token: str):
    """Add token to blacklist"""
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    token_blacklist.add(token_hash)
    auth_logger.info(f"Token blacklisted: {token_hash[:16]}...")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash with timing attack protection"""
    # Add small random delay to prevent timing attacks
    time.sleep(secrets.randbelow(100) / 10000)  # 0-10ms random delay
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """Generate password hash with enhanced security"""
    # Validate password strength first
    is_valid, errors = validate_password_strength(password)
    if not is_valid:
        raise ValueError(f"Password does not meet security requirements: {', '.join(errors)}")
    
    return pwd_context.hash(password)


def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """Create JWT access token with enhanced security"""
    to_encode = data.copy()
    
    # Add security claims
    current_time = datetime.now(timezone.utc)
    jti = secrets.token_urlsafe(32)  # Unique token ID
    
    if expires_delta:
        expire = current_time + expires_delta
    else:
        expire = current_time + timedelta(minutes=security_config.JWT_ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({
        "exp": expire,
        "iat": current_time,
        "nbf": current_time,
        "jti": jti,
        "type": "access",
        "iss": "SecureShield-Pro",
        "aud": "api"
    })
    
    encoded_jwt = jwt.encode(to_encode, security_config.JWT_SECRET_KEY, algorithm=security_config.JWT_ALGORITHM)
    
    # Log token creation for audit
    auth_logger.info(f"Access token created for user: {data.get('sub', 'unknown')}")
    
    return encoded_jwt


def create_refresh_token(data: Dict[str, Any]) -> str:
    """Create JWT refresh token"""
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire, "type": "refresh"})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt


def verify_token(token: str, token_type: str = "access") -> Dict[str, Any]:
    """Verify and decode JWT token"""
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        
        # Check token type
        if payload.get("type") != token_type:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid token type. Expected {token_type}",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        # Check expiration
        exp = payload.get("exp")
        if exp is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token missing expiration",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        if datetime.fromtimestamp(exp, tz=timezone.utc) < datetime.now(timezone.utc):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token expired",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        return payload
        
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )


def generate_otp_code() -> str:
    """Generate 6-digit OTP code"""
    return secrets.randbelow(1000000).__str__().zfill(6)


def generate_2fa_secret() -> str:
    """Generate 2FA secret key"""
    return pyotp.random_base32()


def generate_2fa_qr_code(user_email: str, secret: str) -> str:
    """Generate 2FA QR code as base64 image"""
    totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=user_email,
        issuer_name=settings.APP_NAME
    )
    
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(totp_uri)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    
    # Convert to base64
    buffer = io.BytesIO()
    img.save(buffer, format='PNG')
    img_str = base64.b64encode(buffer.getvalue()).decode()
    
    return f"data:image/png;base64,{img_str}"


def verify_2fa_code(secret: str, code: str) -> bool:
    """Verify 2FA TOTP code"""
    try:
        totp = pyotp.TOTP(secret)
        return totp.verify(code, valid_window=1)  # Allow 1 window tolerance
    except Exception:
        return False


def create_password_reset_token(email: str) -> str:
    """Create password reset token"""
    data = {"email": email, "type": "password_reset"}
    expire = datetime.now(timezone.utc) + timedelta(hours=1)  # 1 hour expiry
    data.update({"exp": expire})
    return jwt.encode(data, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def verify_password_reset_token(token: str) -> Optional[str]:
    """Verify password reset token and return email"""
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        
        if payload.get("type") != "password_reset":
            return None
        
        email = payload.get("email")
        if email is None:
            return None
        
        return email
        
    except JWTError:
        return None


def generate_secure_random_string(length: int = 32) -> str:
    """Generate secure random string for secrets"""
    return secrets.token_urlsafe(length)


def validate_password_strength(password: str) -> tuple[bool, str]:
    """
    Validate password strength
    Returns (is_valid, error_message)
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    
    if not any(c.islower() for c in password):
        return False, "Password must contain at least one lowercase letter"
    
    if not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter"
    
    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one digit"
    
    if not any(c in "!@#$%^&*()_+-=[]{}|;':\",./<>?" for c in password):
        return False, "Password must contain at least one special character"
    
    return True, "Password is strong"


async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(HTTPBearer())) -> Dict[str, Any]:
    """Get current authenticated user from JWT token"""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        # Extract token from Bearer format
        token_str = credentials.credentials
        
        # Check if token is blacklisted
        if is_token_blacklisted(token_str):
            raise credentials_exception
        
        # Decode JWT token
        payload = jwt.decode(
            token_str, 
            security_config.JWT_SECRET_KEY, 
            algorithms=[security_config.JWT_ALGORITHM]
        )
        
        username: Optional[str] = payload.get("sub")
        if username is None:
            raise credentials_exception
            
        token_type: Optional[str] = payload.get("type")
        if token_type != "access":
            raise credentials_exception
            
        # Return user info from token
        return {
            "username": username,
            "token_type": token_type,
            "exp": payload.get("exp")
        }
            
    except JWTError:
        raise credentials_exception


class SecurityHeaders:
    """Security headers for API responses"""
    
    @staticmethod
    def get_headers() -> Dict[str, str]:
        """Get security headers"""
        return {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Content-Security-Policy": "default-src 'self'",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "geolocation=(), microphone=(), camera=()"
        }