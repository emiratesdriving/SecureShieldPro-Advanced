"""
Advanced Security Middleware for SecureShield Pro
Implements comprehensive security controls following OWASP best practices
"""
import time
import hashlib
import secrets
from typing import Optional, Dict, Any
from fastapi import Request, Response, HTTPException
from fastapi.middleware.base import BaseHTTPMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
import bleach
import re
from datetime import datetime, timedelta
import logging

# Configure security logging
security_logger = logging.getLogger("security")
security_logger.setLevel(logging.INFO)

# Rate limiter configuration
limiter = Limiter(key_func=get_remote_address)

class SecurityHeaders:
    """Secure HTTP headers following OWASP recommendations"""
    
    @staticmethod
    def get_security_headers() -> Dict[str, str]:
        nonce = secrets.token_urlsafe(32)
        return {
            # Content Security Policy with strict nonce-based CSP
            "Content-Security-Policy": f"default-src 'self'; script-src 'self' 'nonce-{nonce}'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self'; frame-ancestors 'none';",
            
            # Prevent XSS attacks
            "X-XSS-Protection": "1; mode=block",
            
            # Prevent MIME type sniffing
            "X-Content-Type-Options": "nosniff",
            
            # Prevent clickjacking
            "X-Frame-Options": "DENY",
            
            # Force HTTPS
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
            
            # Referrer policy
            "Referrer-Policy": "strict-origin-when-cross-origin",
            
            # Permissions policy
            "Permissions-Policy": "geolocation=(), camera=(), microphone=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()",
            
            # Cross-Origin policies
            "Cross-Origin-Embedder-Policy": "require-corp",
            "Cross-Origin-Opener-Policy": "same-origin",
            "Cross-Origin-Resource-Policy": "same-origin",
            
            # Server header removal
            "Server": "SecureShield-Pro",
            
            # Cache control for sensitive data
            "Cache-Control": "no-store, no-cache, must-revalidate, proxy-revalidate",
            "Pragma": "no-cache",
            "Expires": "0"
        }

class InputSanitizer:
    """Advanced input sanitization and validation"""
    
    # Common attack patterns
    SQL_INJECTION_PATTERNS = [
        r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION)\b)",
        r"(\'|(\'\')|(\-\-)|(\%27)|(\%2D\%2D))",
        r"(\b(OR|AND)\b.*(\b(TRUE|FALSE)\b|[\d]+\s*=\s*[\d]+))",
        r"(\bCONCAT\b|\bCHAR\b|\bASCII\b)"
    ]
    
    XSS_PATTERNS = [
        r"<script[^>]*>.*?</script>",
        r"javascript:",
        r"vbscript:",
        r"onload\s*=",
        r"onerror\s*=",
        r"onclick\s*=",
        r"onmouseover\s*="
    ]
    
    COMMAND_INJECTION_PATTERNS = [
        r"[;&|`$()]",
        r"\b(cat|ls|ps|id|whoami|uname|netstat|wget|curl)\b",
        r"\.\.\/",
        r"\/etc\/passwd",
        r"\/proc\/"
    ]
    
    @classmethod
    def sanitize_input(cls, input_data: Any) -> Any:
        """Comprehensive input sanitization"""
        if isinstance(input_data, str):
            return cls._sanitize_string(input_data)
        elif isinstance(input_data, dict):
            return {key: cls.sanitize_input(value) for key, value in input_data.items()}
        elif isinstance(input_data, list):
            return [cls.sanitize_input(item) for item in input_data]
        return input_data
    
    @classmethod
    def _sanitize_string(cls, text: str) -> str:
        """Sanitize string input"""
        if not text:
            return text
            
        # HTML sanitization
        text = bleach.clean(text, tags=[], attributes={}, strip=True)
        
        # Check for malicious patterns
        cls._detect_malicious_patterns(text)
        
        # Additional escaping
        text = text.replace("\\", "\\\\")
        text = text.replace("'", "\\'")
        text = text.replace('"', '\\"')
        
        return text
    
    @classmethod
    def _detect_malicious_patterns(cls, text: str):
        """Detect and block malicious patterns"""
        text_lower = text.lower()
        
        # SQL Injection detection
        for pattern in cls.SQL_INJECTION_PATTERNS:
            if re.search(pattern, text_lower, re.IGNORECASE):
                security_logger.warning(f"SQL injection attempt detected: {text[:100]}")
                raise HTTPException(status_code=400, detail="Invalid input detected")
        
        # XSS detection
        for pattern in cls.XSS_PATTERNS:
            if re.search(pattern, text_lower, re.IGNORECASE):
                security_logger.warning(f"XSS attempt detected: {text[:100]}")
                raise HTTPException(status_code=400, detail="Invalid input detected")
        
        # Command injection detection
        for pattern in cls.COMMAND_INJECTION_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                security_logger.warning(f"Command injection attempt detected: {text[:100]}")
                raise HTTPException(status_code=400, detail="Invalid input detected")

class SecurityMiddleware(BaseHTTPMiddleware):
    """Comprehensive security middleware"""
    
    def __init__(self, app, enabled_features: Optional[Dict[str, bool]] = None):
        super().__init__(app)
        self.enabled_features = enabled_features or {
            "security_headers": True,
            "input_sanitization": True,
            "request_logging": True,
            "ip_filtering": True,
            "request_size_limit": True
        }
        self.blocked_ips = set()
        self.suspicious_requests = {}
        self.max_request_size = 10 * 1024 * 1024  # 10MB
    
    async def dispatch(self, request: Request, call_next):
        start_time = time.time()
        
        # IP filtering
        if self.enabled_features.get("ip_filtering"):
            client_ip = self._get_client_ip(request)
            if client_ip in self.blocked_ips:
                security_logger.warning(f"Blocked IP attempted access: {client_ip}")
                return JSONResponse(
                    status_code=403,
                    content={"detail": "Access denied"}
                )
        
        # Request size limit
        if self.enabled_features.get("request_size_limit"):
            content_length = request.headers.get("content-length")
            if content_length and int(content_length) > self.max_request_size:
                security_logger.warning(f"Request size limit exceeded: {content_length}")
                return JSONResponse(
                    status_code=413,
                    content={"detail": "Request too large"}
                )
        
        # Input sanitization for POST/PUT requests
        if self.enabled_features.get("input_sanitization"):
            if request.method in ["POST", "PUT", "PATCH"]:
                await self._sanitize_request_body(request)
        
        # Process request
        try:
            response = await call_next(request)
        except Exception as e:
            security_logger.error(f"Request processing error: {str(e)}")
            return JSONResponse(
                status_code=500,
                content={"detail": "Internal server error"}
            )
        
        # Add security headers
        if self.enabled_features.get("security_headers"):
            for header, value in SecurityHeaders.get_security_headers().items():
                response.headers[header] = value
        
        # Security logging
        if self.enabled_features.get("request_logging"):
            await self._log_request(request, response, time.time() - start_time)
        
        return response
    
    def _get_client_ip(self, request: Request) -> str:
        """Get real client IP considering proxies"""
        # Check for forwarded headers
        forwarded_for = request.headers.get("x-forwarded-for")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        
        real_ip = request.headers.get("x-real-ip")
        if real_ip:
            return real_ip
        
        return request.client.host if request.client else "unknown"
    
    async def _sanitize_request_body(self, request: Request):
        """Sanitize request body data"""
        try:
            if request.headers.get("content-type", "").startswith("application/json"):
                body = await request.body()
                if body:
                    import json
                    data = json.loads(body)
                    sanitized_data = InputSanitizer.sanitize_input(data)
                    # Note: FastAPI will re-parse the body, this is for validation
        except Exception as e:
            security_logger.warning(f"Body sanitization error: {str(e)}")
    
    async def _log_request(self, request: Request, response: Response, duration: float):
        """Log security-relevant request information"""
        client_ip = self._get_client_ip(request)
        user_agent = request.headers.get("user-agent", "unknown")
        
        # Detect suspicious patterns
        suspicious_score = 0
        
        # Check for automated tools
        suspicious_agents = ["sqlmap", "nmap", "nikto", "burp", "zap", "curl", "wget"]
        if any(agent in user_agent.lower() for agent in suspicious_agents):
            suspicious_score += 5
        
        # Check for unusual request patterns
        if response.status_code >= 400:
            suspicious_score += 2
        
        if duration > 5.0:  # Slow requests might indicate attacks
            suspicious_score += 1
        
        # Track suspicious requests per IP
        if suspicious_score > 0:
            if client_ip not in self.suspicious_requests:
                self.suspicious_requests[client_ip] = []
            
            self.suspicious_requests[client_ip].append({
                "timestamp": datetime.now(),
                "score": suspicious_score,
                "path": str(request.url.path),
                "method": request.method
            })
            
            # Auto-block IPs with high suspicious activity
            recent_requests = [
                req for req in self.suspicious_requests[client_ip]
                if req["timestamp"] > datetime.now() - timedelta(minutes=10)
            ]
            
            total_score = sum(req["score"] for req in recent_requests)
            if total_score > 20:  # Threshold for auto-blocking
                self.blocked_ips.add(client_ip)
                security_logger.error(f"Auto-blocked suspicious IP: {client_ip}")
        
        # Log the request
        security_logger.info(
            f"REQUEST: {client_ip} {request.method} {request.url.path} "
            f"Status: {response.status_code} Duration: {duration:.2f}s "
            f"Suspicious: {suspicious_score} UA: {user_agent[:100]}"
        )

class CSRFProtection:
    """CSRF token generation and validation"""
    
    @staticmethod
    def generate_token(session_id: str) -> str:
        """Generate CSRF token"""
        timestamp = str(int(time.time()))
        message = f"{session_id}:{timestamp}"
        token = hashlib.sha256(message.encode()).hexdigest()
        return f"{timestamp}:{token}"
    
    @staticmethod
    def validate_token(token: str, session_id: str, max_age: int = 3600) -> bool:
        """Validate CSRF token"""
        try:
            timestamp_str, token_hash = token.split(":", 1)
            timestamp = int(timestamp_str)
            
            # Check token age
            if time.time() - timestamp > max_age:
                return False
            
            # Regenerate expected token
            message = f"{session_id}:{timestamp_str}"
            expected_token = hashlib.sha256(message.encode()).hexdigest()
            
            return token_hash == expected_token
        except (ValueError, AttributeError):
            return False

class SecurityAudit:
    """Security audit and monitoring"""
    
    @staticmethod
    def log_security_event(event_type: str, details: Dict[str, Any], severity: str = "INFO"):
        """Log security events for audit trail"""
        audit_entry = {
            "timestamp": datetime.now().isoformat(),
            "event_type": event_type,
            "severity": severity,
            "details": details
        }
        
        security_logger.info(f"SECURITY_EVENT: {audit_entry}")
        
        # Here you could also write to a dedicated security log file or database
        # For production, consider using structured logging with JSON format