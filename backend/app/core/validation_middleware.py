"""
Advanced Input Validation and Security Middleware
Implements comprehensive input sanitization and attack prevention
"""
import re
import json
import logging
from typing import Any, Dict, List, Optional
from fastapi import Request, HTTPException, Response
from fastapi.middleware.base import BaseHTTPMiddleware
from starlette.middleware.base import BaseHTTPMiddleware as StarletteBaseHTTPMiddleware
import time

security_logger = logging.getLogger("security.validation")

class InputValidationMiddleware(StarletteBaseHTTPMiddleware):
    """Advanced input validation middleware"""
    
    def __init__(self, app, max_request_size: int = 10 * 1024 * 1024):
        super().__init__(app)
        self.max_request_size = max_request_size
        
        # Malicious patterns
        self.sql_patterns = [
            r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION)\b)",
            r"(\'|(\'\')|(\-\-)|(\%27)|(\%2D\%2D))",
            r"(\b(OR|AND)\b.*(\b(TRUE|FALSE)\b|[\d]+\s*=\s*[\d]+))"
        ]
        
        self.xss_patterns = [
            r"<script[^>]*>.*?</script>",
            r"javascript:",
            r"vbscript:",
            r"on\w+\s*="
        ]
        
        self.command_injection_patterns = [
            r"[;&|`$()]",
            r"\b(cat|ls|ps|id|whoami|uname|netstat|wget|curl)\b",
            r"\.\.\/",
            r"\/etc\/passwd"
        ]
    
    async def dispatch(self, request: Request, call_next):
        start_time = time.time()
        
        # Request size validation
        content_length = request.headers.get("content-length")
        if content_length and int(content_length) > self.max_request_size:
            security_logger.warning(f"Request size exceeded: {content_length} bytes")
            return Response(
                content="Request too large",
                status_code=413,
                media_type="text/plain"
            )
        
        # Validate request data
        if request.method in ["POST", "PUT", "PATCH"]:
            try:
                await self._validate_request_data(request)
            except HTTPException as e:
                security_logger.warning(f"Malicious input detected: {e.detail}")
                return Response(
                    content=json.dumps({"error": "Invalid input detected"}),
                    status_code=400,
                    media_type="application/json"
                )
        
        # Process request
        response = await call_next(request)
        
        # Log processing time
        processing_time = time.time() - start_time
        if processing_time > 5.0:  # Log slow requests
            security_logger.info(f"Slow request: {request.url.path} took {processing_time:.2f}s")
        
        return response
    
    async def _validate_request_data(self, request: Request):
        """Validate request data for malicious patterns"""
        try:
            # Get request body
            body = await request.body()
            if not body:
                return
            
            # Check content type
            content_type = request.headers.get("content-type", "")
            
            if "application/json" in content_type:
                try:
                    data = json.loads(body)
                    self._validate_json_data(data)
                except json.JSONDecodeError:
                    raise HTTPException(status_code=400, detail="Invalid JSON format")
            
            elif "application/x-www-form-urlencoded" in content_type:
                form_data = body.decode("utf-8")
                self._validate_string_input(form_data)
            
            elif "multipart/form-data" in content_type:
                # Skip binary file validation for now
                pass
            
        except UnicodeDecodeError:
            raise HTTPException(status_code=400, detail="Invalid character encoding")
    
    def _validate_json_data(self, data: Any):
        """Recursively validate JSON data"""
        if isinstance(data, dict):
            for key, value in data.items():
                if isinstance(key, str):
                    self._validate_string_input(key)
                self._validate_json_data(value)
        elif isinstance(data, list):
            for item in data:
                self._validate_json_data(item)
        elif isinstance(data, str):
            self._validate_string_input(data)
    
    def _validate_string_input(self, text: str):
        """Validate string input for malicious patterns"""
        if not text or len(text) > 10000:  # Limit string length
            return
        
        text_lower = text.lower()
        
        # Check for SQL injection
        for pattern in self.sql_patterns:
            if re.search(pattern, text_lower, re.IGNORECASE):
                raise HTTPException(status_code=400, detail="SQL injection pattern detected")
        
        # Check for XSS
        for pattern in self.xss_patterns:
            if re.search(pattern, text_lower, re.IGNORECASE):
                raise HTTPException(status_code=400, detail="XSS pattern detected")
        
        # Check for command injection
        for pattern in self.command_injection_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                raise HTTPException(status_code=400, detail="Command injection pattern detected")


class SecurityHeadersMiddleware(StarletteBaseHTTPMiddleware):
    """Security headers middleware"""
    
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        
        # Add comprehensive security headers
        response.headers.update({
            # XSS Protection
            "X-XSS-Protection": "1; mode=block",
            
            # Content Type Options
            "X-Content-Type-Options": "nosniff",
            
            # Frame Options
            "X-Frame-Options": "DENY",
            
            # HSTS
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
            
            # Referrer Policy
            "Referrer-Policy": "strict-origin-when-cross-origin",
            
            # Content Security Policy
            "Content-Security-Policy": (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline'; "
                "style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data: https:; "
                "font-src 'self'; "
                "connect-src 'self'; "
                "frame-ancestors 'none';"
            ),
            
            # Permissions Policy
            "Permissions-Policy": (
                "geolocation=(), camera=(), microphone=(), "
                "payment=(), usb=(), magnetometer=(), "
                "gyroscope=(), accelerometer=()"
            ),
            
            # Cross-Origin Policies
            "Cross-Origin-Embedder-Policy": "require-corp",
            "Cross-Origin-Opener-Policy": "same-origin",
            "Cross-Origin-Resource-Policy": "same-origin",
            
            # Cache Control for sensitive endpoints
            "Cache-Control": "no-store, no-cache, must-revalidate, proxy-revalidate",
            "Pragma": "no-cache",
            "Expires": "0",
            
            # Hide server information
            "Server": "SecureShield-Pro"
        })
        
        return response


class RequestLoggingMiddleware(StarletteBaseHTTPMiddleware):
    """Security-focused request logging"""
    
    def __init__(self, app):
        super().__init__(app)
        self.suspicious_ips = set()
        self.request_counts = {}
    
    async def dispatch(self, request: Request, call_next):
        start_time = time.time()
        
        # Get client information
        client_ip = self._get_client_ip(request)
        user_agent = request.headers.get("user-agent", "unknown")
        method = request.method
        path = request.url.path
        
        # Track requests per IP
        current_time = int(time.time())
        if client_ip not in self.request_counts:
            self.request_counts[client_ip] = []
        
        # Clean old requests (older than 1 hour)
        self.request_counts[client_ip] = [
            req_time for req_time in self.request_counts[client_ip]
            if current_time - req_time < 3600
        ]
        
        # Add current request
        self.request_counts[client_ip].append(current_time)
        
        # Check for suspicious activity
        request_count = len(self.request_counts[client_ip])
        if request_count > 1000:  # More than 1000 requests per hour
            self.suspicious_ips.add(client_ip)
            security_logger.warning(f"Suspicious activity from IP {client_ip}: {request_count} requests/hour")
        
        # Process request
        response = await call_next(request)
        
        # Calculate processing time
        processing_time = time.time() - start_time
        
        # Log request details
        log_entry = {
            "timestamp": time.time(),
            "client_ip": client_ip,
            "method": method,
            "path": path,
            "status_code": response.status_code,
            "processing_time": round(processing_time, 3),
            "user_agent": user_agent[:100],  # Truncate long user agents
            "suspicious": client_ip in self.suspicious_ips
        }
        
        # Log based on severity
        if response.status_code >= 500:
            security_logger.error(f"SERVER_ERROR: {log_entry}")
        elif response.status_code >= 400:
            security_logger.warning(f"CLIENT_ERROR: {log_entry}")
        elif client_ip in self.suspicious_ips:
            security_logger.warning(f"SUSPICIOUS_REQUEST: {log_entry}")
        else:
            security_logger.info(f"REQUEST: {log_entry}")
        
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