"""
Security middleware for FastAPI application
"""

from fastapi import Request, Response, HTTPException, status
from fastapi.middleware.base import BaseHTTPMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.base import RequestResponseEndpoint
from typing import Dict, Optional
import time
import json
import logging
from datetime import datetime, timedelta
from collections import defaultdict, deque
from app.core.config import settings
from app.core.auth import SecurityHeaders
import ipaddress


logger = logging.getLogger(__name__)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Rate limiting middleware using sliding window algorithm"""
    
    def __init__(self, app, requests_per_window: int = None, window_seconds: int = None):
        super().__init__(app)
        self.requests_per_window = requests_per_window or settings.RATE_LIMIT_REQUESTS
        self.window_seconds = window_seconds or settings.RATE_LIMIT_WINDOW
        self.clients: Dict[str, deque] = defaultdict(deque)
    
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        # Get client IP
        client_ip = self._get_client_ip(request)
        
        # Check rate limit
        current_time = time.time()
        client_requests = self.clients[client_ip]
        
        # Remove old requests outside the window
        while client_requests and client_requests[0] <= current_time - self.window_seconds:
            client_requests.popleft()
        
        # Check if limit exceeded
        if len(client_requests) >= self.requests_per_window:
            logger.warning(f"Rate limit exceeded for IP: {client_ip}")
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={
                    "detail": "Rate limit exceeded",
                    "retry_after": self.window_seconds
                },
                headers={
                    "Retry-After": str(self.window_seconds),
                    **SecurityHeaders.get_headers()
                }
            )
        
        # Add current request
        client_requests.append(current_time)
        
        response = await call_next(request)
        return response
    
    def _get_client_ip(self, request: Request) -> str:
        """Get client IP address from request"""
        # Check for forwarded headers (behind proxy)
        forwarded_for = request.headers.get("x-forwarded-for")
        if forwarded_for:
            # Take the first IP in the chain
            return forwarded_for.split(",")[0].strip()
        
        forwarded = request.headers.get("x-forwarded")
        if forwarded:
            return forwarded.split(",")[0].strip()
        
        real_ip = request.headers.get("x-real-ip")
        if real_ip:
            return real_ip
        
        # Fallback to client host
        return request.client.host if request.client else "unknown"


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Middleware to add security headers to all responses"""
    
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)
        
        # Add security headers
        for header, value in SecurityHeaders.get_headers().items():
            response.headers[header] = value
        
        return response


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Middleware to log API requests and responses"""
    
    def __init__(self, app):
        super().__init__(app)
        self.logger = logging.getLogger("api.requests")
    
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        start_time = time.time()
        
        # Log request
        self.logger.info(
            f"Request: {request.method} {request.url.path} "
            f"from {self._get_client_ip(request)}"
        )
        
        try:
            response = await call_next(request)
            
            # Calculate response time
            process_time = time.time() - start_time
            
            # Log response
            self.logger.info(
                f"Response: {response.status_code} "
                f"in {process_time:.3f}s"
            )
            
            # Add timing header
            response.headers["X-Process-Time"] = str(process_time)
            
            return response
            
        except Exception as e:
            process_time = time.time() - start_time
            self.logger.error(
                f"Request failed: {request.method} {request.url.path} "
                f"in {process_time:.3f}s - Error: {str(e)}"
            )
            raise
    
    def _get_client_ip(self, request: Request) -> str:
        """Get client IP address from request"""
        forwarded_for = request.headers.get("x-forwarded-for")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        return request.client.host if request.client else "unknown"


class IPWhitelistMiddleware(BaseHTTPMiddleware):
    """Middleware to restrict access by IP address"""
    
    def __init__(self, app, whitelist: Optional[list] = None):
        super().__init__(app)
        self.whitelist = whitelist or []
        self.networks = []
        
        # Parse CIDR networks
        for ip_or_network in self.whitelist:
            try:
                self.networks.append(ipaddress.ip_network(ip_or_network, strict=False))
            except ValueError:
                logger.warning(f"Invalid IP/network in whitelist: {ip_or_network}")
    
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        if not self.networks:
            # No whitelist configured, allow all
            return await call_next(request)
        
        client_ip = self._get_client_ip(request)
        
        try:
            client_addr = ipaddress.ip_address(client_ip)
            
            # Check if client IP is in any whitelisted network
            for network in self.networks:
                if client_addr in network:
                    return await call_next(request)
            
            # IP not whitelisted
            logger.warning(f"Access denied for IP: {client_ip}")
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"detail": "Access denied"}
            )
            
        except ValueError:
            # Invalid IP address
            logger.warning(f"Invalid client IP: {client_ip}")
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"detail": "Access denied"}
            )
    
    def _get_client_ip(self, request: Request) -> str:
        """Get client IP address from request"""
        forwarded_for = request.headers.get("x-forwarded-for")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        return request.client.host if request.client else "unknown"


class ContentSecurityMiddleware(BaseHTTPMiddleware):
    """Middleware for content security validation"""
    
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        # Validate content type for POST/PUT requests
        if request.method in ["POST", "PUT", "PATCH"]:
            content_type = request.headers.get("content-type", "")
            
            # Only allow JSON and form data
            allowed_types = [
                "application/json",
                "application/x-www-form-urlencoded",
                "multipart/form-data"
            ]
            
            if not any(allowed_type in content_type.lower() for allowed_type in allowed_types):
                return JSONResponse(
                    status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
                    content={"detail": "Unsupported media type"}
                )
        
        # Validate request size
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                size_mb = int(content_length) / (1024 * 1024)
                if size_mb > settings.MAX_UPLOAD_SIZE_MB:
                    return JSONResponse(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        content={"detail": "Request too large"}
                    )
            except ValueError:
                pass
        
        return await call_next(request)


class AuditLogMiddleware(BaseHTTPMiddleware):
    """Middleware to create audit logs for sensitive operations"""
    
    def __init__(self, app):
        super().__init__(app)
        self.sensitive_paths = [
            "/api/v1/auth",
            "/api/v1/users",
            "/api/v1/projects",
            "/api/v1/scans"
        ]
    
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        # Check if this is a sensitive operation
        should_audit = any(
            request.url.path.startswith(path) for path in self.sensitive_paths
        )
        
        if should_audit:
            # Extract audit information
            user_id = getattr(request.state, "user_id", None)
            audit_data = {
                "timestamp": datetime.utcnow().isoformat(),
                "method": request.method,
                "path": request.url.path,
                "ip_address": self._get_client_ip(request),
                "user_agent": request.headers.get("user-agent"),
                "user_id": user_id
            }
            
            # Log the audit event
            logger.info(f"Audit: {json.dumps(audit_data)}")
        
        return await call_next(request)
    
    def _get_client_ip(self, request: Request) -> str:
        """Get client IP address from request"""
        forwarded_for = request.headers.get("x-forwarded-for")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        return request.client.host if request.client else "unknown"


# Middleware configuration
def get_middleware_stack():
    """Get the complete middleware stack"""
    return [
        SecurityHeadersMiddleware,
        RateLimitMiddleware,
        RequestLoggingMiddleware,
        ContentSecurityMiddleware,
        AuditLogMiddleware
    ]