"""
Enhanced Security Configuration for SecureShield Pro
Following OWASP and NIST security guidelines for bulletproof protection
"""
from typing import Dict, List, Any
from pydantic_settings import BaseSettings
from pydantic import field_validator
import secrets

class SecurityConfig(BaseSettings):
    """Enhanced security configuration"""
    
    # JWT Security
    JWT_SECRET_KEY: str = secrets.token_urlsafe(64)
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    JWT_REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    JWT_BLACKLIST_ENABLED: bool = True
    
    # Password Security (NIST SP 800-63B compliant)
    PASSWORD_MIN_LENGTH: int = 12
    PASSWORD_MAX_LENGTH: int = 128
    PASSWORD_REQUIRE_UPPERCASE: bool = True
    PASSWORD_REQUIRE_LOWERCASE: bool = True
    PASSWORD_REQUIRE_NUMBERS: bool = True
    PASSWORD_REQUIRE_SPECIAL_CHARS: bool = True
    PASSWORD_SALT_ROUNDS: int = 12
    PASSWORD_HISTORY_COUNT: int = 5
    PASSWORD_MAX_AGE_DAYS: int = 90
    
    # Rate Limiting
    RATE_LIMIT_LOGIN: str = "5/minute"
    RATE_LIMIT_API: str = "100/minute"
    RATE_LIMIT_UPLOAD: str = "10/minute"
    RATE_LIMIT_GLOBAL: str = "1000/hour"
    
    # Session Security
    SESSION_COOKIE_SECURE: bool = True
    SESSION_COOKIE_HTTPONLY: bool = True
    SESSION_COOKIE_SAMESITE: str = "strict"
    SESSION_TIMEOUT_MINUTES: int = 30
    SESSION_REGENERATE_ON_AUTH: bool = True
    
    # File Upload Security
    MAX_FILE_SIZE: int = 50 * 1024 * 1024  # 50MB
    ALLOWED_FILE_EXTENSIONS: List[str] = [
        '.py', '.js', '.ts', '.java', '.cpp', '.c', '.go', '.rs', '.php',
        '.rb', '.cs', '.xml', '.json', '.yaml', '.yml', '.txt', '.md'
    ]
    FORBIDDEN_FILE_TYPES: List[str] = [
        '.exe', '.bat', '.cmd', '.com', '.scr', '.pif', '.msi', '.dll',
        '.sh', '.bash', '.zsh', '.ps1', '.vbs', '.jar'
    ]
    SCAN_UPLOADED_FILES: bool = True
    QUARANTINE_SUSPICIOUS_FILES: bool = True
    
    # Database Security
    DB_CONNECTION_POOL_SIZE: int = 10
    DB_MAX_OVERFLOW: int = 20
    DB_POOL_TIMEOUT: int = 30
    DB_POOL_RECYCLE: int = 3600
    DB_ENCRYPT_SENSITIVE_DATA: bool = True
    DB_AUDIT_ALL_CHANGES: bool = True
    
    # CORS Security
    CORS_ALLOWED_ORIGINS: List[str] = ["http://localhost:3000", "http://localhost:3001"]
    CORS_ALLOW_CREDENTIALS: bool = True
    CORS_ALLOWED_METHODS: List[str] = ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
    CORS_ALLOWED_HEADERS: List[str] = [
        "Authorization", "Content-Type", "X-CSRF-Token", "X-Requested-With"
    ]
    
    # Security Headers Configuration
    HSTS_MAX_AGE: int = 31536000  # 1 year
    CSP_NONCE_ENABLED: bool = True
    SECURITY_HEADERS_ENABLED: bool = True
    
    # IP Security
    BLOCKED_IP_ADDRESSES: List[str] = []
    TRUSTED_PROXY_IPS: List[str] = ["127.0.0.1", "::1"]
    GEO_BLOCKING_ENABLED: bool = False
    BLOCKED_COUNTRIES: List[str] = []
    
    # Audit and Logging
    SECURITY_LOG_LEVEL: str = "INFO"
    AUDIT_ALL_REQUESTS: bool = True
    LOG_SENSITIVE_DATA: bool = False
    SECURITY_LOG_RETENTION_DAYS: int = 90
    
    # Encryption
    ENCRYPTION_ALGORITHM: str = "AES-256-GCM"
    ENCRYPTION_KEY: str = secrets.token_urlsafe(32)
    DATA_AT_REST_ENCRYPTION: bool = True
    
    # API Security
    API_VERSION_DEPRECATION_MONTHS: int = 12
    API_REQUIRE_AUTHENTICATION: bool = True
    API_REQUIRE_HTTPS: bool = True
    API_REQUEST_ID_HEADER: str = "X-Request-ID"
    
    # Two-Factor Authentication
    TOTP_ENABLED: bool = True
    TOTP_ISSUER: str = "SecureShield Pro"
    TOTP_PERIOD: int = 30
    TOTP_DIGITS: int = 6
    BACKUP_CODES_COUNT: int = 10
    
    # Account Security
    MAX_LOGIN_ATTEMPTS: int = 5
    ACCOUNT_LOCKOUT_DURATION_MINUTES: int = 30
    ACCOUNT_LOCKOUT_ENABLED: bool = True
    REQUIRE_EMAIL_VERIFICATION: bool = True
    
    # Security Monitoring
    INTRUSION_DETECTION_ENABLED: bool = True
    ANOMALY_DETECTION_ENABLED: bool = True
    THREAT_INTELLIGENCE_ENABLED: bool = True
    SECURITY_SCAN_INTERVAL_HOURS: int = 24
    
    # Compliance
    GDPR_COMPLIANCE_ENABLED: bool = True
    HIPAA_COMPLIANCE_ENABLED: bool = False
    SOC2_COMPLIANCE_ENABLED: bool = True
    DATA_RETENTION_DAYS: int = 2555  # 7 years
    
    @field_validator('JWT_SECRET_KEY')
    def validate_jwt_secret(cls, v: str) -> str:
        if len(v) < 32:
            raise ValueError('JWT secret key must be at least 32 characters')
        return v
    
    @field_validator('PASSWORD_MIN_LENGTH')
    def validate_password_length(cls, v: int) -> int:
        if v < 8:
            raise ValueError('Minimum password length must be at least 8')
        return v
    
    @field_validator('CORS_ALLOWED_ORIGINS')
    def validate_cors_origins(cls, v: List[str]) -> List[str]:
        if not v:
            raise ValueError('At least one CORS origin must be specified')
        return v
    
    class Config:
        env_file = ".env"
        case_sensitive = True
        extra = "ignore"  # Ignore extra fields instead of raising validation errors

# Security patterns and rules
SECURITY_PATTERNS = {
    "sql_injection": [
        r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION)\b)",
        r"(\'|(\'\')|(\-\-)|(\%27)|(\%2D\%2D))",
        r"(\b(OR|AND)\b.*(\b(TRUE|FALSE)\b|[\d]+\s*=\s*[\d]+))"
    ],
    
    "xss_patterns": [
        r"<script[^>]*>.*?</script>",
        r"javascript:",
        r"vbscript:",
        r"on\w+\s*="
    ],
    
    "command_injection": [
        r"[;&|`$()]",
        r"\b(cat|ls|ps|id|whoami|uname|netstat|wget|curl)\b",
        r"\.\.\/",
        r"\/etc\/passwd"
    ],
    
    "directory_traversal": [
        r"\.\.\/",
        r"\.\.\\",
        r"\/etc\/",
        r"\/proc\/",
        r"\/sys\/",
        r"C:\\Windows\\",
        r"C:\\System32\\"
    ],
    
    "ldap_injection": [
        r"[()&|!*<>=~]",
        r"\x00",
        r"\\[0-9a-fA-F]{2}"
    ]
}

# Security validation rules
VALIDATION_RULES = {
    "email": r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$",
    "phone": r"^\+?1?[0-9]{10,15}$",
    "username": r"^[a-zA-Z0-9_-]{3,30}$",
    "filename": r"^[a-zA-Z0-9._-]+$",
    "ipv4": r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$",
    "ipv6": r"^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$"
}

# Content Security Policy templates
CSP_TEMPLATES = {
    "strict": "default-src 'self'; script-src 'self' 'nonce-{nonce}'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self'; frame-ancestors 'none';",
    "api_only": "default-src 'none'; script-src 'none'; style-src 'none'; img-src 'none'; font-src 'none'; connect-src 'none'; frame-ancestors 'none';",
    "development": "default-src 'self' 'unsafe-inline' 'unsafe-eval'; img-src 'self' data: https:; font-src 'self' https:; connect-src 'self' ws: wss:;"
}

# Threat intelligence indicators
THREAT_INDICATORS = {
    "malicious_user_agents": [
        "sqlmap", "nmap", "nikto", "burpsuite", "zaproxy", "w3af",
        "nuclei", "masscan", "zmap", "dirb", "dirbuster", "gobuster"
    ],
    
    "suspicious_headers": [
        "x-forwarded-for: 127.0.0.1",
        "x-originating-ip: 127.0.0.1",
        "x-remote-ip: 127.0.0.1",
        "x-remote-addr: 127.0.0.1"
    ],
    
    "attack_signatures": [
        "union select", "drop table", "exec xp_", "sp_executesql",
        "<script>", "javascript:", "onerror=", "onload=",
        "../etc/passwd", "..\\windows\\system32", "cmd.exe", "powershell"
    ]
}

# Initialize security configuration
security_config = SecurityConfig()