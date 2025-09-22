"""
Database models for SecureShield Pro
"""

from sqlalchemy import Column, Integer, String, DateTime, Boolean, Text, JSON, ForeignKey, Enum
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from datetime import datetime
from enum import Enum as PyEnum
from app.db.database import Base
import uuid


class UserRole(str, PyEnum):
    """User role enumeration"""
    ADMIN = "admin"  # lowercase to match database
    ANALYST = "analyst"
    VIEWER = "viewer"


class ScanStatus(PyEnum):
    """Scan status enumeration"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class VulnerabilitySeverity(PyEnum):
    """Vulnerability severity enumeration"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class User(Base):
    """User model"""
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    username = Column(String(100), unique=True, nullable=False)  # Required field
    hashed_password = Column(String(255), nullable=False)
    first_name = Column(String(255), nullable=True)
    last_name = Column(String(255), nullable=True)
    full_name = Column(String(255), nullable=True)  # computed from first_name + last_name
    role = Column(Enum("admin", "analyst", "viewer", name="userrole"), default="viewer", nullable=False)
    is_active = Column(Boolean, default=True, nullable=True)
    is_verified = Column(Boolean, default=False, nullable=False)
    is_superuser = Column(Boolean, default=False, nullable=True)
    two_factor_enabled = Column(Boolean, default=False, nullable=True)
    two_factor_secret = Column(String(32), nullable=True)
    totp_secret = Column(String(32), nullable=True)
    backup_codes = Column(Text, nullable=True)
    
    # OAuth fields
    google_id = Column(String(255), nullable=True, unique=True)
    github_id = Column(String(255), nullable=True, unique=True)
    avatar_url = Column(String(500), nullable=True)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    last_login = Column(DateTime(timezone=True), nullable=True)
    
    # Relationships
    projects = relationship("Project", back_populates="owner")
    scans = relationship("Scan", back_populates="user")
    vulnerability_scans = relationship("VulnerabilityScans", back_populates="created_by_user")
    security_findings = relationship("SecurityFindings", back_populates="assigned_to_user")


class Project(Base):
    """Project model"""
    __tablename__ = "projects"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    repository_url = Column(String(500), nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    
    # Configuration
    scan_config = Column(JSON, nullable=True)  # SAST/DAST configuration
    
    # Foreign keys
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationships
    owner = relationship("User", back_populates="projects")
    scans = relationship("Scan", back_populates="project")


class Scan(Base):
    """Security scan model"""
    __tablename__ = "scans"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255), nullable=False)
    scan_type = Column(String(50), nullable=False)  # sast, dast, dependency, etc.
    status = Column(Enum(ScanStatus), default=ScanStatus.PENDING, nullable=False)
    
    # Scan details
    target_path = Column(String(500), nullable=True)
    target_url = Column(String(500), nullable=True)
    command_executed = Column(Text, nullable=True)
    
    # Results
    total_findings = Column(Integer, default=0)
    critical_findings = Column(Integer, default=0)
    high_findings = Column(Integer, default=0)
    medium_findings = Column(Integer, default=0)
    low_findings = Column(Integer, default=0)
    
    # Metadata
    duration_seconds = Column(Integer, nullable=True)
    scan_config = Column(JSON, nullable=True)
    raw_output = Column(Text, nullable=True)
    error_message = Column(Text, nullable=True)
    
    # Foreign keys
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    
    # Relationships
    project = relationship("Project", back_populates="scans")
    user = relationship("User", back_populates="scans")
    findings = relationship("Finding", back_populates="scan")


class Finding(Base):
    """Security finding model"""
    __tablename__ = "findings"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(Enum(VulnerabilitySeverity), nullable=False)
    
    # Location details
    file_path = Column(String(1000), nullable=True)
    line_number = Column(Integer, nullable=True)
    column_number = Column(Integer, nullable=True)
    
    # Vulnerability details
    cwe_id = Column(String(20), nullable=True)  # CWE-79, etc.
    cve_id = Column(String(20), nullable=True)  # CVE-2023-1234, etc.
    rule_id = Column(String(100), nullable=True)
    confidence = Column(String(20), nullable=True)  # high, medium, low
    
    # Code context
    code_snippet = Column(Text, nullable=True)
    
    # AI analysis
    ai_analysis = Column(Text, nullable=True)
    ai_remediation = Column(Text, nullable=True)
    
    # Status
    is_false_positive = Column(Boolean, default=False)
    is_resolved = Column(Boolean, default=False)
    resolution_comment = Column(Text, nullable=True)
    
    # Foreign keys
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationships
    scan = relationship("Scan", back_populates="findings")


class OTPCode(Base):
    """OTP verification codes"""
    __tablename__ = "otp_codes"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    email = Column(String(255), nullable=False, index=True)
    code = Column(String(6), nullable=False)
    purpose = Column(String(50), nullable=False)  # login, signup, reset_password
    is_used = Column(Boolean, default=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class AuditLog(Base):
    """Audit log for security events"""
    __tablename__ = "audit_logs"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    action = Column(String(100), nullable=False)
    resource_type = Column(String(50), nullable=True)
    resource_id = Column(String(36), nullable=True)
    ip_address = Column(String(45), nullable=True)  # IPv6 compatible
    user_agent = Column(String(500), nullable=True)
    details = Column(JSON, nullable=True)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    

class VulnerabilityScans(Base):
    """Vulnerability scan results"""
    __tablename__ = "vulnerability_scans"
    
    id = Column(Integer, primary_key=True, index=True)
    scan_name = Column(String(255), nullable=False)
    scan_type = Column(String(50), nullable=False)  # SAST, DAST, SCA, etc.
    target = Column(String(500), nullable=False)  # URL, repo, file path
    status = Column(Enum(ScanStatus), default=ScanStatus.PENDING)
    
    # Results
    total_findings = Column(Integer, default=0)
    critical_findings = Column(Integer, default=0)
    high_findings = Column(Integer, default=0)
    medium_findings = Column(Integer, default=0)
    low_findings = Column(Integer, default=0)
    
    # Metadata
    scan_duration = Column(String(50), nullable=True)
    tools_used = Column(JSON, nullable=True)
    raw_output = Column(Text, nullable=True)
    
    # AI Analysis
    ai_analysis = Column(Text, nullable=True)
    ai_remediation = Column(Text, nullable=True)
    
    # Relationships
    created_by = Column(Integer, ForeignKey("users.id"))
    created_by_user = relationship("User", back_populates="vulnerability_scans")
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())


class SecurityFindings(Base):
    """Individual security findings from scans"""
    __tablename__ = "security_findings"
    
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("vulnerability_scans.id"))
    
    # Finding details
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(Enum(VulnerabilitySeverity), nullable=False)
    confidence = Column(String(20), nullable=True)  # HIGH, MEDIUM, LOW
    
    # Location
    file_path = Column(String(1000), nullable=True)
    line_number = Column(Integer, nullable=True)
    column_number = Column(Integer, nullable=True)
    
    # Vulnerability details
    cwe_id = Column(String(20), nullable=True)  # CWE-79, etc.
    cve_id = Column(String(20), nullable=True)  # CVE-2021-44228, etc.
    rule_id = Column(String(100), nullable=True)
    
    # Context
    code_snippet = Column(Text, nullable=True)
    evidence = Column(Text, nullable=True)
    
    # Status tracking
    status = Column(String(20), default="open")  # open, investigating, fixed, false_positive
    assigned_to = Column(Integer, ForeignKey("users.id"), nullable=True)
    assigned_to_user = relationship("User", back_populates="security_findings")
    
    # AI Analysis
    ai_analysis = Column(Text, nullable=True)
    ai_remediation = Column(Text, nullable=True)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())


# ============================================================================
# THREAT INTELLIGENCE MODELS
# ============================================================================

class IOCType(PyEnum):
    """IOC type enumeration"""
    IP_ADDRESS = "ip"
    DOMAIN = "domain"
    URL = "url"
    EMAIL = "email"
    FILE_HASH = "file_hash"
    MUTEX = "mutex"
    REGISTRY_KEY = "registry_key"
    USER_AGENT = "user_agent"
    SSL_CERT = "ssl_cert"
    YARA_RULE = "yara_rule"


class ThreatActorType(PyEnum):
    """Threat actor type enumeration"""
    APT = "apt"
    CYBERCRIMINAL = "cybercriminal"
    HACKTIVIST = "hacktivist"
    INSIDER = "insider"
    NATION_STATE = "nation_state"
    SCRIPT_KIDDIE = "script_kiddie"
    UNKNOWN = "unknown"


class ThreatLevel(PyEnum):
    """Threat level enumeration"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class IOC(Base):
    """Indicator of Compromise model"""
    __tablename__ = "iocs"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    ioc_id = Column(String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))
    
    # IOC Details
    type = Column(Enum(IOCType), nullable=False)
    value = Column(String(1000), nullable=False, index=True)
    description = Column(Text, nullable=True)
    
    # Threat Information
    threat_level = Column(Enum(ThreatLevel), default=ThreatLevel.MEDIUM, nullable=False)
    confidence = Column(Integer, default=50, nullable=False)  # 0-100
    
    # Attribution
    threat_actor_id = Column(Integer, ForeignKey("threat_actors.id"), nullable=True)
    campaign_id = Column(Integer, ForeignKey("threat_campaigns.id"), nullable=True)
    
    # Sources and Context
    source = Column(String(255), nullable=True)  # MISP, internal, external feed
    source_url = Column(String(1000), nullable=True)
    tags = Column(JSON, nullable=True)  # Array of tags
    
    # Temporal Information
    first_seen = Column(DateTime(timezone=True), nullable=True)
    last_seen = Column(DateTime(timezone=True), nullable=True)
    valid_from = Column(DateTime(timezone=True), server_default=func.now())
    valid_until = Column(DateTime(timezone=True), nullable=True)
    
    # Status
    is_active = Column(Boolean, default=True, nullable=False)
    is_whitelist = Column(Boolean, default=False, nullable=False)
    
    # Detection Information
    detection_count = Column(Integer, default=0, nullable=False)
    last_detection = Column(DateTime(timezone=True), nullable=True)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationships
    threat_actor = relationship("ThreatActor", back_populates="iocs")
    campaign = relationship("ThreatCampaign", back_populates="iocs")
    detections = relationship("IOCDetection", back_populates="ioc")


class ThreatActor(Base):
    """Threat actor model"""
    __tablename__ = "threat_actors"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    actor_id = Column(String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))
    
    # Basic Information
    name = Column(String(255), nullable=False, unique=True)
    aliases = Column(JSON, nullable=True)  # Array of alternative names
    description = Column(Text, nullable=True)
    
    # Classification
    actor_type = Column(Enum(ThreatActorType), nullable=False)
    sophistication = Column(String(50), nullable=True)  # low, medium, high, expert
    
    # Attribution
    country = Column(String(100), nullable=True)
    region = Column(String(100), nullable=True)
    motivation = Column(JSON, nullable=True)  # Array of motivations
    
    # Activity Information
    first_seen = Column(DateTime(timezone=True), nullable=True)
    last_seen = Column(DateTime(timezone=True), nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    
    # Additional Details
    targets = Column(JSON, nullable=True)  # Industries, countries, etc.
    ttps = Column(JSON, nullable=True)  # Tactics, techniques, procedures
    tools = Column(JSON, nullable=True)  # Malware, tools used
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationships
    iocs = relationship("IOC", back_populates="threat_actor")
    campaigns = relationship("ThreatCampaign", back_populates="threat_actor")


class ThreatCampaign(Base):
    """Threat campaign model"""
    __tablename__ = "threat_campaigns"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    campaign_id = Column(String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))
    
    # Basic Information
    name = Column(String(255), nullable=False, unique=True)
    description = Column(Text, nullable=True)
    
    # Attribution
    threat_actor_id = Column(Integer, ForeignKey("threat_actors.id"), nullable=True)
    
    # Campaign Details
    objectives = Column(JSON, nullable=True)  # Array of objectives
    targets = Column(JSON, nullable=True)  # Target information
    
    # Temporal Information
    start_date = Column(DateTime(timezone=True), nullable=True)
    end_date = Column(DateTime(timezone=True), nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    
    # Impact Assessment
    estimated_impact = Column(String(50), nullable=True)  # low, medium, high, critical
    confirmed_victims = Column(Integer, default=0, nullable=False)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationships
    threat_actor = relationship("ThreatActor", back_populates="campaigns")
    iocs = relationship("IOC", back_populates="campaign")


class IOCDetection(Base):
    """IOC detection event model"""
    __tablename__ = "ioc_detections"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    detection_id = Column(String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))
    
    # Detection Details
    ioc_id = Column(Integer, ForeignKey("iocs.id"), nullable=False)
    source_system = Column(String(255), nullable=False)  # SIEM, firewall, etc.
    detection_method = Column(String(255), nullable=True)  # signature, behavior, etc.
    
    # Context Information
    asset_affected = Column(String(255), nullable=True)
    user_affected = Column(String(255), nullable=True)
    
    # Event Details
    event_data = Column(JSON, nullable=True)  # Raw event data
    risk_score = Column(Integer, default=50, nullable=False)  # 0-100
    
    # Response Information
    action_taken = Column(String(255), nullable=True)  # blocked, quarantined, etc.
    analyst_notes = Column(Text, nullable=True)
    is_false_positive = Column(Boolean, default=False, nullable=False)
    
    # Timestamps
    detected_at = Column(DateTime(timezone=True), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    ioc = relationship("IOC", back_populates="detections")


class ThreatIntelFeed(Base):
    """Threat intelligence feed model"""
    __tablename__ = "threat_intel_feeds"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    feed_id = Column(String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))
    
    # Feed Information
    name = Column(String(255), nullable=False, unique=True)
    description = Column(Text, nullable=True)
    provider = Column(String(255), nullable=False)
    feed_type = Column(String(100), nullable=False)  # misp, stix, csv, json, etc.
    
    # Connection Details
    url = Column(String(1000), nullable=True)
    api_key = Column(String(500), nullable=True)
    username = Column(String(255), nullable=True)
    password_hash = Column(String(255), nullable=True)
    
    # Configuration
    update_frequency = Column(Integer, default=3600, nullable=False)  # seconds
    is_active = Column(Boolean, default=True, nullable=False)
    auto_import = Column(Boolean, default=True, nullable=False)
    
    # Status
    last_update = Column(DateTime(timezone=True), nullable=True)
    last_success = Column(DateTime(timezone=True), nullable=True)
    last_error = Column(Text, nullable=True)
    total_iocs_imported = Column(Integer, default=0, nullable=False)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())


class ThreatIntelReport(Base):
    """Threat intelligence report model"""
    __tablename__ = "threat_intel_reports"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    report_id = Column(String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))
    
    # Report Information
    title = Column(String(500), nullable=False)
    summary = Column(Text, nullable=True)
    content = Column(Text, nullable=True)
    
    # Classification
    threat_level = Column(Enum(ThreatLevel), default=ThreatLevel.MEDIUM, nullable=False)
    report_type = Column(String(100), nullable=False)  # analysis, advisory, alert, etc.
    
    # Attribution
    author = Column(String(255), nullable=True)
    source = Column(String(255), nullable=True)
    
    # Associated Entities
    related_actors = Column(JSON, nullable=True)  # Array of threat actor IDs
    related_campaigns = Column(JSON, nullable=True)  # Array of campaign IDs
    related_iocs = Column(JSON, nullable=True)  # Array of IOC IDs
    
    # Temporal Information
    published_date = Column(DateTime(timezone=True), nullable=True)
    valid_from = Column(DateTime(timezone=True), server_default=func.now())
    valid_until = Column(DateTime(timezone=True), nullable=True)
    
    # Status
    is_public = Column(Boolean, default=False, nullable=False)
    confidence = Column(Integer, default=50, nullable=False)  # 0-100
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())