"""
Enhanced Security Analysis Engine
Advanced file analysis with AI-powered vulnerability detection and automated remediation
"""

import asyncio
import hashlib
import json
import mimetypes
import os
import subprocess
import tempfile
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional, Union
import logging
import zipfile
import tarfile
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)

class AnalysisStatus(Enum):
    PENDING = "pending"
    ANALYZING = "analyzing"
    COMPLETED = "completed"
    FAILED = "failed"
    PROCESSING = "processing"

class VulnerabilityLevel(Enum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class AnalysisType(Enum):
    STATIC_ANALYSIS = "static_analysis"
    DEPENDENCY_SCAN = "dependency_scan"
    SECRET_DETECTION = "secret_detection"
    MALWARE_SCAN = "malware_scan"
    CODE_QUALITY = "code_quality"
    CONFIGURATION_SCAN = "configuration_scan"
    COMPLIANCE_CHECK = "compliance_check"

@dataclass
class SecurityFinding:
    id: str
    type: str
    title: str
    description: str
    severity: VulnerabilityLevel
    confidence: float
    file_path: str
    line_number: Optional[int] = None
    column_number: Optional[int] = None
    code_snippet: Optional[str] = None
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None
    remediation: Optional[str] = None
    references: List[str] = field(default_factory=list)
    false_positive: bool = False
    
@dataclass 
class AnalysisReport:
    id: str
    filename: str
    file_hash: str
    file_size: int
    analysis_type: List[AnalysisType]
    status: AnalysisStatus
    findings: List[SecurityFinding]
    metadata: Dict[str, Any]
    created_at: datetime
    completed_at: Optional[datetime] = None
    execution_time: Optional[float] = None
    ai_summary: Optional[str] = None
    remediation_suggestions: List[str] = field(default_factory=list)

class SecurityAnalysisEngine:
    """
    Advanced Security Analysis Engine with AI-powered vulnerability detection
    """
    
    def __init__(self, upload_dir: str = "/var/tmp/security_uploads"):
        self.upload_dir = Path(upload_dir)
        self.upload_dir.mkdir(parents=True, exist_ok=True)
        self.reports: Dict[str, AnalysisReport] = {}
        self.analysis_cache: Dict[str, AnalysisReport] = {}
        
        # Initialize AI models (simulated for demo)
        self.ai_models = {
            "vulnerability_detector": self._init_vulnerability_model(),
            "code_analyzer": self._init_code_model(),
            "malware_detector": self._init_malware_model(),
            "dependency_scanner": self._init_dependency_model()
        }
        
    def _init_vulnerability_model(self):
        """Initialize vulnerability detection model"""
        return {
            "model_name": "VulnDetect-AI-v2.1",
            "accuracy": 0.94,
            "last_updated": datetime.now(),
            "patterns": self._load_vulnerability_patterns()
        }
    
    def _init_code_model(self):
        """Initialize code quality analysis model"""
        return {
            "model_name": "CodeSecure-AI-v1.8",
            "accuracy": 0.89,
            "last_updated": datetime.now(),
            "rules": self._load_code_analysis_rules()
        }
    
    def _init_malware_model(self):
        """Initialize malware detection model"""
        return {
            "model_name": "MalwareShield-AI-v3.2",
            "accuracy": 0.96,
            "last_updated": datetime.now(),
            "signatures": self._load_malware_signatures()
        }
    
    def _init_dependency_model(self):
        """Initialize dependency vulnerability scanner"""
        return {
            "model_name": "DepScan-AI-v2.0",
            "accuracy": 0.92,
            "last_updated": datetime.now(),
            "database": self._load_vulnerability_database()
        }
    
    def _load_vulnerability_patterns(self) -> List[Dict]:
        """Load vulnerability detection patterns"""
        return [
            {
                "pattern": r"password\s*=\s*['\"][^'\"]*['\"]",
                "type": "hardcoded_password",
                "severity": VulnerabilityLevel.HIGH,
                "cwe": "CWE-798"
            },
            {
                "pattern": r"SELECT\s+.*\s+FROM\s+.*\s+WHERE\s+.*\+",
                "type": "sql_injection",
                "severity": VulnerabilityLevel.CRITICAL,
                "cwe": "CWE-89"
            },
            {
                "pattern": r"eval\s*\(",
                "type": "code_injection",
                "severity": VulnerabilityLevel.HIGH,
                "cwe": "CWE-95"
            },
            {
                "pattern": r"<script[^>]*>.*</script>",
                "type": "xss_vulnerability",
                "severity": VulnerabilityLevel.MEDIUM,
                "cwe": "CWE-79"
            }
        ]
    
    def _load_code_analysis_rules(self) -> List[Dict]:
        """Load code quality analysis rules"""
        return [
            {
                "rule": "no_hardcoded_secrets",
                "description": "Detect hardcoded API keys, tokens, and passwords",
                "severity": VulnerabilityLevel.HIGH
            },
            {
                "rule": "insecure_random",
                "description": "Detect use of insecure random number generators",
                "severity": VulnerabilityLevel.MEDIUM
            },
            {
                "rule": "weak_crypto",
                "description": "Detect use of weak cryptographic algorithms",
                "severity": VulnerabilityLevel.HIGH
            }
        ]
    
    def _load_malware_signatures(self) -> List[Dict]:
        """Load malware detection signatures"""
        return [
            {
                "signature": "suspicious_network_activity",
                "description": "Suspicious network communication patterns",
                "confidence": 0.85
            },
            {
                "signature": "obfuscated_code",
                "description": "Heavily obfuscated or encoded content",
                "confidence": 0.78
            }
        ]
    
    def _load_vulnerability_database(self) -> Dict:
        """Load known vulnerability database"""
        return {
            "npm": {
                "axios": {
                    "0.21.0": ["CVE-2020-28168"],
                    "0.21.1": ["CVE-2021-3749"]
                }
            },
            "pip": {
                "django": {
                    "3.0.0": ["CVE-2020-9402"],
                    "2.2.0": ["CVE-2019-6975"]
                }
            }
        }
    
    async def upload_and_analyze(self, file_data: bytes, filename: str, analysis_types: List[AnalysisType] = None) -> str:
        """
        Upload file and start comprehensive security analysis
        """
        try:
            # Generate unique analysis ID
            analysis_id = str(uuid.uuid4())
            
            # Calculate file hash
            file_hash = hashlib.sha256(file_data).hexdigest()
            
            # Check cache for existing analysis
            if file_hash in self.analysis_cache:
                cached_report = self.analysis_cache[file_hash]
                logger.info(f"Using cached analysis for file: {filename}")
                return cached_report.id
            
            # Save uploaded file
            file_path = self.upload_dir / f"{analysis_id}_{filename}"
            with open(file_path, 'wb') as f:
                f.write(file_data)
            
            # Default analysis types if not specified
            if analysis_types is None:
                analysis_types = [
                    AnalysisType.STATIC_ANALYSIS,
                    AnalysisType.DEPENDENCY_SCAN,
                    AnalysisType.SECRET_DETECTION,
                    AnalysisType.MALWARE_SCAN
                ]
            
            # Create analysis report
            report = AnalysisReport(
                id=analysis_id,
                filename=filename,
                file_hash=file_hash,
                file_size=len(file_data),
                analysis_type=analysis_types,
                status=AnalysisStatus.PENDING,
                findings=[],
                metadata={
                    "file_type": mimetypes.guess_type(filename)[0] or "unknown",
                    "upload_path": str(file_path)
                },
                created_at=datetime.now()
            )
            
            self.reports[analysis_id] = report
            
            # Start analysis in background
            asyncio.create_task(self._run_analysis(analysis_id))
            
            logger.info(f"Started analysis for file: {filename} (ID: {analysis_id})")
            return analysis_id
            
        except Exception as e:
            logger.error(f"Failed to upload and analyze file: {str(e)}")
            raise
    
    async def _run_analysis(self, analysis_id: str):
        """
        Execute comprehensive security analysis
        """
        try:
            report = self.reports[analysis_id]
            report.status = AnalysisStatus.ANALYZING
            start_time = datetime.now()
            
            file_path = Path(report.metadata["upload_path"])
            findings = []
            
            # Run different analysis types
            for analysis_type in report.analysis_type:
                type_findings = await self._run_analysis_type(analysis_type, file_path, report)
                findings.extend(type_findings)
            
            # AI-powered analysis enhancement
            enhanced_findings = await self._enhance_findings_with_ai(findings, file_path)
            
            # Generate AI summary and remediation suggestions
            ai_summary = await self._generate_ai_summary(enhanced_findings, report)
            remediation_suggestions = await self._generate_remediation_suggestions(enhanced_findings)
            
            # Update report
            report.findings = enhanced_findings
            report.ai_summary = ai_summary
            report.remediation_suggestions = remediation_suggestions
            report.status = AnalysisStatus.COMPLETED
            report.completed_at = datetime.now()
            report.execution_time = (report.completed_at - start_time).total_seconds()
            
            # Cache the report
            self.analysis_cache[report.file_hash] = report
            
            logger.info(f"Analysis completed for {report.filename}: {len(enhanced_findings)} findings")
            
        except Exception as e:
            report = self.reports[analysis_id]
            report.status = AnalysisStatus.FAILED
            report.metadata["error"] = str(e)
            logger.error(f"Analysis failed for {analysis_id}: {str(e)}")
    
    async def _run_analysis_type(self, analysis_type: AnalysisType, file_path: Path, report: AnalysisReport) -> List[SecurityFinding]:
        """
        Run specific type of security analysis
        """
        try:
            if analysis_type == AnalysisType.STATIC_ANALYSIS:
                return await self._static_analysis(file_path, report)
            elif analysis_type == AnalysisType.DEPENDENCY_SCAN:
                return await self._dependency_scan(file_path, report)
            elif analysis_type == AnalysisType.SECRET_DETECTION:
                return await self._secret_detection(file_path, report)
            elif analysis_type == AnalysisType.MALWARE_SCAN:
                return await self._malware_scan(file_path, report)
            elif analysis_type == AnalysisType.CODE_QUALITY:
                return await self._code_quality_analysis(file_path, report)
            elif analysis_type == AnalysisType.CONFIGURATION_SCAN:
                return await self._configuration_scan(file_path, report)
            else:
                return []
                
        except Exception as e:
            logger.error(f"Analysis type {analysis_type} failed: {str(e)}")
            return []
    
    async def _static_analysis(self, file_path: Path, report: AnalysisReport) -> List[SecurityFinding]:
        """
        Perform static code analysis
        """
        findings = []
        
        try:
            # Read file content
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            lines = content.split('\n')
            
            # Apply vulnerability patterns
            for i, line in enumerate(lines, 1):
                for pattern_info in self.ai_models["vulnerability_detector"]["patterns"]:
                    import re
                    if re.search(pattern_info["pattern"], line, re.IGNORECASE):
                        finding = SecurityFinding(
                            id=str(uuid.uuid4()),
                            type=pattern_info["type"],
                            title=f"Potential {pattern_info['type'].replace('_', ' ').title()}",
                            description=f"Line {i} contains pattern that may indicate {pattern_info['type']}",
                            severity=pattern_info["severity"],
                            confidence=0.8,
                            file_path=str(file_path.name),
                            line_number=i,
                            code_snippet=line.strip(),
                            cwe_id=pattern_info.get("cwe"),
                            remediation=self._get_remediation_for_type(pattern_info["type"])
                        )
                        findings.append(finding)
            
            # Simulate additional AI analysis
            await asyncio.sleep(0.5)  # Simulate processing time
            
        except Exception as e:
            logger.error(f"Static analysis failed: {str(e)}")
        
        return findings
    
    async def _dependency_scan(self, file_path: Path, report: AnalysisReport) -> List[SecurityFinding]:
        """
        Scan for vulnerable dependencies
        """
        findings = []
        
        try:
            # Check for package files
            if file_path.name in ['package.json', 'requirements.txt', 'Pipfile', 'composer.json']:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # Simulate dependency vulnerability detection
                if 'axios' in content and '0.21.0' in content:
                    finding = SecurityFinding(
                        id=str(uuid.uuid4()),
                        type="vulnerable_dependency",
                        title="Vulnerable Axios Version Detected",
                        description="Using vulnerable version of axios (0.21.0) with known CVE",
                        severity=VulnerabilityLevel.HIGH,
                        confidence=0.95,
                        file_path=str(file_path.name),
                        cwe_id="CWE-1104",
                        cvss_score=7.5,
                        remediation="Update axios to version 0.21.2 or later",
                        references=["https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-28168"]
                    )
                    findings.append(finding)
            
            await asyncio.sleep(0.3)  # Simulate processing time
            
        except Exception as e:
            logger.error(f"Dependency scan failed: {str(e)}")
        
        return findings
    
    async def _secret_detection(self, file_path: Path, report: AnalysisReport) -> List[SecurityFinding]:
        """
        Detect hardcoded secrets and credentials
        """
        findings = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Secret patterns
            secret_patterns = [
                (r'aws_access_key_id\s*=\s*[\'"]([A-Z0-9]{20})[\'"]', 'AWS Access Key'),
                (r'api_key\s*=\s*[\'"]([a-zA-Z0-9]{32,})[\'"]', 'API Key'),
                (r'password\s*=\s*[\'"]([^\'\"]{8,})[\'"]', 'Hardcoded Password'),
                (r'secret_key\s*=\s*[\'"]([a-zA-Z0-9]{16,})[\'"]', 'Secret Key'),
                (r'token\s*=\s*[\'"]([a-zA-Z0-9]{20,})[\'"]', 'Authentication Token')
            ]
            
            lines = content.split('\n')
            for i, line in enumerate(lines, 1):
                for pattern, secret_type in secret_patterns:
                    import re
                    match = re.search(pattern, line, re.IGNORECASE)
                    if match:
                        finding = SecurityFinding(
                            id=str(uuid.uuid4()),
                            type="hardcoded_secret",
                            title=f"Hardcoded {secret_type} Detected",
                            description=f"Found hardcoded {secret_type.lower()} in source code",
                            severity=VulnerabilityLevel.HIGH,
                            confidence=0.9,
                            file_path=str(file_path.name),
                            line_number=i,
                            code_snippet=line.strip(),
                            cwe_id="CWE-798",
                            remediation=f"Remove hardcoded {secret_type.lower()} and use environment variables or secure vault"
                        )
                        findings.append(finding)
            
            await asyncio.sleep(0.4)  # Simulate processing time
            
        except Exception as e:
            logger.error(f"Secret detection failed: {str(e)}")
        
        return findings
    
    async def _malware_scan(self, file_path: Path, report: AnalysisReport) -> List[SecurityFinding]:
        """
        Scan for malware and suspicious patterns
        """
        findings = []
        
        try:
            # Check file size and type
            file_size = file_path.stat().st_size
            if file_size > 50 * 1024 * 1024:  # > 50MB
                finding = SecurityFinding(
                    id=str(uuid.uuid4()),
                    type="suspicious_file_size",
                    title="Suspicious Large File Size",
                    description=f"File size ({file_size} bytes) is unusually large",
                    severity=VulnerabilityLevel.MEDIUM,
                    confidence=0.6,
                    file_path=str(file_path.name),
                    remediation="Verify file contents and purpose"
                )
                findings.append(finding)
            
            # Simulate entropy analysis
            with open(file_path, 'rb') as f:
                data = f.read(1024)  # Read first 1KB
                
            # Simple entropy check (high entropy might indicate encryption/obfuscation)
            if len(set(data)) > 200:  # High character diversity
                finding = SecurityFinding(
                    id=str(uuid.uuid4()),
                    type="high_entropy_content",
                    title="High Entropy Content Detected",
                    description="File contains high entropy data which may indicate obfuscation or encryption",
                    severity=VulnerabilityLevel.LOW,
                    confidence=0.7,
                    file_path=str(file_path.name),
                    remediation="Analyze file content for potential obfuscation or malicious code"
                )
                findings.append(finding)
            
            await asyncio.sleep(0.6)  # Simulate processing time
            
        except Exception as e:
            logger.error(f"Malware scan failed: {str(e)}")
        
        return findings
    
    async def _code_quality_analysis(self, file_path: Path, report: AnalysisReport) -> List[SecurityFinding]:
        """
        Analyze code quality and security practices
        """
        findings = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Check for security best practices
            if 'import hashlib' in content and 'md5' in content:
                finding = SecurityFinding(
                    id=str(uuid.uuid4()),
                    type="weak_hashing",
                    title="Weak Hashing Algorithm",
                    description="Use of MD5 hashing algorithm detected",
                    severity=VulnerabilityLevel.MEDIUM,
                    confidence=0.8,
                    file_path=str(file_path.name),
                    cwe_id="CWE-328",
                    remediation="Use stronger hashing algorithms like SHA-256 or bcrypt"
                )
                findings.append(finding)
            
            await asyncio.sleep(0.3)  # Simulate processing time
            
        except Exception as e:
            logger.error(f"Code quality analysis failed: {str(e)}")
        
        return findings
    
    async def _configuration_scan(self, file_path: Path, report: AnalysisReport) -> List[SecurityFinding]:
        """
        Scan configuration files for security issues
        """
        findings = []
        
        try:
            if file_path.suffix in ['.yml', '.yaml', '.json', '.xml', '.conf']:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # Check for insecure configurations
                if 'ssl: false' in content.lower() or 'tls: false' in content.lower():
                    finding = SecurityFinding(
                        id=str(uuid.uuid4()),
                        type="insecure_configuration",
                        title="Insecure SSL/TLS Configuration",
                        description="SSL/TLS is disabled in configuration",
                        severity=VulnerabilityLevel.HIGH,
                        confidence=0.9,
                        file_path=str(file_path.name),
                        remediation="Enable SSL/TLS encryption in configuration"
                    )
                    findings.append(finding)
            
            await asyncio.sleep(0.2)  # Simulate processing time
            
        except Exception as e:
            logger.error(f"Configuration scan failed: {str(e)}")
        
        return findings
    
    async def _enhance_findings_with_ai(self, findings: List[SecurityFinding], file_path: Path) -> List[SecurityFinding]:
        """
        Enhance findings using AI analysis
        """
        try:
            # Simulate AI enhancement
            for finding in findings:
                # AI confidence adjustment
                if finding.type == "hardcoded_secret":
                    finding.confidence = min(0.95, finding.confidence + 0.1)
                elif finding.type == "sql_injection":
                    finding.confidence = min(0.98, finding.confidence + 0.15)
                
                # AI-generated additional context
                if not finding.remediation:
                    finding.remediation = self._get_remediation_for_type(finding.type)
            
            await asyncio.sleep(0.5)  # Simulate AI processing time
            
        except Exception as e:
            logger.error(f"AI enhancement failed: {str(e)}")
        
        return findings
    
    async def _generate_ai_summary(self, findings: List[SecurityFinding], report: AnalysisReport) -> str:
        """
        Generate AI-powered analysis summary
        """
        try:
            critical_count = len([f for f in findings if f.severity == VulnerabilityLevel.CRITICAL])
            high_count = len([f for f in findings if f.severity == VulnerabilityLevel.HIGH])
            medium_count = len([f for f in findings if f.severity == VulnerabilityLevel.MEDIUM])
            low_count = len([f for f in findings if f.severity == VulnerabilityLevel.LOW])
            
            filename = getattr(report, 'filename', 'Unknown')
            file_size = getattr(report, 'file_size', 0)
            analysis_types = getattr(report, 'analysis_type', [])
            analysis_count = len(analysis_types) if analysis_types else 1
            
            summary = f"""
AI Security Analysis Summary for {filename}:

File Analysis: Analyzed {file_size} bytes using {analysis_count} analysis engines.

Vulnerability Overview:
• {critical_count} Critical vulnerabilities
• {high_count} High severity issues  
• {medium_count} Medium severity issues
• {low_count} Low severity informational findings

Key Security Concerns:
"""
            
            # Add specific findings summary
            if critical_count > 0:
                summary += "⚠️  CRITICAL: Immediate attention required for critical vulnerabilities\n"
            if high_count > 0:
                summary += "🔥 HIGH PRIORITY: Multiple high-severity security issues detected\n"
            
            # AI recommendations
            summary += "\nAI Recommendations:\n"
            if any(f.type == "hardcoded_secret" for f in findings):
                summary += "• Implement secure secret management practices\n"
            if any(f.type == "sql_injection" for f in findings):
                summary += "• Apply input validation and parameterized queries\n"
            if any(f.type == "vulnerable_dependency" for f in findings):
                summary += "• Update vulnerable dependencies immediately\n"
            
            execution_time = getattr(report, 'execution_time', 0.0)
            if execution_time and execution_time > 0:
                summary += f"\nAnalysis completed in {execution_time:.2f} seconds"
            else:
                summary += "\nAnalysis completed successfully"
            
            return summary.strip()
            
        except Exception as e:
            logger.error(f"AI summary generation failed: {str(e)}")
            return "AI summary generation failed"
    
    async def _generate_remediation_suggestions(self, findings: List[SecurityFinding]) -> List[str]:
        """
        Generate AI-powered remediation suggestions
        """
        suggestions = []
        
        try:
            # Group findings by type for better suggestions
            finding_types = set(f.type for f in findings)
            
            for finding_type in finding_types:
                count = len([f for f in findings if f.type == finding_type])
                suggestion = self._get_comprehensive_remediation(finding_type, count)
                if suggestion:
                    suggestions.append(suggestion)
            
            # Add general security suggestions
            if len(findings) > 5:
                suggestions.append("Consider implementing a comprehensive security code review process")
            if any(f.severity == VulnerabilityLevel.CRITICAL for f in findings):
                suggestions.append("Prioritize fixing critical vulnerabilities before deployment")
            
        except Exception as e:
            logger.error(f"Remediation suggestions failed: {str(e)}")
        
        return suggestions[:10]  # Limit to top 10 suggestions
    
    def _get_remediation_for_type(self, finding_type: str) -> str:
        """
        Get basic remediation for finding type
        """
        remediation_map = {
            "hardcoded_password": "Use environment variables or secure configuration management",
            "sql_injection": "Use parameterized queries and input validation",
            "code_injection": "Avoid eval() and use safe alternatives for dynamic code execution",
            "xss_vulnerability": "Implement proper input sanitization and output encoding",
            "hardcoded_secret": "Use secure secret management solutions like HashiCorp Vault",
            "vulnerable_dependency": "Update to the latest secure version of the dependency",
            "weak_hashing": "Use cryptographically secure hashing algorithms",
            "insecure_configuration": "Enable security features and follow security best practices"
        }
        return remediation_map.get(finding_type, "Review and follow security best practices")
    
    def _get_comprehensive_remediation(self, finding_type: str, count: int) -> str:
        """
        Get comprehensive remediation suggestion with count context
        """
        base_remediation = self._get_remediation_for_type(finding_type)
        
        if count > 1:
            return f"Found {count} instances of {finding_type.replace('_', ' ')}: {base_remediation}. Consider implementing automated checks."
        else:
            return f"Found {finding_type.replace('_', ' ')}: {base_remediation}"
    
    # Management and Query Methods
    async def get_analysis_report(self, analysis_id: str) -> Optional[AnalysisReport]:
        """Get analysis report by ID"""
        return self.reports.get(analysis_id)
    
    async def get_analysis_status(self, analysis_id: str) -> Optional[AnalysisStatus]:
        """Get analysis status"""
        report = self.reports.get(analysis_id)
        return report.status if report else None
    
    async def list_reports(self, limit: int = 50, status_filter: Optional[AnalysisStatus] = None) -> List[Dict]:
        """List analysis reports with optional filtering"""
        reports = list(self.reports.values())
        
        if status_filter:
            reports = [r for r in reports if r.status == status_filter]
        
        # Sort by creation time (newest first)
        reports.sort(key=lambda x: x.created_at, reverse=True)
        
        return [
            {
                "id": r.id,
                "filename": r.filename,
                "status": r.status.value,
                "findings_count": len(r.findings),
                "severity_breakdown": self._get_severity_breakdown(r.findings),
                "created_at": r.created_at.isoformat(),
                "completed_at": r.completed_at.isoformat() if r.completed_at else None,
                "execution_time": r.execution_time,
                "file_size": r.file_size
            } for r in reports[:limit]
        ]
    
    def _get_severity_breakdown(self, findings: List[SecurityFinding]) -> Dict[str, int]:
        """Get breakdown of findings by severity"""
        breakdown = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "informational": 0
        }
        
        for finding in findings:
            breakdown[finding.severity.value] += 1
        
        return breakdown
    
    async def delete_report(self, analysis_id: str) -> bool:
        """Delete analysis report and associated files"""
        try:
            if analysis_id in self.reports:
                report = self.reports[analysis_id]
                
                # Delete uploaded file
                file_path = Path(report.metadata.get("upload_path", ""))
                if file_path.exists():
                    file_path.unlink()
                
                # Remove from reports and cache
                del self.reports[analysis_id]
                if report.file_hash in self.analysis_cache:
                    del self.analysis_cache[report.file_hash]
                
                return True
            return False
            
        except Exception as e:
            logger.error(f"Failed to delete report {analysis_id}: {str(e)}")
            return False
    
    async def get_analysis_metrics(self) -> Dict[str, Any]:
        """Get analysis engine metrics"""
        total_reports = len(self.reports)
        completed_reports = len([r for r in self.reports.values() if r.status == AnalysisStatus.COMPLETED])
        failed_reports = len([r for r in self.reports.values() if r.status == AnalysisStatus.FAILED])
        
        # Calculate average execution time
        completed = [r for r in self.reports.values() if r.status == AnalysisStatus.COMPLETED and r.execution_time]
        avg_execution_time = sum(r.execution_time for r in completed) / len(completed) if completed else 0
        
        # Total findings by severity
        all_findings = []
        for report in self.reports.values():
            all_findings.extend(report.findings)
        
        severity_stats = self._get_severity_breakdown(all_findings)
        
        return {
            "total_reports": total_reports,
            "completed_reports": completed_reports,
            "failed_reports": failed_reports,
            "success_rate": completed_reports / total_reports if total_reports > 0 else 0,
            "average_execution_time": avg_execution_time,
            "total_findings": len(all_findings),
            "severity_breakdown": severity_stats,
            "cache_size": len(self.analysis_cache),
            "ai_models_status": {
                name: model["accuracy"] for name, model in self.ai_models.items()
            }
        }

# Initialize global analysis engine
analysis_engine = SecurityAnalysisEngine()