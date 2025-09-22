"""
Base scanner interface and common utilities
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum
import asyncio
import subprocess
import tempfile
import os
import json
import logging
from datetime import datetime
from app.core.config import settings

logger = logging.getLogger(__name__)


class ScanType(Enum):
    """Supported scan types"""
    SAST = "sast"
    DAST = "dast"
    DEPENDENCY = "dependency"
    SECRET = "secret"
    CONTAINER = "container"


class SeverityLevel(Enum):
    """Vulnerability severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class ScanResult:
    """Scan result data structure"""
    scan_id: str
    scan_type: ScanType
    status: str
    start_time: datetime
    end_time: Optional[datetime]
    findings: List[Dict[str, Any]]
    metadata: Dict[str, Any]
    raw_output: Optional[str] = None
    error_message: Optional[str] = None


@dataclass
class Finding:
    """Individual vulnerability finding"""
    title: str
    description: str
    severity: SeverityLevel
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    column_number: Optional[int] = None
    cwe_id: Optional[str] = None
    cve_id: Optional[str] = None
    rule_id: Optional[str] = None
    confidence: Optional[str] = None
    code_snippet: Optional[str] = None
    remediation: Optional[str] = None


class BaseScanner(ABC):
    """Base class for all security scanners"""
    
    def __init__(self, scan_type: ScanType):
        self.scan_type = scan_type
        self.logger = logging.getLogger(f"scanner.{scan_type.value}")
    
    @abstractmethod
    async def scan(self, target: str, options: Dict[str, Any] = None) -> ScanResult:
        """Execute the security scan"""
        pass
    
    @abstractmethod
    def parse_results(self, raw_output: str) -> List[Finding]:
        """Parse raw scanner output into structured findings"""
        pass
    
    async def run_command(self, command: List[str], cwd: Optional[str] = None, timeout: int = 300) -> tuple[str, str, int]:
        """
        Run a shell command asynchronously with timeout
        Returns (stdout, stderr, returncode)
        """
        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout
            )
            
            return (
                stdout.decode('utf-8', errors='ignore'),
                stderr.decode('utf-8', errors='ignore'),
                process.returncode
            )
            
        except asyncio.TimeoutError:
            self.logger.error(f"Command timeout: {' '.join(command)}")
            if 'process' in locals():
                process.kill()
                await process.wait()
            raise Exception(f"Command timed out after {timeout} seconds")
        
        except Exception as e:
            self.logger.error(f"Command execution failed: {e}")
            raise Exception(f"Command execution failed: {str(e)}")
    
    def create_temp_directory(self) -> str:
        """Create a temporary directory for scan operations"""
        return tempfile.mkdtemp(prefix=f"{self.scan_type.value}_")
    
    def cleanup_temp_directory(self, temp_dir: str):
        """Clean up temporary directory"""
        try:
            import shutil
            shutil.rmtree(temp_dir)
        except Exception as e:
            self.logger.warning(f"Failed to cleanup temp directory {temp_dir}: {e}")
    
    def validate_target(self, target: str) -> bool:
        """Validate scan target"""
        if not target:
            return False
        
        # Check if target is a valid file/directory path
        if os.path.exists(target):
            return True
        
        # Check if target is a valid URL for DAST
        if self.scan_type == ScanType.DAST:
            import re
            url_pattern = re.compile(
                r'^https?://'  # http:// or https://
                r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain...
                r'localhost|'  # localhost...
                r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
                r'(?::\d+)?'  # optional port
                r'(?:/?|[/?]\S+)$', re.IGNORECASE)
            return url_pattern.match(target) is not None
        
        return False
    
    def extract_code_snippet(self, file_path: str, line_number: int, context_lines: int = 3) -> Optional[str]:
        """Extract code snippet around the vulnerability"""
        try:
            if not os.path.exists(file_path):
                return None
            
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            start_line = max(0, line_number - context_lines - 1)
            end_line = min(len(lines), line_number + context_lines)
            
            snippet_lines = []
            for i in range(start_line, end_line):
                marker = ">>> " if i == line_number - 1 else "    "
                snippet_lines.append(f"{marker}{i + 1:4d}: {lines[i].rstrip()}")
            
            return "\n".join(snippet_lines)
            
        except Exception as e:
            self.logger.warning(f"Failed to extract code snippet from {file_path}:{line_number}: {e}")
            return None
    
    def normalize_severity(self, severity: str) -> SeverityLevel:
        """Normalize severity level from different scanner outputs"""
        severity_map = {
            # Common mappings
            'critical': SeverityLevel.CRITICAL,
            'high': SeverityLevel.HIGH,
            'medium': SeverityLevel.MEDIUM,
            'low': SeverityLevel.LOW,
            'info': SeverityLevel.INFO,
            'information': SeverityLevel.INFO,
            
            # Bandit mappings
            'high_severity': SeverityLevel.HIGH,
            'medium_severity': SeverityLevel.MEDIUM,
            'low_severity': SeverityLevel.LOW,
            
            # Semgrep mappings
            'error': SeverityLevel.HIGH,
            'warning': SeverityLevel.MEDIUM,
            'note': SeverityLevel.LOW,
            
            # Safety mappings
            'high_vulnerability': SeverityLevel.HIGH,
            'medium_vulnerability': SeverityLevel.MEDIUM,
            'low_vulnerability': SeverityLevel.LOW,
        }
        
        normalized = severity.lower().replace('-', '_').replace(' ', '_')
        return severity_map.get(normalized, SeverityLevel.INFO)
    
    def get_cwe_description(self, cwe_id: str) -> Optional[str]:
        """Get CWE description (basic implementation)"""
        cwe_descriptions = {
            'CWE-20': 'Improper Input Validation',
            'CWE-22': 'Path Traversal',
            'CWE-79': 'Cross-site Scripting (XSS)',
            'CWE-89': 'SQL Injection',
            'CWE-94': 'Code Injection',
            'CWE-200': 'Information Exposure',
            'CWE-250': 'Execution with Unnecessary Privileges',
            'CWE-287': 'Improper Authentication',
            'CWE-352': 'Cross-Site Request Forgery (CSRF)',
            'CWE-502': 'Deserialization of Untrusted Data',
            'CWE-611': 'XML External Entity (XXE)',
            'CWE-798': 'Use of Hard-coded Credentials',
        }
        return cwe_descriptions.get(cwe_id)


class ScannerRegistry:
    """Registry for all available scanners"""
    
    def __init__(self):
        self._scanners: Dict[ScanType, BaseScanner] = {}
    
    def register(self, scanner: BaseScanner):
        """Register a scanner"""
        self._scanners[scanner.scan_type] = scanner
    
    def get_scanner(self, scan_type: ScanType) -> Optional[BaseScanner]:
        """Get scanner by type"""
        return self._scanners.get(scan_type)
    
    def get_available_scanners(self) -> List[ScanType]:
        """Get list of available scanner types"""
        return list(self._scanners.keys())


# Global scanner registry
scanner_registry = ScannerRegistry()