"""
SAST (Static Application Security Testing) scanner implementations
"""

import os
import json
from typing import Dict, List, Any, Optional
from datetime import datetime
import uuid

from .base import BaseScanner, ScanType, ScanResult, Finding, SeverityLevel


class BanditScanner(BaseScanner):
    """Bandit SAST scanner for Python code"""
    
    def __init__(self):
        super().__init__(ScanType.SAST)
        self.tool_name = "bandit"
    
    async def scan(self, target: str, options: Optional[Dict[str, Any]] = None) -> ScanResult:
        """Execute Bandit SAST scan"""
        if options is None:
            options = {}
        
        scan_id = str(uuid.uuid4())
        start_time = datetime.utcnow()
        
        self.logger.info(f"Starting Bandit scan {scan_id} for target: {target}")
        
        if not self.validate_target(target):
            return ScanResult(
                scan_id=scan_id,
                scan_type=self.scan_type,
                status="failed",
                start_time=start_time,
                end_time=datetime.utcnow(),
                findings=[],
                metadata={"tool": self.tool_name, "target": target},
                error_message="Invalid target path"
            )
        
        try:
            # Prepare bandit command
            command = [
                "bandit",
                "-r",  # recursive
                "-f", "json",  # JSON output
                target
            ]
            
            # Add options
            if options.get("exclude_paths"):
                command.extend(["--exclude", ",".join(options["exclude_paths"])])
            
            if options.get("severity_level"):
                command.extend(["-ll", options["severity_level"]])
            
            if options.get("confidence_level"):
                command.extend(["-i", options["confidence_level"]])
            
            # Run bandit
            stdout, stderr, returncode = await self.run_command(command, timeout=600)
            
            end_time = datetime.utcnow()
            
            # Parse results
            findings = []
            if stdout:
                try:
                    findings = self.parse_results(stdout)
                except Exception as e:
                    self.logger.error(f"Failed to parse Bandit results: {e}")
            
            status = "completed" if returncode == 0 or returncode == 1 else "failed"  # Bandit returns 1 when issues found
            
            return ScanResult(
                scan_id=scan_id,
                scan_type=self.scan_type,
                status=status,
                start_time=start_time,
                end_time=end_time,
                findings=[finding.__dict__ for finding in findings],
                metadata={
                    "tool": self.tool_name,
                    "target": target,
                    "command": " ".join(command),
                    "return_code": returncode
                },
                raw_output=stdout,
                error_message=stderr if stderr else None
            )
            
        except Exception as e:
            self.logger.error(f"Bandit scan failed: {e}")
            return ScanResult(
                scan_id=scan_id,
                scan_type=self.scan_type,
                status="failed",
                start_time=start_time,
                end_time=datetime.utcnow(),
                findings=[],
                metadata={"tool": self.tool_name, "target": target},
                error_message=str(e)
            )
    
    def parse_results(self, raw_output: str) -> List[Finding]:
        """Parse Bandit JSON output"""
        findings = []
        
        try:
            data = json.loads(raw_output)
            
            for result in data.get("results", []):
                finding = Finding(
                    title=result.get("test_name", "Unknown Issue"),
                    description=result.get("issue_text", ""),
                    severity=self.normalize_severity(result.get("issue_severity", "low")),
                    file_path=result.get("filename"),
                    line_number=result.get("line_number"),
                    column_number=result.get("col_offset"),
                    cwe_id=result.get("issue_cwe", {}).get("id") if result.get("issue_cwe") else None,
                    rule_id=result.get("test_id"),
                    confidence=result.get("issue_confidence", "unknown").lower(),
                    code_snippet=result.get("code") or self.extract_code_snippet(
                        result.get("filename", ""), 
                        result.get("line_number", 0)
                    ) if result.get("filename") and result.get("line_number") else None
                )
                
                findings.append(finding)
                
        except json.JSONDecodeError as e:
            self.logger.error(f"Failed to parse Bandit JSON output: {e}")
        
        return findings


class SemgrepScanner(BaseScanner):
    """Semgrep SAST scanner for multiple languages"""
    
    def __init__(self):
        super().__init__(ScanType.SAST)
        self.tool_name = "semgrep"
    
    async def scan(self, target: str, options: Optional[Dict[str, Any]] = None) -> ScanResult:
        """Execute Semgrep SAST scan"""
        if options is None:
            options = {}
        
        scan_id = str(uuid.uuid4())
        start_time = datetime.utcnow()
        
        self.logger.info(f"Starting Semgrep scan {scan_id} for target: {target}")
        
        if not self.validate_target(target):
            return ScanResult(
                scan_id=scan_id,
                scan_type=self.scan_type,
                status="failed",
                start_time=start_time,
                end_time=datetime.utcnow(),
                findings=[],
                metadata={"tool": self.tool_name, "target": target},
                error_message="Invalid target path"
            )
        
        try:
            # Prepare semgrep command
            command = [
                "semgrep",
                "--json",
                "--config=auto",  # Use default rulesets
                target
            ]
            
            # Add custom rulesets if specified
            if options.get("rulesets"):
                command = [
                    "semgrep",
                    "--json",
                    f"--config={','.join(options['rulesets'])}",
                    target
                ]
            
            # Add severity filter
            if options.get("severity"):
                command.extend(["--severity", options["severity"]])
            
            # Run semgrep
            stdout, stderr, returncode = await self.run_command(command, timeout=900)
            
            end_time = datetime.utcnow()
            
            # Parse results
            findings = []
            if stdout:
                try:
                    findings = self.parse_results(stdout)
                except Exception as e:
                    self.logger.error(f"Failed to parse Semgrep results: {e}")
            
            status = "completed" if returncode == 0 else "failed"
            
            return ScanResult(
                scan_id=scan_id,
                scan_type=self.scan_type,
                status=status,
                start_time=start_time,
                end_time=end_time,
                findings=[finding.__dict__ for finding in findings],
                metadata={
                    "tool": self.tool_name,
                    "target": target,
                    "command": " ".join(command),
                    "return_code": returncode
                },
                raw_output=stdout,
                error_message=stderr if stderr else None
            )
            
        except Exception as e:
            self.logger.error(f"Semgrep scan failed: {e}")
            return ScanResult(
                scan_id=scan_id,
                scan_type=self.scan_type,
                status="failed",
                start_time=start_time,
                end_time=datetime.utcnow(),
                findings=[],
                metadata={"tool": self.tool_name, "target": target},
                error_message=str(e)
            )
    
    def parse_results(self, raw_output: str) -> List[Finding]:
        """Parse Semgrep JSON output"""
        findings = []
        
        try:
            data = json.loads(raw_output)
            
            for result in data.get("results", []):
                # Extract location info
                start_pos = result.get("start", {})
                end_pos = result.get("end", {})
                
                finding = Finding(
                    title=result.get("check_id", "Unknown Issue"),
                    description=result.get("message", ""),
                    severity=self.normalize_severity(result.get("extra", {}).get("severity", "info")),
                    file_path=result.get("path"),
                    line_number=start_pos.get("line"),
                    column_number=start_pos.get("col"),
                    rule_id=result.get("check_id"),
                    confidence="high",  # Semgrep generally has high confidence
                    code_snippet=self.extract_code_snippet(
                        result.get("path", ""), 
                        start_pos.get("line", 0)
                    ) if result.get("path") and start_pos.get("line") else None
                )
                
                # Add CWE if available
                if "cwe" in result.get("extra", {}).get("metadata", {}):
                    finding.cwe_id = f"CWE-{result['extra']['metadata']['cwe'][0]}"
                
                findings.append(finding)
                
        except json.JSONDecodeError as e:
            self.logger.error(f"Failed to parse Semgrep JSON output: {e}")
        
        return findings


class SafetyScanner(BaseScanner):
    """Safety scanner for Python dependency vulnerabilities"""
    
    def __init__(self):
        super().__init__(ScanType.DEPENDENCY)
        self.tool_name = "safety"
    
    async def scan(self, target: str, options: Optional[Dict[str, Any]] = None) -> ScanResult:
        """Execute Safety dependency scan"""
        if options is None:
            options = {}
        
        scan_id = str(uuid.uuid4())
        start_time = datetime.utcnow()
        
        self.logger.info(f"Starting Safety scan {scan_id} for target: {target}")
        
        try:
            # Look for requirements.txt or similar files
            requirements_files = []
            if os.path.isdir(target):
                for filename in ["requirements.txt", "Pipfile", "pyproject.toml", "poetry.lock"]:
                    filepath = os.path.join(target, filename)
                    if os.path.exists(filepath):
                        requirements_files.append(filepath)
            elif target.endswith((".txt", ".toml", ".lock")):
                if os.path.exists(target):
                    requirements_files.append(target)
            
            if not requirements_files:
                return ScanResult(
                    scan_id=scan_id,
                    scan_type=self.scan_type,
                    status="failed",
                    start_time=start_time,
                    end_time=datetime.utcnow(),
                    findings=[],
                    metadata={"tool": self.tool_name, "target": target},
                    error_message="No requirements files found"
                )
            
            all_findings = []
            combined_output = []
            
            for req_file in requirements_files:
                # Prepare safety command
                command = [
                    "safety",
                    "check",
                    "--json",
                    "--file", req_file
                ]
                
                # Run safety
                stdout, stderr, returncode = await self.run_command(command, timeout=300)
                
                if stdout:
                    combined_output.append(f"=== {req_file} ===\n{stdout}")
                    try:
                        findings = self.parse_results(stdout, req_file)
                        all_findings.extend(findings)
                    except Exception as e:
                        self.logger.error(f"Failed to parse Safety results for {req_file}: {e}")
            
            end_time = datetime.utcnow()
            
            return ScanResult(
                scan_id=scan_id,
                scan_type=self.scan_type,
                status="completed",
                start_time=start_time,
                end_time=end_time,
                findings=[finding.__dict__ for finding in all_findings],
                metadata={
                    "tool": self.tool_name,
                    "target": target,
                    "files_scanned": requirements_files
                },
                raw_output="\n\n".join(combined_output)
            )
            
        except Exception as e:
            self.logger.error(f"Safety scan failed: {e}")
            return ScanResult(
                scan_id=scan_id,
                scan_type=self.scan_type,
                status="failed",
                start_time=start_time,
                end_time=datetime.utcnow(),
                findings=[],
                metadata={"tool": self.tool_name, "target": target},
                error_message=str(e)
            )
    
    def parse_results(self, raw_output: str, requirements_file: str = "") -> List[Finding]:
        """Parse Safety JSON output"""
        findings = []
        
        try:
            data = json.loads(raw_output)
            
            for vulnerability in data:
                finding = Finding(
                    title=f"Vulnerable dependency: {vulnerability.get('package_name', 'Unknown')}",
                    description=vulnerability.get("advisory", ""),
                    severity=self.normalize_severity(vulnerability.get("vulnerability_id", "").split("-")[0] if vulnerability.get("vulnerability_id") else "medium"),
                    file_path=requirements_file,
                    cve_id=vulnerability.get("vulnerability_id"),
                    rule_id=f"safety-{vulnerability.get('package_name', 'unknown')}",
                    confidence="high"
                )
                
                findings.append(finding)
                
        except json.JSONDecodeError as e:
            self.logger.error(f"Failed to parse Safety JSON output: {e}")
        
        return findings