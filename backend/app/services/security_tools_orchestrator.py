"""
Professional Security Tools Integration
Integrates industry-standard security scanning tools like BurpSuite, Nessus, Semgrep, Bearer, etc.
"""

import os
import json
import asyncio
import subprocess
import tempfile
import shutil
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass
from enum import Enum
import uuid

logger = logging.getLogger(__name__)

class ScanTool(Enum):
    """Supported professional security scanning tools"""
    SEMGREP = "semgrep"
    BEARER = "bearer"
    CODEQL = "codeql"
    TRIVY = "trivy"
    BANDIT = "bandit"
    ESLINT_SECURITY = "eslint-plugin-security"
    OWASP_DEPENDENCY_CHECK = "dependency-check"
    SAFETY = "safety"
    SNYK = "snyk"
    SONARQUBE = "sonarqube"
    CHECKMARX = "checkmarx"
    VERACODE = "veracode"
    NUCLEI = "nuclei"
    NIKTO = "nikto"
    NMAP = "nmap"
    MASSCAN = "masscan"

class FileType(Enum):
    """Supported file types for analysis"""
    # Source Code
    PYTHON = "py"
    JAVASCRIPT = "js"
    TYPESCRIPT = "ts"
    JAVA = "java"
    CSHARP = "cs"
    CPP = "cpp"
    C = "c"
    GO = "go"
    RUST = "rs"
    PHP = "php"
    RUBY = "rb"
    SWIFT = "swift"
    KOTLIN = "kt"
    SCALA = "scala"
    
    # Web Technologies
    HTML = "html"
    CSS = "css"
    JSON = "json"
    XML = "xml"
    YAML = "yaml"
    
    # Documents
    PDF = "pdf"
    DOCX = "docx"
    XLSX = "xlsx"
    CSV = "csv"
    TXT = "txt"
    
    # Archives
    ZIP = "zip"
    TAR = "tar"
    GZ = "gz"
    RAR = "rar"
    
    # Logs
    LOG = "log"
    SYSLOG = "syslog"
    NGINX_LOG = "access.log"
    APACHE_LOG = "error.log"
    
    # Container/Infrastructure
    DOCKERFILE = "dockerfile"
    DOCKER_COMPOSE = "docker-compose.yml"
    KUBERNETES = "k8s.yaml"
    TERRAFORM = "tf"
    
    # Mobile
    APK = "apk"
    IPA = "ipa"
    
    # Binary
    ELF = "elf"
    PE = "exe"
    MACHO = "macho"

@dataclass
class ScanResult:
    """Standardized scan result format"""
    tool: ScanTool
    file_path: str
    vulnerability_type: str
    severity: str
    title: str
    description: str
    line_number: Optional[int] = None
    column_number: Optional[int] = None
    cwe_id: Optional[str] = None
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    confidence: Optional[str] = None
    remediation: Optional[str] = None
    references: List[str] = None
    metadata: Dict[str, Any] = None

class SecurityToolsOrchestrator:
    """Orchestrates multiple security scanning tools"""
    
    def __init__(self):
        self.tools_config = self._load_tools_configuration()
        self.installed_tools = self._detect_installed_tools()
        self.scan_rules = self._load_scan_rules()
        
    def _load_tools_configuration(self) -> Dict[str, Dict]:
        """Load configuration for each security tool"""
        return {
            ScanTool.SEMGREP.value: {
                "command": "semgrep",
                "install_cmd": "pip install semgrep",
                "docker_image": "returntocorp/semgrep",
                "config_files": ["p/security-audit", "p/owasp-top-10", "p/cwe-top-25"],
                "output_format": "json",
                "supported_files": [".py", ".js", ".ts", ".java", ".go", ".rb", ".php", ".cs"],
                "args": ["--config=auto", "--json", "--timeout=300"]
            },
            ScanTool.BEARER.value: {
                "command": "bearer",
                "install_cmd": "curl -sfL https://raw.githubusercontent.com/Bearer/bearer/main/contrib/install.sh | sh",
                "docker_image": "bearer/bearer",
                "output_format": "json",
                "supported_files": [".rb", ".js", ".ts", ".py", ".java", ".php", ".cs"],
                "args": ["scan", "--format=json", "--quiet"]
            },
            ScanTool.TRIVY.value: {
                "command": "trivy",
                "install_cmd": "curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh",
                "docker_image": "aquasec/trivy",
                "output_format": "json",
                "supported_files": ["*"],  # Supports all file types
                "args": ["fs", "--format=json", "--security-checks=vuln,secret,config"]
            },
            ScanTool.BANDIT.value: {
                "command": "bandit",
                "install_cmd": "pip install bandit",
                "docker_image": "secfigo/bandit",
                "output_format": "json",
                "supported_files": [".py"],
                "args": ["-r", "-f", "json"]
            },
            ScanTool.OWASP_DEPENDENCY_CHECK.value: {
                "command": "dependency-check",
                "install_cmd": "wget https://github.com/jeremylong/DependencyCheck/releases/download/v8.4.0/dependency-check-8.4.0-release.zip",
                "docker_image": "owasp/dependency-check",
                "output_format": "json",
                "supported_files": ["package.json", "requirements.txt", "pom.xml", "Gemfile", "composer.json"],
                "args": ["--format", "JSON", "--enableRetired"]
            },
            ScanTool.SAFETY.value: {
                "command": "safety",
                "install_cmd": "pip install safety",
                "docker_image": "pyupio/safety",
                "output_format": "json",
                "supported_files": ["requirements.txt", "Pipfile"],
                "args": ["check", "--json"]
            },
            ScanTool.NUCLEI.value: {
                "command": "nuclei",
                "install_cmd": "go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest",
                "docker_image": "projectdiscovery/nuclei",
                "output_format": "json",
                "supported_files": ["*"],  # Network/web scanning
                "args": ["-json", "-silent"]
            },
            ScanTool.CODEQL.value: {
                "command": "codeql",
                "install_cmd": "# Download from GitHub releases",
                "docker_image": "ghcr.io/github/codeql-action/codeql-runner",
                "output_format": "sarif",
                "supported_files": [".py", ".js", ".ts", ".java", ".cs", ".cpp", ".c", ".go"],
                "args": ["database", "analyze", "--format=sarif-latest"]
            }
        }
    
    def _detect_installed_tools(self) -> List[ScanTool]:
        """Detect which security tools are installed and available"""
        installed = []
        
        for tool in ScanTool:
            config = self.tools_config.get(tool.value, {})
            command = config.get("command")
            
            if command and self._command_exists(command):
                installed.append(tool)
                logger.info(f"Detected installed tool: {tool.value}")
            else:
                logger.debug(f"Tool not installed: {tool.value}")
                
        return installed
    
    def _command_exists(self, command: str) -> bool:
        """Check if a command exists in PATH"""
        try:
            subprocess.run([command, "--version"], capture_output=True, timeout=5)
            return True
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
            return False
    
    def _load_scan_rules(self) -> Dict[str, List[ScanTool]]:
        """Load rules for which tools to use for which file types"""
        return {
            ".py": [ScanTool.SEMGREP, ScanTool.BANDIT, ScanTool.SAFETY, ScanTool.TRIVY],
            ".js": [ScanTool.SEMGREP, ScanTool.ESLINT_SECURITY, ScanTool.TRIVY],
            ".ts": [ScanTool.SEMGREP, ScanTool.ESLINT_SECURITY, ScanTool.TRIVY],
            ".java": [ScanTool.SEMGREP, ScanTool.OWASP_DEPENDENCY_CHECK, ScanTool.TRIVY, ScanTool.CODEQL],
            ".go": [ScanTool.SEMGREP, ScanTool.TRIVY, ScanTool.CODEQL],
            ".rb": [ScanTool.SEMGREP, ScanTool.BEARER, ScanTool.TRIVY],
            ".php": [ScanTool.SEMGREP, ScanTool.BEARER, ScanTool.TRIVY],
            ".cs": [ScanTool.SEMGREP, ScanTool.TRIVY, ScanTool.CODEQL],
            ".dockerfile": [ScanTool.TRIVY, ScanTool.SEMGREP],
            ".yaml": [ScanTool.TRIVY, ScanTool.SEMGREP],
            ".json": [ScanTool.TRIVY, ScanTool.SEMGREP],
            "requirements.txt": [ScanTool.SAFETY, ScanTool.TRIVY],
            "package.json": [ScanTool.OWASP_DEPENDENCY_CHECK, ScanTool.TRIVY],
            "*": [ScanTool.TRIVY, ScanTool.NUCLEI]  # Universal scanners
        }
    
    async def scan_file(self, file_path: str, scan_types: List[str] = None) -> List[ScanResult]:
        """Scan a file with appropriate security tools"""
        results = []
        file_ext = Path(file_path).suffix.lower()
        
        # Determine which tools to use
        applicable_tools = self._get_applicable_tools(file_path, scan_types)
        
        for tool in applicable_tools:
            if tool in self.installed_tools:
                try:
                    tool_results = await self._run_tool_scan(tool, file_path)
                    results.extend(tool_results)
                except Exception as e:
                    logger.error(f"Error running {tool.value} on {file_path}: {e}")
            else:
                logger.warning(f"Tool {tool.value} not installed, skipping")
        
        return self._deduplicate_results(results)
    
    def _get_applicable_tools(self, file_path: str, scan_types: List[str] = None) -> List[ScanTool]:
        """Get list of tools applicable for the given file"""
        file_ext = Path(file_path).suffix.lower()
        filename = Path(file_path).name.lower()
        
        applicable = set()
        
        # Add tools based on file extension
        if file_ext in self.scan_rules:
            applicable.update(self.scan_rules[file_ext])
        
        # Add tools based on filename patterns
        for pattern, tools in self.scan_rules.items():
            if pattern in filename:
                applicable.update(tools)
        
        # Add universal tools
        applicable.update(self.scan_rules.get("*", []))
        
        # Filter by requested scan types if specified
        if scan_types:
            type_mapping = {
                "sast": [ScanTool.SEMGREP, ScanTool.BANDIT, ScanTool.CODEQL],
                "dast": [ScanTool.NUCLEI, ScanTool.NIKTO],
                "dependency": [ScanTool.OWASP_DEPENDENCY_CHECK, ScanTool.SAFETY],
                "secrets": [ScanTool.TRIVY, ScanTool.BEARER],
                "infrastructure": [ScanTool.TRIVY, ScanTool.SEMGREP],
                "container": [ScanTool.TRIVY],
                "network": [ScanTool.NUCLEI, ScanTool.NMAP]
            }
            
            filtered = set()
            for scan_type in scan_types:
                if scan_type.lower() in type_mapping:
                    filtered.update(type_mapping[scan_type.lower()])
            
            applicable = applicable.intersection(filtered)
        
        return list(applicable)
    
    async def _run_tool_scan(self, tool: ScanTool, file_path: str) -> List[ScanResult]:
        """Run a specific tool scan on a file"""
        config = self.tools_config[tool.value]
        command = config["command"]
        args = config["args"].copy()
        
        # Prepare command
        cmd = [command] + args + [file_path]
        
        try:
            # Run scan with timeout
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=tempfile.gettempdir()
            )
            
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=300)
            
            if process.returncode != 0 and process.returncode != 1:  # Some tools use exit code 1 for findings
                logger.warning(f"{tool.value} returned code {process.returncode}: {stderr.decode()}")
            
            # Parse results
            return self._parse_tool_output(tool, stdout.decode(), file_path)
            
        except asyncio.TimeoutError:
            logger.error(f"{tool.value} scan timed out for {file_path}")
            return []
        except Exception as e:
            logger.error(f"Error running {tool.value}: {e}")
            return []
    
    def _parse_tool_output(self, tool: ScanTool, output: str, file_path: str) -> List[ScanResult]:
        """Parse tool-specific output format into standardized results"""
        results = []
        
        try:
            if tool == ScanTool.SEMGREP:
                results = self._parse_semgrep_output(output, file_path)
            elif tool == ScanTool.BEARER:
                results = self._parse_bearer_output(output, file_path)
            elif tool == ScanTool.TRIVY:
                results = self._parse_trivy_output(output, file_path)
            elif tool == ScanTool.BANDIT:
                results = self._parse_bandit_output(output, file_path)
            elif tool == ScanTool.SAFETY:
                results = self._parse_safety_output(output, file_path)
            elif tool == ScanTool.OWASP_DEPENDENCY_CHECK:
                results = self._parse_dependency_check_output(output, file_path)
            elif tool == ScanTool.NUCLEI:
                results = self._parse_nuclei_output(output, file_path)
            else:
                # Generic JSON parser for unknown tools
                results = self._parse_generic_json_output(tool, output, file_path)
                
        except Exception as e:
            logger.error(f"Error parsing {tool.value} output: {e}")
            
        return results
    
    def _parse_semgrep_output(self, output: str, file_path: str) -> List[ScanResult]:
        """Parse Semgrep JSON output"""
        results = []
        try:
            data = json.loads(output)
            for finding in data.get("results", []):
                result = ScanResult(
                    tool=ScanTool.SEMGREP,
                    file_path=finding.get("path", file_path),
                    vulnerability_type=finding.get("check_id", "unknown"),
                    severity=self._map_semgrep_severity(finding.get("extra", {}).get("severity", "INFO")),
                    title=finding.get("extra", {}).get("message", "Security Issue"),
                    description=finding.get("extra", {}).get("metadata", {}).get("description", ""),
                    line_number=finding.get("start", {}).get("line"),
                    column_number=finding.get("start", {}).get("col"),
                    cwe_id=self._extract_cwe_from_semgrep(finding),
                    confidence=finding.get("extra", {}).get("metadata", {}).get("confidence", "MEDIUM"),
                    remediation=finding.get("extra", {}).get("fix", ""),
                    references=finding.get("extra", {}).get("metadata", {}).get("references", []),
                    metadata=finding.get("extra", {})
                )
                results.append(result)
        except json.JSONDecodeError:
            logger.error("Failed to parse Semgrep JSON output")
        return results
    
    def _parse_bearer_output(self, output: str, file_path: str) -> List[ScanResult]:
        """Parse Bearer JSON output"""
        results = []
        try:
            data = json.loads(output)
            for finding in data.get("findings", []):
                result = ScanResult(
                    tool=ScanTool.BEARER,
                    file_path=finding.get("filename", file_path),
                    vulnerability_type=finding.get("rule_id", "unknown"),
                    severity=finding.get("severity", "MEDIUM").upper(),
                    title=finding.get("description", "Security Issue"),
                    description=finding.get("description", ""),
                    line_number=finding.get("source", {}).get("start", {}).get("line"),
                    confidence="HIGH",  # Bearer typically has high confidence
                    metadata=finding
                )
                results.append(result)
        except json.JSONDecodeError:
            logger.error("Failed to parse Bearer JSON output")
        return results
    
    def _parse_trivy_output(self, output: str, file_path: str) -> List[ScanResult]:
        """Parse Trivy JSON output"""
        results = []
        try:
            data = json.loads(output)
            for result_group in data.get("Results", []):
                for vuln in result_group.get("Vulnerabilities", []):
                    result = ScanResult(
                        tool=ScanTool.TRIVY,
                        file_path=result_group.get("Target", file_path),
                        vulnerability_type=vuln.get("VulnerabilityID", "unknown"),
                        severity=vuln.get("Severity", "UNKNOWN"),
                        title=vuln.get("Title", vuln.get("VulnerabilityID", "Security Issue")),
                        description=vuln.get("Description", ""),
                        cve_id=vuln.get("VulnerabilityID") if vuln.get("VulnerabilityID", "").startswith("CVE") else None,
                        cvss_score=vuln.get("CVSS", {}).get("nvd", {}).get("V3Score"),
                        references=vuln.get("References", []),
                        metadata=vuln
                    )
                    results.append(result)
                    
                # Parse secrets
                for secret in result_group.get("Secrets", []):
                    result = ScanResult(
                        tool=ScanTool.TRIVY,
                        file_path=result_group.get("Target", file_path),
                        vulnerability_type="secret",
                        severity="HIGH",
                        title=f"Secret detected: {secret.get('RuleID', 'Unknown')}",
                        description=secret.get("Title", "Potential secret detected"),
                        line_number=secret.get("StartLine"),
                        metadata=secret
                    )
                    results.append(result)
        except json.JSONDecodeError:
            logger.error("Failed to parse Trivy JSON output")
        return results
    
    def _parse_bandit_output(self, output: str, file_path: str) -> List[ScanResult]:
        """Parse Bandit JSON output"""
        results = []
        try:
            data = json.loads(output)
            for finding in data.get("results", []):
                result = ScanResult(
                    tool=ScanTool.BANDIT,
                    file_path=finding.get("filename", file_path),
                    vulnerability_type=finding.get("test_id", "unknown"),
                    severity=finding.get("issue_severity", "MEDIUM"),
                    title=finding.get("issue_text", "Security Issue"),
                    description=finding.get("issue_text", ""),
                    line_number=finding.get("line_number"),
                    cwe_id=finding.get("test_id"),  # Bandit test IDs map to CWEs
                    confidence=finding.get("issue_confidence", "MEDIUM"),
                    metadata=finding
                )
                results.append(result)
        except json.JSONDecodeError:
            logger.error("Failed to parse Bandit JSON output")
        return results
    
    def _map_semgrep_severity(self, severity: str) -> str:
        """Map Semgrep severity to standard levels"""
        mapping = {
            "ERROR": "HIGH",
            "WARNING": "MEDIUM", 
            "INFO": "LOW"
        }
        return mapping.get(severity.upper(), "MEDIUM")
    
    def _extract_cwe_from_semgrep(self, finding: dict) -> Optional[str]:
        """Extract CWE ID from Semgrep finding"""
        metadata = finding.get("extra", {}).get("metadata", {})
        cwe = metadata.get("cwe", [""])[0] if metadata.get("cwe") else ""
        return cwe if cwe else None
    
    def _deduplicate_results(self, results: List[ScanResult]) -> List[ScanResult]:
        """Remove duplicate findings from multiple tools"""
        seen = set()
        unique_results = []
        
        for result in results:
            # Create a signature for deduplication
            signature = (
                result.file_path,
                result.vulnerability_type,
                result.line_number,
                result.title
            )
            
            if signature not in seen:
                seen.add(signature)
                unique_results.append(result)
                
        return unique_results
    
    def _parse_generic_json_output(self, tool: ScanTool, output: str, file_path: str) -> List[ScanResult]:
        """Generic JSON parser for unknown tools"""
        results = []
        try:
            data = json.loads(output)
            # Try to extract findings using common field names
            findings = data.get("findings", data.get("results", data.get("vulnerabilities", [])))
            
            for finding in findings:
                result = ScanResult(
                    tool=tool,
                    file_path=finding.get("file", finding.get("path", file_path)),
                    vulnerability_type=finding.get("type", finding.get("rule", "unknown")),
                    severity=finding.get("severity", "MEDIUM"),
                    title=finding.get("title", finding.get("message", "Security Issue")),
                    description=finding.get("description", ""),
                    line_number=finding.get("line", finding.get("line_number")),
                    metadata=finding
                )
                results.append(result)
        except (json.JSONDecodeError, TypeError):
            logger.error(f"Failed to parse {tool.value} output as JSON")
        return results
    
    async def install_tool(self, tool: ScanTool) -> bool:
        """Install a security tool"""
        config = self.tools_config.get(tool.value, {})
        install_cmd = config.get("install_cmd")
        
        if not install_cmd or install_cmd.startswith("#"):
            logger.warning(f"No automatic installation available for {tool.value}")
            return False
        
        try:
            logger.info(f"Installing {tool.value}...")
            process = await asyncio.create_subprocess_shell(
                install_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                logger.info(f"Successfully installed {tool.value}")
                self.installed_tools.append(tool)
                return True
            else:
                logger.error(f"Failed to install {tool.value}: {stderr.decode()}")
                return False
                
        except Exception as e:
            logger.error(f"Error installing {tool.value}: {e}")
            return False
    
    def get_tool_status(self) -> Dict[str, Dict]:
        """Get status of all security tools"""
        status = {}
        
        for tool in ScanTool:
            config = self.tools_config.get(tool.value, {})
            status[tool.value] = {
                "installed": tool in self.installed_tools,
                "supported_files": config.get("supported_files", []),
                "docker_available": bool(config.get("docker_image")),
                "install_command": config.get("install_cmd", "")
            }
            
        return status

# Global instance
security_tools = SecurityToolsOrchestrator()