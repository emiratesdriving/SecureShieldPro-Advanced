"""
Security Scanning API endpoints for SecureShield Pro
Handles SAST, DAST, dependency scanning, and vulnerability management
"""

from fastapi import APIRouter, HTTPException, Depends, UploadFile, File, BackgroundTasks
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime
import json
import uuid
import asyncio
import subprocess
import os
import tempfile

from app.db.database import get_db
from app.api.v1.auth import get_current_user
from app.db.models import User, VulnerabilityScans, SecurityFindings
from app.core.config import settings

# Router
router = APIRouter(tags=["scanning", "Security Scanning"])

# Pydantic models
class ScanRequest(BaseModel):
    scan_name: str = Field(..., min_length=1, max_length=255)
    scan_type: str = Field(..., pattern=r"^(SAST|DAST|SCA|SECRETS|DEPENDENCY)$")
    target: str = Field(..., min_length=1, max_length=500)
    options: Optional[Dict[str, Any]] = None

class ScanResponse(BaseModel):
    scan_id: int
    scan_name: str
    scan_type: str
    status: str
    created_at: datetime
    progress: int = 0

class FindingResponse(BaseModel):
    id: int
    scan_id: int
    title: str
    description: str
    severity: str
    file_path: Optional[str]
    line_number: Optional[int]
    cwe_id: Optional[str]
    cvss_score: Optional[float]

class ScanResultsResponse(BaseModel):
    scan: ScanResponse
    findings: List[FindingResponse]
    summary: Dict[str, int]

class FileUploadResponse(BaseModel):
    filename: str
    file_id: str
    size: int
    message: str

# Security scanning tools integration
class SecurityScanner:
    """Security scanning engine with multiple tool integrations"""
    
    def __init__(self):
        self.scan_dir = "/tmp/secureshield_scans"
        os.makedirs(self.scan_dir, exist_ok=True)
    
    async def run_sast_scan(self, file_path: str, scan_id: int) -> Dict[str, Any]:
        """Run Static Application Security Testing (SAST) scan"""
        results = {
            "tool": "bandit",
            "findings": [],
            "summary": {"high": 0, "medium": 0, "low": 0, "info": 0}
        }
        
        try:
            # Run Bandit for Python files
            if file_path.endswith(('.py', '.pyw')):
                cmd = ["bandit", "-r", file_path, "-f", "json"]
                result = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await result.communicate()
                
                if stdout:
                    bandit_results = json.loads(stdout.decode())
                    for finding in bandit_results.get("results", []):
                        severity = finding.get("issue_severity", "INFO").lower()
                        results["findings"].append({
                            "title": finding.get("test_name", "Security Issue"),
                            "description": finding.get("issue_text", ""),
                            "severity": severity.upper(),
                            "file_path": finding.get("filename", ""),
                            "line_number": finding.get("line_number", 0),
                            "confidence": finding.get("issue_confidence", ""),
                            "cwe_id": f"CWE-{finding.get('test_id', '').replace('B', '')}"
                        })
                        results["summary"][severity] += 1
            
            # Run Semgrep for broader language support
            elif file_path.endswith(('.js', '.ts', '.jsx', '.tsx', '.java', '.go', '.php')):
                cmd = ["semgrep", "--config=auto", "--json", file_path]
                result = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await result.communicate()
                
                if stdout:
                    semgrep_results = json.loads(stdout.decode())
                    for finding in semgrep_results.get("results", []):
                        severity = self._map_semgrep_severity(finding.get("extra", {}).get("severity", "INFO"))
                        results["findings"].append({
                            "title": finding.get("check_id", "Security Issue"),
                            "description": finding.get("extra", {}).get("message", ""),
                            "severity": severity,
                            "file_path": finding.get("path", ""),
                            "line_number": finding.get("start", {}).get("line", 0),
                            "confidence": "HIGH",
                            "cwe_id": self._extract_cwe_from_semgrep(finding)
                        })
                        results["summary"][severity.lower()] += 1
                        
        except Exception as e:
            results["error"] = str(e)
        
        return results
    
    async def run_dependency_scan(self, file_path: str, scan_id: int) -> Dict[str, Any]:
        """Run dependency vulnerability scanning"""
        results = {
            "tool": "safety",
            "findings": [],
            "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0}
        }
        
        try:
            # For Python requirements
            if file_path.endswith(('requirements.txt', 'pyproject.toml', 'Pipfile')):
                cmd = ["safety", "check", "--json", "-r", file_path]
                result = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await result.communicate()
                
                if stdout:
                    safety_results = json.loads(stdout.decode())
                    for finding in safety_results:
                        severity = self._map_safety_severity(finding.get("vulnerability_id", ""))
                        results["findings"].append({
                            "title": f"Vulnerable Dependency: {finding.get('package', '')}",
                            "description": finding.get("advisory", ""),
                            "severity": severity,
                            "package": finding.get("package", ""),
                            "installed_version": finding.get("installed_version", ""),
                            "vulnerable_versions": finding.get("vulnerable_versions", ""),
                            "cve_id": finding.get("vulnerability_id", "")
                        })
                        results["summary"][severity.lower()] += 1
            
            # For Node.js package.json
            elif file_path.endswith('package.json'):
                # Use npm audit
                cmd = ["npm", "audit", "--json", "--prefix", os.path.dirname(file_path)]
                result = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await result.communicate()
                
                if stdout:
                    npm_results = json.loads(stdout.decode())
                    vulnerabilities = npm_results.get("vulnerabilities", {})
                    for pkg_name, vuln_data in vulnerabilities.items():
                        severity = vuln_data.get("severity", "low").upper()
                        results["findings"].append({
                            "title": f"Vulnerable NPM Package: {pkg_name}",
                            "description": vuln_data.get("title", ""),
                            "severity": severity,
                            "package": pkg_name,
                            "cve_id": vuln_data.get("url", "").split("/")[-1] if vuln_data.get("url") else ""
                        })
                        results["summary"][severity.lower()] += 1
                        
        except Exception as e:
            results["error"] = str(e)
            
        return results
    
    async def run_secrets_scan(self, file_path: str, scan_id: int) -> Dict[str, Any]:
        """Run secrets detection scanning"""
        results = {
            "tool": "truffleHog",
            "findings": [],
            "summary": {"high": 0, "medium": 0, "low": 0}
        }
        
        try:
            # Use TruffleHog for secrets detection
            cmd = ["trufflehog", "filesystem", file_path, "--json"]
            result = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await result.communicate()
            
            if stdout:
                for line in stdout.decode().split('\n'):
                    if line.strip():
                        finding = json.loads(line)
                        results["findings"].append({
                            "title": f"Secret Detected: {finding.get('DetectorName', 'Unknown')}",
                            "description": f"Potential secret found in {finding.get('SourceMetadata', {}).get('Data', {}).get('Filesystem', {}).get('file', '')}",
                            "severity": "HIGH",
                            "file_path": finding.get('SourceMetadata', {}).get('Data', {}).get('Filesystem', {}).get('file', ''),
                            "line_number": finding.get('SourceMetadata', {}).get('Data', {}).get('Filesystem', {}).get('line', 0),
                            "secret_type": finding.get('DetectorName', ''),
                            "verified": finding.get('Verified', False)
                        })
                        results["summary"]["high"] += 1
                        
        except Exception as e:
            results["error"] = str(e)
            
        return results
    
    def _map_semgrep_severity(self, severity: str) -> str:
        """Map Semgrep severity to our standard levels"""
        mapping = {
            "ERROR": "HIGH",
            "WARNING": "MEDIUM", 
            "INFO": "LOW"
        }
        return mapping.get(severity.upper(), "LOW")
    
    def _map_safety_severity(self, vuln_id: str) -> str:
        """Map Safety vulnerability to severity based on ID patterns"""
        if "CRITICAL" in vuln_id.upper():
            return "CRITICAL"
        elif any(x in vuln_id.upper() for x in ["HIGH", "SEVERE"]):
            return "HIGH"
        elif "MEDIUM" in vuln_id.upper():
            return "MEDIUM"
        else:
            return "LOW"
    
    def _extract_cwe_from_semgrep(self, finding: Dict) -> str:
        """Extract CWE ID from Semgrep finding"""
        metadata = finding.get("extra", {}).get("metadata", {})
        cwe = metadata.get("cwe", [""])[0] if metadata.get("cwe") else ""
        return cwe if cwe.startswith("CWE-") else ""

# Initialize scanner
scanner = SecurityScanner()

@router.post("/upload", response_model=FileUploadResponse)
async def upload_file(
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user)
):
    """Upload file for security scanning"""
    
    # Validate file size (max 50MB)
    if file.size and file.size > 50 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="File too large (max 50MB)")
    
    # Generate unique file ID
    file_id = str(uuid.uuid4())
    
    # Create upload directory
    upload_dir = f"{scanner.scan_dir}/{file_id}"
    os.makedirs(upload_dir, exist_ok=True)
    
    # Save file
    file_path = f"{upload_dir}/{file.filename}"
    with open(file_path, "wb") as f:
        content = await file.read()
        f.write(content)
    
    return FileUploadResponse(
        filename=file.filename,
        file_id=file_id,
        size=len(content),
        message="File uploaded successfully"
    )

@router.post("/start", response_model=ScanResponse)
async def start_scan(
    scan_request: ScanRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Start a new security scan"""
    
    # Create scan record
    scan = VulnerabilityScans(
        scan_name=scan_request.scan_name,
        scan_type=scan_request.scan_type,
        target=scan_request.target,
        status="QUEUED",
        progress=0,
        created_by=current_user.id,
        scan_options=scan_request.options or {}
    )
    
    db.add(scan)
    db.commit()
    db.refresh(scan)
    
    # Start background scan
    background_tasks.add_task(run_background_scan, scan.id, scan_request, db)
    
    return ScanResponse(
        scan_id=scan.id,
        scan_name=scan.scan_name,
        scan_type=scan.scan_type,
        status=scan.status,
        created_at=scan.created_at,
        progress=scan.progress
    )

@router.get("/", response_model=List[ScanResponse])
async def get_scans(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get user's security scans"""
    
    scans = db.query(VulnerabilityScans).filter(
        VulnerabilityScans.created_by == current_user.id
    ).offset(skip).limit(limit).all()
    
    return [
        ScanResponse(
            scan_id=scan.id,
            scan_name=scan.scan_name,
            scan_type=scan.scan_type,
            status=scan.status,
            created_at=scan.created_at,
            progress=scan.progress
        )
        for scan in scans
    ]

@router.get("/{scan_id}/results", response_model=ScanResultsResponse)
async def get_scan_results(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get scan results with findings"""
    
    # Get scan
    scan = db.query(VulnerabilityScans).filter(
        VulnerabilityScans.id == scan_id,
        VulnerabilityScans.created_by == current_user.id
    ).first()
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    # Get findings
    findings = db.query(SecurityFindings).filter(
        SecurityFindings.scan_id == scan_id
    ).all()
    
    # Calculate summary
    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in findings:
        severity = finding.severity.lower()
        if severity in summary:
            summary[severity] += 1
    
    return ScanResultsResponse(
        scan=ScanResponse(
            scan_id=scan.id,
            scan_name=scan.scan_name,
            scan_type=scan.scan_type,
            status=scan.status,
            created_at=scan.created_at,
            progress=scan.progress
        ),
        findings=[
            FindingResponse(
                id=finding.id,
                scan_id=finding.scan_id,
                title=finding.title,
                description=finding.description,
                severity=finding.severity,
                file_path=finding.file_path,
                line_number=finding.line_number,
                cwe_id=finding.cwe_id,
                cvss_score=finding.cvss_score
            )
            for finding in findings
        ],
        summary=summary
    )

async def run_background_scan(scan_id: int, scan_request: ScanRequest, db: Session):
    """Run security scan in background"""
    
    # Update scan status
    scan = db.query(VulnerabilityScans).filter(VulnerabilityScans.id == scan_id).first()
    scan.status = "RUNNING"
    scan.progress = 10
    db.commit()
    
    try:
        results = None
        target_path = scan_request.target
        
        # Determine scan type and run appropriate scanner
        if scan_request.scan_type == "SAST":
            results = await scanner.run_sast_scan(target_path, scan_id)
        elif scan_request.scan_type == "DEPENDENCY" or scan_request.scan_type == "SCA":
            results = await scanner.run_dependency_scan(target_path, scan_id)
        elif scan_request.scan_type == "SECRETS":
            results = await scanner.run_secrets_scan(target_path, scan_id)
        
        scan.progress = 70
        db.commit()
        
        # Save findings to database
        if results and "findings" in results:
            for finding_data in results["findings"]:
                finding = SecurityFindings(
                    scan_id=scan_id,
                    title=finding_data.get("title", ""),
                    description=finding_data.get("description", ""),
                    severity=finding_data.get("severity", "LOW"),
                    file_path=finding_data.get("file_path"),
                    line_number=finding_data.get("line_number"),
                    cwe_id=finding_data.get("cwe_id"),
                    cvss_score=finding_data.get("cvss_score"),
                    additional_data=finding_data
                )
                db.add(finding)
        
        # Update scan completion
        scan.status = "COMPLETED"
        scan.progress = 100
        scan.results = results
        db.commit()
        
    except Exception as e:
        # Handle scan errors
        scan.status = "FAILED"
        scan.error_message = str(e)
        db.commit()

@router.delete("/{scan_id}")
async def delete_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Delete a scan and its findings"""
    
    scan = db.query(VulnerabilityScans).filter(
        VulnerabilityScans.id == scan_id,
        VulnerabilityScans.created_by == current_user.id
    ).first()
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    # Delete findings first
    db.query(SecurityFindings).filter(SecurityFindings.scan_id == scan_id).delete()
    
    # Delete scan
    db.delete(scan)
    db.commit()
    
    return {"message": "Scan deleted successfully"}