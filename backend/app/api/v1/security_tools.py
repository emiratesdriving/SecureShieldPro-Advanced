"""
Professional Security Tools API Endpoints
Enterprise-grade security scanning and analysis
"""

from fastapi import APIRouter, HTTPException, Depends, UploadFile, File
from typing import List, Dict, Any, Optional
from pathlib import Path
import tempfile
import os
import aiofiles
import json

from app.api.v1.auth import get_current_user
from app.services.security_tools_orchestrator import SecurityToolsOrchestrator
from app.services.professional_report_generator import SecurityReportGenerator
from app.db.models import User

router = APIRouter()

# Initialize orchestrator and report generator
orchestrator = SecurityToolsOrchestrator()
report_generator = SecurityReportGenerator()


@router.post("/scan/comprehensive")
async def comprehensive_security_scan(
    files: List[UploadFile] = File(...),
    tools: Optional[List[str]] = None,
    current_user: User = Depends(get_current_user)
):
    """
    Perform comprehensive security scan using multiple professional tools
    """
    try:
        results = []
        temp_dir = tempfile.mkdtemp()
        
        for file in files:
            # Save uploaded file
            file_path = Path(temp_dir) / file.filename
            async with aiofiles.open(file_path, 'wb') as f:
                content = await file.read()
                await f.write(content)
            
            # Run security scan
            scan_result = await orchestrator.run_comprehensive_scan(
                str(file_path),
                tools=tools
            )
            
            results.append({
                'filename': file.filename,
                'scan_results': scan_result
            })
        
        # Cleanup
        import shutil
        shutil.rmtree(temp_dir)
        
        return {
            'status': 'success',
            'scan_id': f"scan_{current_user.id}_{len(results)}",
            'results': results,
            'tools_used': orchestrator.get_available_tools()
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")


@router.get("/tools/available")
async def get_available_tools(current_user: User = Depends(get_current_user)):
    """Get list of available security tools"""
    return {
        'available_tools': orchestrator.get_available_tools(),
        'tool_status': await orchestrator.check_tool_installation()
    }


@router.post("/tools/install")
async def install_security_tools(
    tools: List[str],
    current_user: User = Depends(get_current_user)
):
    """Install specified security tools"""
    try:
        installation_results = await orchestrator.install_tools(tools)
        return {
            'status': 'success',
            'installation_results': installation_results
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Installation failed: {str(e)}")


@router.post("/scan/sast")
async def static_analysis_scan(
    files: List[UploadFile] = File(...),
    tools: Optional[List[str]] = None,
    current_user: User = Depends(get_current_user)
):
    """
    Static Application Security Testing (SAST) scan
    """
    try:
        sast_tools = tools or ['semgrep', 'bandit', 'bearer', 'codeql']
        results = []
        temp_dir = tempfile.mkdtemp()
        
        for file in files:
            file_path = Path(temp_dir) / file.filename
            async with aiofiles.open(file_path, 'wb') as f:
                content = await file.read()
                await f.write(content)
            
            scan_result = await orchestrator.run_sast_scan(str(file_path), sast_tools)
            results.append({
                'filename': file.filename,
                'vulnerabilities': scan_result
            })
        
        # Cleanup
        import shutil
        shutil.rmtree(temp_dir)
        
        return {
            'status': 'success',
            'scan_type': 'SAST',
            'results': results
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"SAST scan failed: {str(e)}")


@router.post("/scan/sca")
async def software_composition_analysis(
    files: List[UploadFile] = File(...),
    current_user: User = Depends(get_current_user)
):
    """
    Software Composition Analysis (SCA) - dependency vulnerabilities
    """
    try:
        sca_tools = ['safety', 'dependency-check', 'trivy']
        results = []
        temp_dir = tempfile.mkdtemp()
        
        for file in files:
            file_path = Path(temp_dir) / file.filename
            async with aiofiles.open(file_path, 'wb') as f:
                content = await file.read()
                await f.write(content)
            
            scan_result = await orchestrator.run_sca_scan(str(file_path), sca_tools)
            results.append({
                'filename': file.filename,
                'dependencies': scan_result
            })
        
        # Cleanup
        import shutil
        shutil.rmtree(temp_dir)
        
        return {
            'status': 'success',
            'scan_type': 'SCA',
            'results': results
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"SCA scan failed: {str(e)}")


@router.post("/scan/dast")
async def dynamic_analysis_scan(
    target_url: str,
    scan_type: str = "basic",
    current_user: User = Depends(get_current_user)
):
    """
    Dynamic Application Security Testing (DAST) scan
    """
    try:
        dast_tools = ['nuclei', 'nmap', 'zap']
        scan_result = await orchestrator.run_dast_scan(target_url, dast_tools, scan_type)
        
        return {
            'status': 'success',
            'scan_type': 'DAST',
            'target': target_url,
            'results': scan_result
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"DAST scan failed: {str(e)}")


@router.post("/scan/secrets")
async def secrets_detection_scan(
    files: List[UploadFile] = File(...),
    current_user: User = Depends(get_current_user)
):
    """
    Secrets detection scan using professional tools
    """
    try:
        secrets_tools = ['gitleaks', 'truffles', 'secretscanner']
        results = []
        temp_dir = tempfile.mkdtemp()
        
        for file in files:
            file_path = Path(temp_dir) / file.filename
            async with aiofiles.open(file_path, 'wb') as f:
                content = await file.read()
                await f.write(content)
            
            scan_result = await orchestrator.run_secrets_scan(str(file_path), secrets_tools)
            results.append({
                'filename': file.filename,
                'secrets_found': scan_result
            })
        
        # Cleanup
        import shutil
        shutil.rmtree(temp_dir)
        
        return {
            'status': 'success',
            'scan_type': 'Secrets Detection',
            'results': results
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Secrets scan failed: {str(e)}")


@router.post("/scan/container")
async def container_security_scan(
    files: List[UploadFile] = File(...),
    current_user: User = Depends(get_current_user)
):
    """
    Container security scan for Docker images and Kubernetes manifests
    """
    try:
        container_tools = ['trivy', 'grype', 'syft']
        results = []
        temp_dir = tempfile.mkdtemp()
        
        for file in files:
            file_path = Path(temp_dir) / file.filename
            async with aiofiles.open(file_path, 'wb') as f:
                content = await file.read()
                await f.write(content)
            
            scan_result = await orchestrator.run_container_scan(str(file_path), container_tools)
            results.append({
                'filename': file.filename,
                'container_vulnerabilities': scan_result
            })
        
        # Cleanup
        import shutil
        shutil.rmtree(temp_dir)
        
        return {
            'status': 'success',
            'scan_type': 'Container Security',
            'results': results
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Container scan failed: {str(e)}")


@router.get("/scan/{scan_id}/status")
async def get_scan_status(
    scan_id: str,
    current_user: User = Depends(get_current_user)
):
    """Get status of running scan"""
    # This would integrate with a job queue system in production
    return {
        'scan_id': scan_id,
        'status': 'completed',  # Mock status
        'progress': 100
    }


@router.get("/scan/{scan_id}/results")
async def get_scan_results(
    scan_id: str,
    format: str = "json",
    current_user: User = Depends(get_current_user)
):
    """Get scan results in specified format"""
    # This would retrieve actual scan results from database
    mock_results = {
        'scan_id': scan_id,
        'timestamp': '2024-01-20T10:00:00Z',
        'vulnerabilities': [
            {
                'severity': 'HIGH',
                'title': 'SQL Injection Vulnerability',
                'description': 'Potential SQL injection in user input handling',
                'file': 'app.py',
                'line': 42,
                'tool': 'semgrep'
            }
        ]
    }
    
    if format == "json":
        return mock_results
    elif format == "sarif":
        # Convert to SARIF format
        return await orchestrator.convert_to_sarif(mock_results)
    else:
        raise HTTPException(status_code=400, detail="Unsupported format")