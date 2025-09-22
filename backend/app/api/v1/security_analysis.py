"""
Enhanced Security Analysis API Endpoints
Advanced file analysis with AI-powered vulnerability detection
"""

from fastapi import APIRouter, HTTPException, UploadFile, File, BackgroundTasks, Query, Form
from fastapi.responses import JSONResponse
from typing import Dict, Any, List, Optional
import logging
from datetime import datetime
import mimetypes

from app.services.security_analysis import (
    SecurityAnalysisEngine,
    AnalysisStatus,
    AnalysisType,
    VulnerabilityLevel,
    analysis_engine
)

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Security Analysis"])

@router.post("/upload")
async def upload_file_for_analysis(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    analysis_types: str = Form(default="static_analysis,dependency_scan,secret_detection,malware_scan"),
    description: str = Form(default="")
) -> Dict[str, Any]:
    """
    Upload file for comprehensive security analysis
    """
    try:
        # Validate file
        if not file.filename:
            raise HTTPException(status_code=400, detail="No file provided")
        
        # Check file size (limit to 100MB)
        file_content = await file.read()
        if len(file_content) > 100 * 1024 * 1024:
            raise HTTPException(status_code=413, detail="File too large (max 100MB)")
        
        # Parse analysis types
        analysis_type_list = []
        for analysis_type in analysis_types.split(","):
            try:
                analysis_type_list.append(AnalysisType(analysis_type.strip()))
            except ValueError:
                logger.warning(f"Invalid analysis type: {analysis_type}")
        
        if not analysis_type_list:
            analysis_type_list = [
                AnalysisType.STATIC_ANALYSIS,
                AnalysisType.DEPENDENCY_SCAN,
                AnalysisType.SECRET_DETECTION,
                AnalysisType.MALWARE_SCAN
            ]
        
        # Start analysis
        analysis_id = await analysis_engine.upload_and_analyze(
            file_content, 
            file.filename, 
            analysis_type_list
        )
        
        # Add background monitoring
        background_tasks.add_task(monitor_analysis_progress, analysis_id)
        
        return {
            "status": "uploaded",
            "analysis_id": analysis_id,
            "filename": file.filename,
            "file_size": len(file_content),
            "analysis_types": [at.value for at in analysis_type_list],
            "message": "File uploaded successfully, analysis started"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"File upload failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Upload failed: {str(e)}")

async def monitor_analysis_progress(analysis_id: str):
    """Background task to monitor analysis progress"""
    try:
        logger.info(f"Monitoring analysis progress: {analysis_id}")
        # Additional monitoring logic can be added here
    except Exception as e:
        logger.error(f"Analysis monitoring failed: {str(e)}")

@router.get("/reports")
async def get_analysis_reports(
    limit: int = Query(default=50, le=100, description="Maximum number of reports to return"),
    status: Optional[str] = Query(default=None, description="Filter by analysis status"),
    severity: Optional[str] = Query(default=None, description="Filter by minimum severity")
) -> Dict[str, Any]:
    """
    Get list of analysis reports with optional filtering
    """
    try:
        status_filter = None
        if status:
            try:
                status_filter = AnalysisStatus(status)
            except ValueError:
                raise HTTPException(status_code=400, detail=f"Invalid status: {status}")
        
        reports = await analysis_engine.list_reports(limit, status_filter)
        
        # Apply severity filter if specified
        if severity:
            try:
                min_severity = VulnerabilityLevel(severity)
                severity_order = {
                    VulnerabilityLevel.INFORMATIONAL: 0,
                    VulnerabilityLevel.LOW: 1,
                    VulnerabilityLevel.MEDIUM: 2,
                    VulnerabilityLevel.HIGH: 3,
                    VulnerabilityLevel.CRITICAL: 4
                }
                min_level = severity_order[min_severity]
                
                filtered_reports = []
                for report in reports:
                    max_severity = 0
                    for sev, count in report["severity_breakdown"].items():
                        if count > 0:
                            sev_level = severity_order.get(VulnerabilityLevel(sev), 0)
                            max_severity = max(max_severity, sev_level)
                    
                    if max_severity >= min_level:
                        filtered_reports.append(report)
                
                reports = filtered_reports
                
            except ValueError:
                raise HTTPException(status_code=400, detail=f"Invalid severity: {severity}")
        
        return {
            "status": "success",
            "total_reports": len(reports),
            "reports": reports
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get reports: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to get reports: {str(e)}")

@router.get("/reports/{analysis_id}")
async def get_analysis_report(analysis_id: str) -> Dict[str, Any]:
    """
    Get detailed analysis report by ID
    """
    try:
        report = await analysis_engine.get_analysis_report(analysis_id)
        
        if not report:
            raise HTTPException(status_code=404, detail="Analysis report not found")
        
        return {
            "status": "success",
            "report": {
                "id": report.id,
                "filename": report.filename,
                "file_hash": report.file_hash,
                "file_size": report.file_size,
                "analysis_type": [at.value for at in report.analysis_type],
                "status": report.status.value,
                "created_at": report.created_at.isoformat(),
                "completed_at": report.completed_at.isoformat() if report.completed_at else None,
                "execution_time": report.execution_time,
                "findings_count": len(report.findings),
                "findings": [
                    {
                        "id": finding.id,
                        "type": finding.type,
                        "title": finding.title,
                        "description": finding.description,
                        "severity": finding.severity.value,
                        "confidence": finding.confidence,
                        "file_path": finding.file_path,
                        "line_number": finding.line_number,
                        "column_number": finding.column_number,
                        "code_snippet": finding.code_snippet,
                        "cwe_id": finding.cwe_id,
                        "cvss_score": finding.cvss_score,
                        "remediation": finding.remediation,
                        "references": finding.references,
                        "false_positive": finding.false_positive
                    } for finding in report.findings
                ],
                "severity_breakdown": {
                    "critical": len([f for f in report.findings if f.severity == VulnerabilityLevel.CRITICAL]),
                    "high": len([f for f in report.findings if f.severity == VulnerabilityLevel.HIGH]),
                    "medium": len([f for f in report.findings if f.severity == VulnerabilityLevel.MEDIUM]),
                    "low": len([f for f in report.findings if f.severity == VulnerabilityLevel.LOW]),
                    "informational": len([f for f in report.findings if f.severity == VulnerabilityLevel.INFORMATIONAL])
                },
                "ai_summary": report.ai_summary,
                "remediation_suggestions": report.remediation_suggestions,
                "metadata": report.metadata
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get report {analysis_id}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to get report: {str(e)}")

@router.get("/reports/{analysis_id}/status")
async def get_analysis_status(analysis_id: str) -> Dict[str, Any]:
    """
    Get analysis status and progress
    """
    try:
        status = await analysis_engine.get_analysis_status(analysis_id)
        
        if not status:
            raise HTTPException(status_code=404, detail="Analysis not found")
        
        # Get basic report info
        report = await analysis_engine.get_analysis_report(analysis_id)
        
        response = {
            "status": "success",
            "analysis_id": analysis_id,
            "current_status": status.value,
            "progress": {
                "completed": status in [AnalysisStatus.COMPLETED, AnalysisStatus.FAILED],
                "progress_percentage": 100 if status in [AnalysisStatus.COMPLETED, AnalysisStatus.FAILED] else 50 if status == AnalysisStatus.ANALYZING else 0
            }
        }
        
        if report:
            response["filename"] = report.filename
            response["created_at"] = report.created_at.isoformat()
            if report.completed_at:
                response["completed_at"] = report.completed_at.isoformat()
                response["execution_time"] = report.execution_time
            if status == AnalysisStatus.COMPLETED:
                response["findings_count"] = len(report.findings)
        
        return response
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get status for {analysis_id}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to get status: {str(e)}")

@router.delete("/reports/{analysis_id}")
async def delete_analysis_report(analysis_id: str) -> Dict[str, Any]:
    """
    Delete analysis report and associated files
    """
    try:
        success = await analysis_engine.delete_report(analysis_id)
        
        if not success:
            raise HTTPException(status_code=404, detail="Analysis report not found")
        
        return {
            "status": "deleted",
            "analysis_id": analysis_id,
            "message": "Analysis report deleted successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete report {analysis_id}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to delete report: {str(e)}")

@router.put("/reports/{analysis_id}/findings/{finding_id}/false-positive")
async def mark_finding_false_positive(
    analysis_id: str,
    finding_id: str,
    is_false_positive: bool
) -> Dict[str, Any]:
    """
    Mark finding as false positive or revert
    """
    try:
        report = await analysis_engine.get_analysis_report(analysis_id)
        
        if not report:
            raise HTTPException(status_code=404, detail="Analysis report not found")
        
        # Find and update the finding
        finding_found = False
        for finding in report.findings:
            if finding.id == finding_id:
                finding.false_positive = is_false_positive
                finding_found = True
                break
        
        if not finding_found:
            raise HTTPException(status_code=404, detail="Finding not found")
        
        return {
            "status": "updated",
            "finding_id": finding_id,
            "false_positive": is_false_positive,
            "message": f"Finding marked as {'false positive' if is_false_positive else 'valid'}"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update finding {finding_id}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to update finding: {str(e)}")

@router.get("/metrics")
async def get_analysis_metrics() -> Dict[str, Any]:
    """
    Get analysis engine performance metrics
    """
    try:
        metrics = await analysis_engine.get_analysis_metrics()
        
        return {
            "status": "success",
            "metrics": metrics
        }
        
    except Exception as e:
        logger.error(f"Failed to get metrics: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to get metrics: {str(e)}")

@router.get("/analysis-types")
async def get_available_analysis_types() -> Dict[str, Any]:
    """
    Get available analysis types and their descriptions
    """
    try:
        analysis_types = [
            {
                "type": "static_analysis",
                "name": "Static Code Analysis",
                "description": "Analyze source code for security vulnerabilities without execution",
                "supported_files": ["*.py", "*.js", "*.java", "*.php", "*.cpp", "*.c"]
            },
            {
                "type": "dependency_scan",
                "name": "Dependency Vulnerability Scan",
                "description": "Check dependencies for known security vulnerabilities",
                "supported_files": ["package.json", "requirements.txt", "composer.json", "pom.xml"]
            },
            {
                "type": "secret_detection",
                "name": "Secret Detection",
                "description": "Detect hardcoded secrets, API keys, and credentials",
                "supported_files": ["*.*"]
            },
            {
                "type": "malware_scan",
                "name": "Malware Detection",
                "description": "Scan for malicious code patterns and suspicious behavior",
                "supported_files": ["*.*"]
            },
            {
                "type": "code_quality",
                "name": "Code Quality Analysis",
                "description": "Analyze code quality and security best practices",
                "supported_files": ["*.py", "*.js", "*.java", "*.php"]
            },
            {
                "type": "configuration_scan",
                "name": "Configuration Security Scan",
                "description": "Check configuration files for security misconfigurations",
                "supported_files": ["*.yml", "*.yaml", "*.json", "*.xml", "*.conf"]
            },
            {
                "type": "compliance_check",
                "name": "Compliance Verification",
                "description": "Verify compliance with security standards and policies",
                "supported_files": ["*.*"]
            }
        ]
        
        return {
            "status": "success",
            "analysis_types": analysis_types
        }
        
    except Exception as e:
        logger.error(f"Failed to get analysis types: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to get analysis types: {str(e)}")

@router.post("/batch-upload")
async def batch_upload_files(
    background_tasks: BackgroundTasks,
    files: List[UploadFile] = File(...),
    analysis_types: str = Form(default="static_analysis,dependency_scan,secret_detection")
) -> Dict[str, Any]:
    """
    Upload multiple files for batch analysis
    """
    try:
        if len(files) > 10:
            raise HTTPException(status_code=400, detail="Maximum 10 files allowed for batch upload")
        
        # Parse analysis types
        analysis_type_list = []
        for analysis_type in analysis_types.split(","):
            try:
                analysis_type_list.append(AnalysisType(analysis_type.strip()))
            except ValueError:
                continue
        
        if not analysis_type_list:
            analysis_type_list = [
                AnalysisType.STATIC_ANALYSIS,
                AnalysisType.DEPENDENCY_SCAN,
                AnalysisType.SECRET_DETECTION
            ]
        
        batch_results = []
        
        for file in files:
            try:
                if not file.filename:
                    continue
                
                file_content = await file.read()
                if len(file_content) > 50 * 1024 * 1024:  # 50MB limit for batch
                    batch_results.append({
                        "filename": file.filename,
                        "status": "error",
                        "error": "File too large for batch upload"
                    })
                    continue
                
                analysis_id = await analysis_engine.upload_and_analyze(
                    file_content,
                    file.filename,
                    analysis_type_list
                )
                
                batch_results.append({
                    "filename": file.filename,
                    "status": "uploaded",
                    "analysis_id": analysis_id,
                    "file_size": len(file_content)
                })
                
            except Exception as e:
                batch_results.append({
                    "filename": file.filename,
                    "status": "error",
                    "error": str(e)
                })
        
        successful_uploads = len([r for r in batch_results if r["status"] == "uploaded"])
        
        return {
            "status": "batch_completed",
            "total_files": len(files),
            "successful_uploads": successful_uploads,
            "failed_uploads": len(files) - successful_uploads,
            "results": batch_results
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Batch upload failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Batch upload failed: {str(e)}")

@router.get("/health")
async def health_check() -> Dict[str, Any]:
    """
    Health check for analysis engine
    """
    try:
        metrics = await analysis_engine.get_analysis_metrics()
        
        return {
            "status": "healthy",
            "engine_ready": True,
            "total_reports": metrics.get("total_reports", 0),
            "ai_models_status": metrics.get("ai_models_status", {}),
            "cache_size": metrics.get("cache_size", 0),
            "success_rate": metrics.get("success_rate", 0)
        }
        
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        return {
            "status": "unhealthy",
            "error": str(e),
            "engine_ready": False
        }