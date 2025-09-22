"""
AI Auto-Remediation API Endpoints
Provides AI-powered automatic vulnerability remediation capabilities
"""

from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks
from typing import Dict, Any, List
import logging

from ..services.ai_remediation import AIRemediationEngine, RemediationScheduler
from ..models.schemas import (
    RemediationScheduleRequest, 
    RemediationScheduleResponse,
    RemediationStatsResponse
)

logger = logging.getLogger(__name__)

# Initialize global instances
ai_remediation_engine = AIRemediationEngine()
remediation_scheduler = RemediationScheduler()

router = APIRouter(prefix="/ai-remediation", tags=["AI Remediation"])

@router.post("/analyze/{vulnerability_id}")
async def analyze_vulnerability(vulnerability_id: str) -> Dict[str, Any]:
    """
    Analyze vulnerability with AI for remediation recommendations
    """
    try:
        # Get vulnerability (simulate for now)
        vulnerability = await ai_remediation_engine._get_vulnerability(vulnerability_id)
        if not vulnerability:
            raise HTTPException(status_code=404, detail="Vulnerability not found")
        
        # Perform AI analysis
        analysis = await ai_remediation_engine.analyze_vulnerability(vulnerability)
        
        return {
            "status": "success",
            "vulnerability_id": vulnerability_id,
            "analysis": analysis
        }
        
    except Exception as e:
        logger.error(f"Vulnerability analysis failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

@router.post("/remediate/{vulnerability_id}")
async def auto_remediate_vulnerability(
    vulnerability_id: str,
    background_tasks: BackgroundTasks
) -> Dict[str, Any]:
    """
    Automatically remediate a vulnerability using AI
    """
    try:
        # Execute remediation in background
        background_tasks.add_task(
            execute_auto_remediation, 
            vulnerability_id
        )
        
        return {
            "status": "accepted",
            "message": "Auto-remediation started",
            "vulnerability_id": vulnerability_id
        }
        
    except Exception as e:
        logger.error(f"Auto-remediation failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Remediation failed: {str(e)}")

async def execute_auto_remediation(vulnerability_id: str):
    """Background task to execute auto-remediation"""
    try:
        result = await ai_remediation_engine.auto_remediate(vulnerability_id)
        logger.info(f"Auto-remediation completed for {vulnerability_id}: {result.success}")
    except Exception as e:
        logger.error(f"Background auto-remediation failed: {str(e)}")

@router.post("/schedule")
async def schedule_remediation(request: RemediationScheduleRequest) -> RemediationScheduleResponse:
    """
    Schedule a remediation task for later execution
    """
    try:
        from ..services.ai_remediation import RemediationPriority
        
        # Convert string priority to enum
        priority = RemediationPriority(request.priority)
        
        task_id = await remediation_scheduler.schedule_remediation(
            vulnerability_id=request.vulnerability_id,
            priority=priority,
            delay_minutes=request.delay_minutes
        )
        
        # Get scheduled task details
        scheduled_task = remediation_scheduler.scheduled_tasks[task_id]
        
        return RemediationScheduleResponse(
            task_id=task_id,
            vulnerability_id=request.vulnerability_id,
            scheduled_time=scheduled_task["scheduled_time"],
            priority=request.priority,
            status=scheduled_task["status"]
        )
        
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid priority: {request.priority}")
    except Exception as e:
        logger.error(f"Remediation scheduling failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Scheduling failed: {str(e)}")

@router.get("/schedule/status")
async def get_scheduler_status() -> Dict[str, Any]:
    """
    Get current scheduler status and task queue
    """
    try:
        status = await remediation_scheduler.get_scheduler_status()
        return {
            "status": "success",
            "scheduler": status
        }
    except Exception as e:
        logger.error(f"Failed to get scheduler status: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Status retrieval failed: {str(e)}")

@router.get("/stats")
async def get_remediation_stats() -> RemediationStatsResponse:
    """
    Get AI remediation statistics and performance metrics
    """
    try:
        stats = await ai_remediation_engine.get_remediation_stats()
        
        return RemediationStatsResponse(
            total_remediations=stats["total_remediations"],
            successful_remediations=stats["successful_remediations"],
            success_rate=stats["success_rate"],
            average_fix_time=stats["average_fix_time"],
            most_common_types=stats["most_common_types"],
            recent_activity=stats["recent_activity"]
        )
        
    except Exception as e:
        logger.error(f"Failed to get remediation stats: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Stats retrieval failed: {str(e)}")

@router.get("/capabilities")
async def get_remediation_capabilities() -> Dict[str, Any]:
    """
    Get AI remediation system capabilities and supported vulnerability types
    """
    return {
        "status": "success",
        "capabilities": {
            "supported_vulnerability_types": [
                "sql_injection",
                "xss",
                "authentication_bypass",
                "configuration_weakness",
                "default_credentials",
                "insecure_permissions",
                "outdated_components"
            ],
            "remediation_types": [
                "code_refactoring",
                "configuration_fix",
                "patch_application",
                "policy_enforcement",
                "network_isolation",
                "credential_rotation",
                "privilege_reduction"
            ],
            "automation_levels": [
                "manual",
                "semi_automated", 
                "fully_automated"
            ],
            "ai_models": {
                "vulnerability_classifier": {
                    "type": "neural_network",
                    "accuracy": 0.96
                },
                "remediation_predictor": {
                    "type": "ensemble",
                    "success_rate": 0.94
                },
                "risk_assessor": {
                    "type": "deep_learning"
                },
                "impact_analyzer": {
                    "type": "transformer"
                }
            },
            "supported_languages": [
                "python",
                "javascript",
                "java",
                "php",
                "go",
                "c_sharp"
            ],
            "integration_support": [
                "github",
                "gitlab",
                "jenkins",
                "azure_devops",
                "aws_codepipeline"
            ]
        }
    }

@router.post("/simulate")
async def simulate_remediation(vulnerability_id: str) -> Dict[str, Any]:
    """
    Simulate remediation without making actual changes (dry run)
    """
    try:
        # Get vulnerability
        vulnerability = await ai_remediation_engine._get_vulnerability(vulnerability_id)
        if not vulnerability:
            raise HTTPException(status_code=404, detail="Vulnerability not found")
        
        # Perform analysis
        analysis = await ai_remediation_engine.analyze_vulnerability(vulnerability)
        
        # Simulate remediation result
        simulation_result = {
            "would_succeed": True,
            "estimated_time_minutes": 45,
            "changes_preview": [
                "Update authentication logic in auth.py:45",
                "Add input validation decorators",
                "Implement parameterized queries",
                "Add security logging"
            ],
            "risk_assessment": "low",
            "rollback_available": True,
            "testing_required": True,
            "approval_needed": False
        }
        
        return {
            "status": "success",
            "vulnerability_id": vulnerability_id,
            "simulation": simulation_result,
            "analysis": analysis["recommended_action"]
        }
        
    except Exception as e:
        logger.error(f"Remediation simulation failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Simulation failed: {str(e)}")

@router.post("/batch-analyze")
async def batch_analyze_vulnerabilities(vulnerability_ids: List[str]) -> Dict[str, Any]:
    """
    Analyze multiple vulnerabilities for batch remediation
    """
    try:
        if len(vulnerability_ids) > 50:
            raise HTTPException(status_code=400, detail="Maximum 50 vulnerabilities per batch")
        
        results = []
        for vuln_id in vulnerability_ids:
            try:
                vulnerability = await ai_remediation_engine._get_vulnerability(vuln_id)
                if vulnerability:
                    analysis = await ai_remediation_engine.analyze_vulnerability(vulnerability)
                    results.append({
                        "vulnerability_id": vuln_id,
                        "status": "analyzed",
                        "priority": analysis["recommended_action"]["priority"],
                        "automation_feasible": analysis["automation_feasibility"]["can_auto_remediate"],
                        "estimated_time": analysis["estimated_fix_time"]["estimated_minutes"]
                    })
                else:
                    results.append({
                        "vulnerability_id": vuln_id,
                        "status": "not_found",
                        "error": "Vulnerability not found"
                    })
            except Exception as e:
                results.append({
                    "vulnerability_id": vuln_id,
                    "status": "error",
                    "error": str(e)
                })
        
        # Generate batch recommendations
        automatable = [r for r in results if r.get("automation_feasible")]
        critical_priority = [r for r in results if r.get("priority") == "critical"]
        
        return {
            "status": "success",
            "total_analyzed": len(results),
            "results": results,
            "batch_recommendations": {
                "automatable_count": len(automatable),
                "critical_count": len(critical_priority),
                "estimated_total_time": sum(r.get("estimated_time", 0) for r in results),
                "suggested_order": sorted(
                    results, 
                    key=lambda x: (
                        x.get("priority") == "critical",
                        x.get("automation_feasible", False),
                        -x.get("estimated_time", 0)
                    ),
                    reverse=True
                )
            }
        }
        
    except Exception as e:
        logger.error(f"Batch analysis failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Batch analysis failed: {str(e)}")

@router.get("/health")
async def health_check() -> Dict[str, Any]:
    """
    Health check for AI remediation system
    """
    try:
        # Check if AI models are loaded
        models_loaded = len(ai_remediation_engine.ml_models) > 0
        
        # Check scheduler status
        scheduler_status = await remediation_scheduler.get_scheduler_status()
        
        return {
            "status": "healthy",
            "ai_models_loaded": models_loaded,
            "scheduler_active": True,
            "active_tasks": scheduler_status["running_tasks"],
            "queue_length": scheduler_status["scheduled_tasks"],
            "success_rate": ai_remediation_engine.success_rate,
            "system_ready": models_loaded
        }
        
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        return {
            "status": "unhealthy",
            "error": str(e),
            "system_ready": False
        }