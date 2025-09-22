"""
SOAR (Security Orchestration, Automation & Response) API Endpoints
Automated incident response and security workflow orchestration
"""

from fastapi import APIRouter, HTTPException, BackgroundTasks, Query
from typing import Dict, Any, List, Optional
import logging
from datetime import datetime

from ..services.soar import (
    SOARPlatform,
    PlaybookStatus,
    ExecutionStatus,
    ActionType,
    soar_platform
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/soar", tags=["SOAR"])

@router.post("/playbooks")
async def create_playbook(playbook_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Create a new security playbook
    """
    try:
        playbook_id = await soar_platform.create_playbook(playbook_data)
        
        return {
            "status": "created",
            "playbook_id": playbook_id,
            "name": playbook_data.get("name"),
            "version": playbook_data.get("version", "1.0")
        }
        
    except Exception as e:
        logger.error(f"Failed to create playbook: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to create playbook: {str(e)}")

@router.get("/playbooks")
async def get_playbooks(
    status: Optional[str] = None,
    limit: int = Query(default=50, le=100)
) -> Dict[str, Any]:
    """
    Get all playbooks with optional status filtering
    """
    try:
        status_filter = PlaybookStatus(status) if status else None
        playbooks = await soar_platform.get_playbooks(status_filter)
        
        # Limit results
        playbooks = playbooks[:limit]
        
        return {
            "status": "success",
            "total_playbooks": len(playbooks),
            "playbooks": playbooks
        }
        
    except Exception as e:
        logger.error(f"Failed to get playbooks: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to get playbooks: {str(e)}")

@router.get("/playbooks/{playbook_id}")
async def get_playbook(playbook_id: str) -> Dict[str, Any]:
    """
    Get detailed playbook information
    """
    try:
        if playbook_id not in soar_platform.playbooks:
            raise HTTPException(status_code=404, detail="Playbook not found")
        
        playbook = soar_platform.playbooks[playbook_id]
        
        return {
            "status": "success",
            "playbook": {
                "id": playbook.id,
                "name": playbook.name,
                "description": playbook.description,
                "version": playbook.version,
                "status": playbook.status.value,
                "trigger_conditions": playbook.trigger_conditions,
                "variables": playbook.variables,
                "tags": playbook.tags,
                "created_by": playbook.created_by,
                "created_at": playbook.created_at.isoformat(),
                "updated_at": playbook.updated_at.isoformat(),
                "actions": [
                    {
                        "id": action.id,
                        "name": action.name,
                        "action_type": action.action_type.value,
                        "parameters": action.parameters,
                        "timeout_seconds": action.timeout_seconds,
                        "requires_approval": action.requires_approval,
                        "depends_on": action.depends_on,
                        "conditions": action.conditions
                    } for action in playbook.actions
                ]
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get playbook: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to get playbook: {str(e)}")

@router.put("/playbooks/{playbook_id}/status")
async def update_playbook_status(
    playbook_id: str,
    status: str
) -> Dict[str, Any]:
    """
    Update playbook status (activate, deactivate, etc.)
    """
    try:
        if playbook_id not in soar_platform.playbooks:
            raise HTTPException(status_code=404, detail="Playbook not found")
        
        playbook = soar_platform.playbooks[playbook_id]
        playbook.status = PlaybookStatus(status)
        playbook.updated_at = datetime.now()
        
        return {
            "status": "updated",
            "playbook_id": playbook_id,
            "new_status": status
        }
        
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid status: {status}")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update playbook status: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to update playbook status: {str(e)}")

@router.post("/incidents/trigger")
async def trigger_incident_response(
    incident_data: Dict[str, Any],
    background_tasks: BackgroundTasks,
    triggered_by: str = "api"
) -> Dict[str, Any]:
    """
    Trigger playbooks based on incident data
    """
    try:
        execution_ids = await soar_platform.trigger_playbook(incident_data, triggered_by)
        
        # Start background monitoring for executions
        background_tasks.add_task(monitor_executions, execution_ids)
        
        return {
            "status": "triggered",
            "incident_id": incident_data.get("id", "unknown"),
            "executions_started": len(execution_ids),
            "execution_ids": execution_ids
        }
        
    except Exception as e:
        logger.error(f"Failed to trigger incident response: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to trigger incident response: {str(e)}")

async def monitor_executions(execution_ids: List[str]):
    """Background task to monitor execution progress"""
    try:
        for execution_id in execution_ids:
            logger.info(f"Monitoring execution: {execution_id}")
            # Additional monitoring logic can be added here
    except Exception as e:
        logger.error(f"Execution monitoring failed: {str(e)}")

@router.get("/executions")
async def get_executions(
    status: Optional[str] = None,
    playbook_id: Optional[str] = None,
    incident_id: Optional[str] = None,
    limit: int = Query(default=50, le=100)
) -> Dict[str, Any]:
    """
    Get playbook executions with optional filtering
    """
    try:
        status_filter = ExecutionStatus(status) if status else None
        executions = await soar_platform.get_executions(status_filter)
        
        # Apply additional filters
        if playbook_id:
            executions = [e for e in executions if e["playbook_id"] == playbook_id]
        
        if incident_id:
            executions = [e for e in executions if e["incident_id"] == incident_id]
        
        # Limit results
        executions = executions[:limit]
        
        return {
            "status": "success",
            "total_executions": len(executions),
            "executions": executions
        }
        
    except Exception as e:
        logger.error(f"Failed to get executions: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to get executions: {str(e)}")

@router.get("/executions/{execution_id}")
async def get_execution_details(execution_id: str) -> Dict[str, Any]:
    """
    Get detailed execution information including logs and results
    """
    try:
        execution_details = await soar_platform.get_execution_details(execution_id)
        
        if not execution_details:
            raise HTTPException(status_code=404, detail="Execution not found")
        
        return {
            "status": "success",
            "execution": execution_details
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get execution details: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to get execution details: {str(e)}")

@router.post("/executions/{execution_id}/cancel")
async def cancel_execution(execution_id: str) -> Dict[str, Any]:
    """
    Cancel a running playbook execution
    """
    try:
        success = await soar_platform.cancel_execution(execution_id)
        
        if not success:
            raise HTTPException(status_code=404, detail="Execution not found or cannot be cancelled")
        
        return {
            "status": "cancelled",
            "execution_id": execution_id
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to cancel execution: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to cancel execution: {str(e)}")

@router.get("/approvals")
async def get_pending_approvals() -> Dict[str, Any]:
    """
    Get all pending approval requests
    """
    try:
        approvals = await soar_platform.get_pending_approvals()
        
        return {
            "status": "success",
            "pending_approvals": len(approvals),
            "approvals": [
                {
                    "id": approval["id"],
                    "execution_id": approval["execution_id"],
                    "action_id": approval["action_id"],
                    "action_name": approval["action_name"],
                    "action_type": approval["action_type"],
                    "parameters": approval["parameters"],
                    "requested_at": approval["requested_at"].isoformat()
                } for approval in approvals
            ]
        }
        
    except Exception as e:
        logger.error(f"Failed to get approvals: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to get approvals: {str(e)}")

@router.post("/approvals/{approval_id}")
async def approve_action(
    approval_id: str,
    approved: bool,
    reason: str = ""
) -> Dict[str, Any]:
    """
    Approve or deny a pending action
    """
    try:
        success = await soar_platform.approve_action(approval_id, approved, reason)
        
        if not success:
            raise HTTPException(status_code=404, detail="Approval request not found")
        
        return {
            "status": "approved" if approved else "denied",
            "approval_id": approval_id,
            "reason": reason
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to process approval: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to process approval: {str(e)}")

@router.get("/metrics")
async def get_soar_metrics() -> Dict[str, Any]:
    """
    Get SOAR platform performance metrics
    """
    try:
        metrics = await soar_platform.get_soar_metrics()
        
        return {
            "status": "success",
            "metrics": metrics
        }
        
    except Exception as e:
        logger.error(f"Failed to get SOAR metrics: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to get SOAR metrics: {str(e)}")

@router.get("/templates")
async def get_playbook_templates() -> Dict[str, Any]:
    """
    Get predefined playbook templates for common scenarios
    """
    try:
        templates = [
            {
                "id": "malware_response",
                "name": "Malware Response",
                "description": "Automated response to malware detection",
                "category": "malware",
                "actions": [
                    {"type": "isolate_host", "name": "Isolate Infected Host"},
                    {"type": "collect_evidence", "name": "Collect Forensic Evidence"},
                    {"type": "quarantine_file", "name": "Quarantine Malicious File"},
                    {"type": "reset_password", "name": "Reset User Password"},
                    {"type": "create_ticket", "name": "Create Investigation Ticket"}
                ]
            },
            {
                "id": "data_breach_response",
                "name": "Data Breach Response", 
                "description": "Comprehensive data breach incident response",
                "category": "data_breach",
                "actions": [
                    {"type": "send_alert", "name": "Notify Security Team"},
                    {"type": "isolate_host", "name": "Isolate Affected Systems"},
                    {"type": "collect_evidence", "name": "Preserve Evidence"},
                    {"type": "block_ip", "name": "Block Suspicious IPs"},
                    {"type": "create_ticket", "name": "Create Legal/Compliance Ticket"}
                ]
            },
            {
                "id": "phishing_response",
                "name": "Phishing Response",
                "description": "Automated phishing attack response",
                "category": "phishing",
                "actions": [
                    {"type": "block_ip", "name": "Block Phishing Domain"},
                    {"type": "quarantine_file", "name": "Quarantine Email Attachments"},
                    {"type": "reset_password", "name": "Force Password Reset"},
                    {"type": "send_alert", "name": "Warn All Users"},
                    {"type": "update_threat_intel", "name": "Update IOC Database"}
                ]
            },
            {
                "id": "insider_threat_response",
                "name": "Insider Threat Response",
                "description": "Response to suspicious insider activity",
                "category": "insider_threat",
                "actions": [
                    {"type": "collect_evidence", "name": "Collect Activity Logs"},
                    {"type": "reset_password", "name": "Disable User Account"},
                    {"type": "send_alert", "name": "Notify HR and Legal"},
                    {"type": "create_ticket", "name": "Create Investigation Case"},
                    {"type": "approve_action", "name": "Manager Approval Required"}
                ]
            },
            {
                "id": "vulnerability_response",
                "name": "Critical Vulnerability Response",
                "description": "Response to critical vulnerability detection",
                "category": "vulnerability",
                "actions": [
                    {"type": "run_scan", "name": "Validate Vulnerability"},
                    {"type": "isolate_host", "name": "Isolate Vulnerable Systems"},
                    {"type": "execute_script", "name": "Apply Emergency Patch"},
                    {"type": "send_alert", "name": "Notify Operations Team"},
                    {"type": "create_ticket", "name": "Track Remediation"}
                ]
            }
        ]
        
        return {
            "status": "success",
            "templates": templates
        }
        
    except Exception as e:
        logger.error(f"Failed to get templates: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to get templates: {str(e)}")

@router.post("/templates/{template_id}/create-playbook")
async def create_playbook_from_template(
    template_id: str,
    customization: Dict[str, Any] = {}
) -> Dict[str, Any]:
    """
    Create a playbook from a predefined template
    """
    try:
        # Get template definitions (simplified for demo)
        templates = {
            "malware_response": {
                "name": "Malware Response Playbook",
                "description": "Automated malware incident response",
                "trigger_conditions": {
                    "event_type": "malware_detected",
                    "severity": {"operator": "greater_than", "value": 3}
                },
                "actions": [
                    {
                        "id": "isolate_host",
                        "name": "Isolate Infected Host",
                        "action_type": "ISOLATE_HOST",
                        "parameters": {"host": "${incident.affected_host}"},
                        "timeout_seconds": 60
                    },
                    {
                        "id": "collect_evidence", 
                        "name": "Collect Evidence",
                        "action_type": "COLLECT_EVIDENCE",
                        "parameters": {"target": "${incident.affected_host}", "evidence_types": ["memory", "disk", "network"]},
                        "depends_on": ["isolate_host"],
                        "timeout_seconds": 300
                    },
                    {
                        "id": "create_ticket",
                        "name": "Create Investigation Ticket",
                        "action_type": "CREATE_TICKET", 
                        "parameters": {"title": "Malware Investigation", "priority": "high"},
                        "depends_on": ["collect_evidence"],
                        "timeout_seconds": 30
                    }
                ]
            }
        }
        
        if template_id not in templates:
            raise HTTPException(status_code=404, detail="Template not found")
        
        template = templates[template_id]
        
        # Apply customizations
        playbook_data = {**template, **customization}
        playbook_data["version"] = "1.0"
        playbook_data["created_by"] = "template"
        
        # Create playbook
        playbook_id = await soar_platform.create_playbook(playbook_data)
        
        return {
            "status": "created",
            "playbook_id": playbook_id,
            "template_id": template_id,
            "name": playbook_data["name"]
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to create playbook from template: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to create playbook from template: {str(e)}")

@router.get("/action-types")
async def get_available_action_types() -> Dict[str, Any]:
    """
    Get all available action types for playbook creation
    """
    try:
        action_types = [
            {
                "type": "ISOLATE_HOST",
                "name": "Isolate Host",
                "description": "Isolate a host from the network",
                "parameters": [
                    {"name": "host", "type": "string", "required": True, "description": "Host to isolate"}
                ]
            },
            {
                "type": "BLOCK_IP",
                "name": "Block IP Address",
                "description": "Block an IP address on firewalls",
                "parameters": [
                    {"name": "ip_address", "type": "string", "required": True, "description": "IP to block"},
                    {"name": "duration", "type": "integer", "required": False, "description": "Block duration in seconds"}
                ]
            },
            {
                "type": "QUARANTINE_FILE",
                "name": "Quarantine File",
                "description": "Move file to quarantine location",
                "parameters": [
                    {"name": "file_path", "type": "string", "required": True, "description": "Path to file"},
                    {"name": "file_hash", "type": "string", "required": False, "description": "File hash"}
                ]
            },
            {
                "type": "RESET_PASSWORD",
                "name": "Reset Password",
                "description": "Force password reset for user",
                "parameters": [
                    {"name": "username", "type": "string", "required": True, "description": "Username to reset"}
                ]
            },
            {
                "type": "SEND_ALERT",
                "name": "Send Alert",
                "description": "Send notification to recipients",
                "parameters": [
                    {"name": "recipients", "type": "array", "required": True, "description": "Alert recipients"},
                    {"name": "subject", "type": "string", "required": True, "description": "Alert subject"},
                    {"name": "message", "type": "string", "required": True, "description": "Alert message"}
                ]
            },
            {
                "type": "COLLECT_EVIDENCE",
                "name": "Collect Evidence",
                "description": "Collect digital forensic evidence",
                "parameters": [
                    {"name": "target", "type": "string", "required": True, "description": "Evidence collection target"},
                    {"name": "evidence_types", "type": "array", "required": False, "description": "Types of evidence to collect"}
                ]
            },
            {
                "type": "CREATE_TICKET",
                "name": "Create Ticket",
                "description": "Create incident tracking ticket",
                "parameters": [
                    {"name": "title", "type": "string", "required": True, "description": "Ticket title"},
                    {"name": "description", "type": "string", "required": False, "description": "Ticket description"},
                    {"name": "priority", "type": "string", "required": False, "description": "Ticket priority"}
                ]
            },
            {
                "type": "RUN_SCAN",
                "name": "Run Security Scan",
                "description": "Execute security scan on targets",
                "parameters": [
                    {"name": "scan_type", "type": "string", "required": True, "description": "Type of scan"},
                    {"name": "targets", "type": "array", "required": True, "description": "Scan targets"}
                ]
            },
            {
                "type": "EXECUTE_SCRIPT",
                "name": "Execute Script",
                "description": "Run custom automation script",
                "parameters": [
                    {"name": "script_path", "type": "string", "required": True, "description": "Path to script"},
                    {"name": "args", "type": "array", "required": False, "description": "Script arguments"}
                ]
            },
            {
                "type": "APPROVE_ACTION",
                "name": "Approval Checkpoint",
                "description": "Require manual approval before proceeding",
                "parameters": []
            }
        ]
        
        return {
            "status": "success",
            "action_types": action_types
        }
        
    except Exception as e:
        logger.error(f"Failed to get action types: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to get action types: {str(e)}")

@router.get("/health")
async def health_check() -> Dict[str, Any]:
    """
    Health check for SOAR platform
    """
    try:
        metrics = await soar_platform.get_soar_metrics()
        
        return {
            "status": "healthy",
            "platform_ready": True,
            "active_playbooks": metrics.get("active_playbooks", 0),
            "running_executions": metrics.get("running_executions", 0),
            "system_health": metrics.get("system_health", 0),
            "action_handlers": len(soar_platform.action_handlers)
        }
        
    except Exception as e:
        logger.error(f"SOAR health check failed: {str(e)}")
        return {
            "status": "unhealthy",
            "error": str(e),
            "platform_ready": False
        }