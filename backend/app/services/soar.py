"""
SOAR Platform - Security Orchestration, Automated Response
Comprehensive security incident response and automation
"""

import logging
import asyncio
import json
from typing import Dict, List, Optional, Any, Callable
from datetime import datetime, timedelta
from enum import Enum
from dataclasses import dataclass, field
from uuid import uuid4

logger = logging.getLogger(__name__)

class IncidentSeverity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class IncidentStatus(Enum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    CLOSED = "closed"

class PlaybookStatus(Enum):
    IDLE = "idle"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    PAUSED = "paused"

class ResponseAction(Enum):
    BLOCK_IP = "block_ip"
    ISOLATE_HOST = "isolate_host"
    RESET_PASSWORD = "reset_password"
    DISABLE_ACCOUNT = "disable_account"
    QUARANTINE_FILE = "quarantine_file"
    SEND_ALERT = "send_alert"
    CREATE_TICKET = "create_ticket"
    COLLECT_LOGS = "collect_logs"
    SCAN_SYSTEM = "scan_system"
    UPDATE_RULES = "update_rules"

@dataclass
class SOARAction:
    action_id: str
    action_type: ResponseAction
    parameters: Dict[str, Any]
    condition: Optional[str] = None
    timeout: int = 300  # 5 minutes default
    retry_count: int = 3
    success_criteria: Optional[str] = None

@dataclass
class PlaybookStep:
    step_id: str
    name: str
    description: str
    actions: List[SOARAction]
    parallel: bool = False
    required: bool = True
    depends_on: List[str] = field(default_factory=list)

@dataclass
class SecurityPlaybook:
    playbook_id: str
    name: str
    description: str
    trigger_conditions: List[str]
    severity_threshold: IncidentSeverity
    steps: List[PlaybookStep]
    auto_execute: bool = False
    approval_required: bool = True
    tags: List[str] = field(default_factory=list)

@dataclass
class SecurityIncident:
    incident_id: str
    title: str
    description: str
    severity: IncidentSeverity
    status: IncidentStatus
    created_at: datetime
    updated_at: datetime
    source: str
    indicators: List[Dict[str, Any]]
    affected_assets: List[str]
    assigned_to: Optional[str] = None
    playbooks_executed: List[str] = field(default_factory=list)
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    timeline: List[Dict[str, Any]] = field(default_factory=list)

@dataclass
class PlaybookExecution:
    execution_id: str
    playbook_id: str
    incident_id: str
    status: PlaybookStatus
    started_at: datetime
    completed_at: Optional[datetime] = None
    current_step: Optional[str] = None
    execution_log: List[Dict[str, Any]] = field(default_factory=list)
    success_rate: float = 0.0

class SOAROrchestrator:
    name: str
    action_type: ActionType
    parameters: Dict[str, Any]
    timeout_seconds: int = 300
    retry_count: int = 0
    max_retries: int = 3
    requires_approval: bool = False
    depends_on: List[str] = field(default_factory=list)
    conditions: Dict[str, Any] = field(default_factory=dict)
    
class PlaybookExecution:
    def __init__(self, execution_id: str, playbook_id: str, incident_id: str, triggered_by: str):
        self.execution_id = execution_id
        self.playbook_id = playbook_id
        self.incident_id = incident_id
        self.triggered_by = triggered_by
        self.status = ExecutionStatus.PENDING
        self.started_at = datetime.now()
        self.completed_at: Optional[datetime] = None
        self.action_results: Dict[str, Dict[str, Any]] = {}
        self.context: Dict[str, Any] = {}
        self.logs: List[Dict[str, Any]] = []
        
    def add_log(self, level: str, message: str, action_id: Optional[str] = None):
        self.logs.append({
            "timestamp": datetime.now(),
            "level": level,
            "message": message,
            "action_id": action_id
        })

@dataclass
class SecurityPlaybook:
    id: str
    name: str
    description: str
    version: str
    trigger_conditions: Dict[str, Any]
    actions: List[PlaybookAction]
    variables: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    created_by: str = ""
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    status: PlaybookStatus = PlaybookStatus.DRAFT

class SOARPlatform:
    """
    Advanced Security Orchestration, Automation & Response Platform
    """
    
    def __init__(self, config_path: Optional[str] = None):
        self.playbooks: Dict[str, SecurityPlaybook] = {}
        self.executions: Dict[str, PlaybookExecution] = {}
        self.action_handlers: Dict[ActionType, callable] = {}
        self.approval_queue: List[Dict[str, Any]] = []
        self.config = self._load_config(config_path)
        self._register_action_handlers()
        
    def _load_config(self, config_path: Optional[str]) -> Dict[str, Any]:
        """Load SOAR platform configuration"""
        default_config = {
            "max_concurrent_executions": 10,
            "default_timeout": 300,
            "approval_timeout": 3600,
            "enable_parallel_execution": True,
            "log_level": "INFO"
        }
        
        if config_path and Path(config_path).exists():
            with open(config_path, 'r') as f:
                user_config = json.load(f)
                default_config.update(user_config)
                
        return default_config
    
    def _register_action_handlers(self):
        """Register handlers for different action types"""
        self.action_handlers = {
            ActionType.ISOLATE_HOST: self._isolate_host,
            ActionType.BLOCK_IP: self._block_ip,
            ActionType.QUARANTINE_FILE: self._quarantine_file,
            ActionType.RESET_PASSWORD: self._reset_password,
            ActionType.SEND_ALERT: self._send_alert,
            ActionType.COLLECT_EVIDENCE: self._collect_evidence,
            ActionType.CREATE_TICKET: self._create_ticket,
            ActionType.RUN_SCAN: self._run_scan,
            ActionType.UPDATE_THREAT_INTEL: self._update_threat_intel,
            ActionType.EXECUTE_SCRIPT: self._execute_script,
            ActionType.APPROVE_ACTION: self._approve_action,
            ActionType.WAIT: self._wait
        }
    
    async def create_playbook(self, playbook_data: Dict[str, Any]) -> str:
        """Create a new security playbook"""
        try:
            playbook_id = playbook_data.get('id', str(uuid.uuid4()))
            
            # Parse actions
            actions = []
            for action_data in playbook_data.get('actions', []):
                action = PlaybookAction(
                    id=action_data['id'],
                    name=action_data['name'],
                    action_type=ActionType(action_data['action_type']),
                    parameters=action_data.get('parameters', {}),
                    timeout_seconds=action_data.get('timeout_seconds', 300),
                    requires_approval=action_data.get('requires_approval', False),
                    depends_on=action_data.get('depends_on', []),
                    conditions=action_data.get('conditions', {})
                )
                actions.append(action)
            
            playbook = SecurityPlaybook(
                id=playbook_id,
                name=playbook_data['name'],
                description=playbook_data['description'],
                version=playbook_data.get('version', '1.0'),
                trigger_conditions=playbook_data.get('trigger_conditions', {}),
                actions=actions,
                variables=playbook_data.get('variables', {}),
                tags=playbook_data.get('tags', []),
                created_by=playbook_data.get('created_by', 'system')
            )
            
            self.playbooks[playbook_id] = playbook
            logger.info(f"Created playbook: {playbook.name} ({playbook_id})")
            
            return playbook_id
            
        except Exception as e:
            logger.error(f"Failed to create playbook: {str(e)}")
            raise
    
    async def trigger_playbook(self, incident_data: Dict[str, Any], triggered_by: str = "system") -> List[str]:
        """Trigger playbooks based on incident conditions"""
        try:
            triggered_executions = []
            
            for playbook in self.playbooks.values():
                if playbook.status != PlaybookStatus.ACTIVE:
                    continue
                    
                # Check trigger conditions
                if self._evaluate_trigger_conditions(incident_data, playbook.trigger_conditions):
                    execution_id = await self._execute_playbook(
                        playbook.id, 
                        incident_data.get('id', str(uuid.uuid4())),
                        triggered_by,
                        incident_data
                    )
                    triggered_executions.append(execution_id)
            
            logger.info(f"Triggered {len(triggered_executions)} playbook executions")
            return triggered_executions
            
        except Exception as e:
            logger.error(f"Failed to trigger playbooks: {str(e)}")
            raise
    
    def _evaluate_trigger_conditions(self, incident_data: Dict[str, Any], conditions: Dict[str, Any]) -> bool:
        """Evaluate if incident matches playbook trigger conditions"""
        try:
            # Simple condition evaluation - can be extended for complex logic
            for key, expected_value in conditions.items():
                if key not in incident_data:
                    return False
                    
                actual_value = incident_data[key]
                
                # Handle different comparison types
                if isinstance(expected_value, dict):
                    operator = expected_value.get('operator', 'equals')
                    value = expected_value.get('value')
                    
                    if operator == 'equals' and actual_value != value:
                        return False
                    elif operator == 'contains' and value not in str(actual_value):
                        return False
                    elif operator == 'greater_than' and actual_value <= value:
                        return False
                    elif operator == 'less_than' and actual_value >= value:
                        return False
                    elif operator == 'in' and actual_value not in value:
                        return False
                else:
                    if actual_value != expected_value:
                        return False
            
            return True
            
        except Exception as e:
            logger.error(f"Error evaluating trigger conditions: {str(e)}")
            return False
    
    async def _execute_playbook(self, playbook_id: str, incident_id: str, triggered_by: str, context: Dict[str, Any]) -> str:
        """Execute a playbook for an incident"""
        try:
            execution_id = str(uuid.uuid4())
            execution = PlaybookExecution(execution_id, playbook_id, incident_id, triggered_by)
            execution.context = context
            
            self.executions[execution_id] = execution
            
            # Start async execution
            asyncio.create_task(self._run_playbook_execution(execution_id))
            
            logger.info(f"Started playbook execution: {execution_id}")
            return execution_id
            
        except Exception as e:
            logger.error(f"Failed to execute playbook: {str(e)}")
            raise
    
    async def _run_playbook_execution(self, execution_id: str):
        """Run the actual playbook execution"""
        try:
            execution = self.executions[execution_id]
            playbook = self.playbooks[execution.playbook_id]
            
            execution.status = ExecutionStatus.RUNNING
            execution.add_log("INFO", "Playbook execution started")
            
            # Build dependency graph
            action_graph = self._build_action_graph(playbook.actions)
            
            # Execute actions based on dependencies
            await self._execute_action_graph(execution, playbook, action_graph)
            
            execution.status = ExecutionStatus.COMPLETED
            execution.completed_at = datetime.now()
            execution.add_log("INFO", "Playbook execution completed")
            
        except Exception as e:
            execution = self.executions[execution_id]
            execution.status = ExecutionStatus.FAILED
            execution.completed_at = datetime.now()
            execution.add_log("ERROR", f"Playbook execution failed: {str(e)}")
            logger.error(f"Playbook execution failed: {str(e)}")
    
    def _build_action_graph(self, actions: List[PlaybookAction]) -> Dict[str, List[str]]:
        """Build dependency graph for actions"""
        graph = {}
        for action in actions:
            graph[action.id] = action.depends_on
        return graph
    
    async def _execute_action_graph(self, execution: PlaybookExecution, playbook: SecurityPlaybook, graph: Dict[str, List[str]]):
        """Execute actions respecting dependencies"""
        completed_actions = set()
        pending_actions = set(graph.keys())
        
        while pending_actions:
            # Find actions that can be executed (dependencies satisfied)
            ready_actions = []
            for action_id in pending_actions:
                dependencies = graph[action_id]
                if all(dep in completed_actions for dep in dependencies):
                    ready_actions.append(action_id)
            
            if not ready_actions:
                # Circular dependency or missing action
                execution.add_log("ERROR", "Circular dependency detected or missing action")
                break
            
            # Execute ready actions (can be parallel if enabled)
            if self.config['enable_parallel_execution']:
                tasks = []
                for action_id in ready_actions:
                    action = next(a for a in playbook.actions if a.id == action_id)
                    task = asyncio.create_task(self._execute_action(execution, action))
                    tasks.append(task)
                
                results = await asyncio.gather(*tasks, return_exceptions=True)
                
                for i, result in enumerate(results):
                    action_id = ready_actions[i]
                    if isinstance(result, Exception):
                        execution.add_log("ERROR", f"Action {action_id} failed: {str(result)}", action_id)
                    else:
                        completed_actions.add(action_id)
                        pending_actions.remove(action_id)
            else:
                # Sequential execution
                for action_id in ready_actions:
                    action = next(a for a in playbook.actions if a.id == action_id)
                    try:
                        await self._execute_action(execution, action)
                        completed_actions.add(action_id)
                        pending_actions.remove(action_id)
                    except Exception as e:
                        execution.add_log("ERROR", f"Action {action_id} failed: {str(e)}", action_id)
                        break
    
    async def _execute_action(self, execution: PlaybookExecution, action: PlaybookAction) -> Dict[str, Any]:
        """Execute a single playbook action"""
        try:
            execution.add_log("INFO", f"Executing action: {action.name}", action.id)
            
            # Check if approval is required
            if action.requires_approval:
                approval_result = await self._request_approval(execution, action)
                if not approval_result.get('approved', False):
                    execution.add_log("INFO", f"Action {action.name} skipped - approval denied", action.id)
                    return {"status": "skipped", "reason": "approval_denied"}
            
            # Get action handler
            handler = self.action_handlers.get(action.action_type)
            if not handler:
                raise ValueError(f"No handler for action type: {action.action_type}")
            
            # Execute with timeout and retry
            for attempt in range(action.max_retries + 1):
                try:
                    result = await asyncio.wait_for(
                        handler(execution, action),
                        timeout=action.timeout_seconds
                    )
                    
                    execution.action_results[action.id] = result
                    execution.add_log("INFO", f"Action {action.name} completed successfully", action.id)
                    return result
                    
                except asyncio.TimeoutError:
                    if attempt == action.max_retries:
                        raise
                    execution.add_log("WARNING", f"Action {action.name} timeout, retrying {attempt + 1}/{action.max_retries}", action.id)
                    await asyncio.sleep(2 ** attempt)  # Exponential backoff
                    
        except Exception as e:
            execution.add_log("ERROR", f"Action {action.name} failed: {str(e)}", action.id)
            raise
    
    async def _request_approval(self, execution: PlaybookExecution, action: PlaybookAction) -> Dict[str, Any]:
        """Request approval for an action"""
        approval_request = {
            "id": str(uuid.uuid4()),
            "execution_id": execution.execution_id,
            "action_id": action.id,
            "action_name": action.name,
            "action_type": action.action_type.value,
            "parameters": action.parameters,
            "requested_at": datetime.now(),
            "status": "pending"
        }
        
        self.approval_queue.append(approval_request)
        
        # Wait for approval (with timeout)
        timeout = self.config['approval_timeout']
        start_time = datetime.now()
        
        while (datetime.now() - start_time).seconds < timeout:
            # Check if approval was granted
            for req in self.approval_queue:
                if req['id'] == approval_request['id'] and req['status'] != 'pending':
                    return {"approved": req['status'] == 'approved', "reason": req.get('reason', '')}
            
            await asyncio.sleep(5)  # Check every 5 seconds
        
        # Timeout - auto-deny
        return {"approved": False, "reason": "approval_timeout"}
    
    # Action Handlers
    async def _isolate_host(self, execution: PlaybookExecution, action: PlaybookAction) -> Dict[str, Any]:
        """Isolate a host from the network"""
        host = action.parameters.get('host')
        execution.add_log("INFO", f"Isolating host: {host}", action.id)
        
        # Simulate host isolation
        await asyncio.sleep(2)
        
        return {
            "status": "success",
            "action": "host_isolated",
            "host": host,
            "timestamp": datetime.now()
        }
    
    async def _block_ip(self, execution: PlaybookExecution, action: PlaybookAction) -> Dict[str, Any]:
        """Block an IP address"""
        ip_address = action.parameters.get('ip_address')
        duration = action.parameters.get('duration', 3600)
        
        execution.add_log("INFO", f"Blocking IP: {ip_address} for {duration} seconds", action.id)
        
        # Simulate IP blocking
        await asyncio.sleep(1)
        
        return {
            "status": "success",
            "action": "ip_blocked",
            "ip_address": ip_address,
            "duration": duration,
            "timestamp": datetime.now()
        }
    
    async def _quarantine_file(self, execution: PlaybookExecution, action: PlaybookAction) -> Dict[str, Any]:
        """Quarantine a suspicious file"""
        file_path = action.parameters.get('file_path')
        file_hash = action.parameters.get('file_hash')
        
        execution.add_log("INFO", f"Quarantining file: {file_path}", action.id)
        
        # Simulate file quarantine
        await asyncio.sleep(1.5)
        
        return {
            "status": "success",
            "action": "file_quarantined",
            "file_path": file_path,
            "file_hash": file_hash,
            "quarantine_location": f"/quarantine/{file_hash}",
            "timestamp": datetime.now()
        }
    
    async def _reset_password(self, execution: PlaybookExecution, action: PlaybookAction) -> Dict[str, Any]:
        """Reset user password"""
        username = action.parameters.get('username')
        
        execution.add_log("INFO", f"Resetting password for user: {username}", action.id)
        
        # Simulate password reset
        await asyncio.sleep(2)
        
        return {
            "status": "success",
            "action": "password_reset",
            "username": username,
            "timestamp": datetime.now()
        }
    
    async def _send_alert(self, execution: PlaybookExecution, action: PlaybookAction) -> Dict[str, Any]:
        """Send security alert"""
        recipients = action.parameters.get('recipients', [])
        subject = action.parameters.get('subject', 'Security Alert')
        message = action.parameters.get('message', '')
        
        execution.add_log("INFO", f"Sending alert to {len(recipients)} recipients", action.id)
        
        # Simulate sending alert
        await asyncio.sleep(1)
        
        return {
            "status": "success",
            "action": "alert_sent",
            "recipients": recipients,
            "subject": subject,
            "timestamp": datetime.now()
        }
    
    async def _collect_evidence(self, execution: PlaybookExecution, action: PlaybookAction) -> Dict[str, Any]:
        """Collect digital evidence"""
        target = action.parameters.get('target')
        evidence_types = action.parameters.get('evidence_types', [])
        
        execution.add_log("INFO", f"Collecting evidence from: {target}", action.id)
        
        # Simulate evidence collection
        await asyncio.sleep(3)
        
        return {
            "status": "success",
            "action": "evidence_collected",
            "target": target,
            "evidence_types": evidence_types,
            "evidence_id": str(uuid.uuid4()),
            "timestamp": datetime.now()
        }
    
    async def _create_ticket(self, execution: PlaybookExecution, action: PlaybookAction) -> Dict[str, Any]:
        """Create incident ticket"""
        title = action.parameters.get('title', 'Security Incident')
        description = action.parameters.get('description', '')
        priority = action.parameters.get('priority', 'medium')
        
        execution.add_log("INFO", f"Creating ticket: {title}", action.id)
        
        # Simulate ticket creation
        await asyncio.sleep(1)
        ticket_id = f"INC-{datetime.now().strftime('%Y%m%d')}-{str(uuid.uuid4())[:8]}"
        
        return {
            "status": "success",
            "action": "ticket_created",
            "ticket_id": ticket_id,
            "title": title,
            "priority": priority,
            "timestamp": datetime.now()
        }
    
    async def _run_scan(self, execution: PlaybookExecution, action: PlaybookAction) -> Dict[str, Any]:
        """Run security scan"""
        scan_type = action.parameters.get('scan_type', 'vulnerability')
        targets = action.parameters.get('targets', [])
        
        execution.add_log("INFO", f"Running {scan_type} scan on {len(targets)} targets", action.id)
        
        # Simulate scan execution
        await asyncio.sleep(5)
        
        return {
            "status": "success",
            "action": "scan_completed",
            "scan_type": scan_type,
            "targets": targets,
            "scan_id": str(uuid.uuid4()),
            "timestamp": datetime.now()
        }
    
    async def _update_threat_intel(self, execution: PlaybookExecution, action: PlaybookAction) -> Dict[str, Any]:
        """Update threat intelligence"""
        indicators = action.parameters.get('indicators', [])
        source = action.parameters.get('source', 'soar')
        
        execution.add_log("INFO", f"Updating threat intel with {len(indicators)} indicators", action.id)
        
        # Simulate threat intel update
        await asyncio.sleep(2)
        
        return {
            "status": "success",
            "action": "threat_intel_updated",
            "indicators_count": len(indicators),
            "source": source,
            "timestamp": datetime.now()
        }
    
    async def _execute_script(self, execution: PlaybookExecution, action: PlaybookAction) -> Dict[str, Any]:
        """Execute custom script"""
        script_path = action.parameters.get('script_path')
        script_args = action.parameters.get('args', [])
        
        execution.add_log("INFO", f"Executing script: {script_path}", action.id)
        
        # Simulate script execution
        await asyncio.sleep(3)
        
        return {
            "status": "success",
            "action": "script_executed",
            "script_path": script_path,
            "exit_code": 0,
            "timestamp": datetime.now()
        }
    
    async def _approve_action(self, execution: PlaybookExecution, action: PlaybookAction) -> Dict[str, Any]:
        """Manual approval checkpoint"""
        return await self._request_approval(execution, action)
    
    async def _wait(self, execution: PlaybookExecution, action: PlaybookAction) -> Dict[str, Any]:
        """Wait for specified duration"""
        duration = action.parameters.get('duration', 10)
        
        execution.add_log("INFO", f"Waiting for {duration} seconds", action.id)
        await asyncio.sleep(duration)
        
        return {
            "status": "success",
            "action": "wait_completed",
            "duration": duration,
            "timestamp": datetime.now()
        }
    
    # Management Methods
    async def get_playbooks(self, status_filter: Optional[PlaybookStatus] = None) -> List[Dict[str, Any]]:
        """Get all playbooks with optional status filtering"""
        playbooks = []
        for playbook in self.playbooks.values():
            if status_filter and playbook.status != status_filter:
                continue
                
            playbooks.append({
                "id": playbook.id,
                "name": playbook.name,
                "description": playbook.description,
                "version": playbook.version,
                "status": playbook.status.value,
                "actions_count": len(playbook.actions),
                "tags": playbook.tags,
                "created_by": playbook.created_by,
                "created_at": playbook.created_at,
                "updated_at": playbook.updated_at
            })
        
        return playbooks
    
    async def get_executions(self, status_filter: Optional[ExecutionStatus] = None) -> List[Dict[str, Any]]:
        """Get playbook executions with optional status filtering"""
        executions = []
        for execution in self.executions.values():
            if status_filter and execution.status != status_filter:
                continue
                
            executions.append({
                "execution_id": execution.execution_id,
                "playbook_id": execution.playbook_id,
                "incident_id": execution.incident_id,
                "status": execution.status.value,
                "triggered_by": execution.triggered_by,
                "started_at": execution.started_at,
                "completed_at": execution.completed_at,
                "actions_completed": len(execution.action_results),
                "logs_count": len(execution.logs)
            })
        
        return executions
    
    async def get_execution_details(self, execution_id: str) -> Optional[Dict[str, Any]]:
        """Get detailed execution information"""
        if execution_id not in self.executions:
            return None
            
        execution = self.executions[execution_id]
        playbook = self.playbooks.get(execution.playbook_id)
        
        return {
            "execution_id": execution.execution_id,
            "playbook": {
                "id": execution.playbook_id,
                "name": playbook.name if playbook else "Unknown",
                "version": playbook.version if playbook else "Unknown"
            },
            "incident_id": execution.incident_id,
            "status": execution.status.value,
            "triggered_by": execution.triggered_by,
            "started_at": execution.started_at,
            "completed_at": execution.completed_at,
            "duration": (execution.completed_at - execution.started_at).total_seconds() if execution.completed_at else None,
            "action_results": execution.action_results,
            "context": execution.context,
            "logs": [
                {
                    "timestamp": log["timestamp"],
                    "level": log["level"],
                    "message": log["message"],
                    "action_id": log.get("action_id")
                } for log in execution.logs
            ]
        }
    
    async def approve_action(self, approval_id: str, approved: bool, reason: str = "") -> bool:
        """Approve or deny a pending action"""
        for req in self.approval_queue:
            if req['id'] == approval_id and req['status'] == 'pending':
                req['status'] = 'approved' if approved else 'denied'
                req['reason'] = reason
                req['approved_at'] = datetime.now()
                return True
        return False
    
    async def get_pending_approvals(self) -> List[Dict[str, Any]]:
        """Get all pending approval requests"""
        return [req for req in self.approval_queue if req['status'] == 'pending']
    
    async def get_metrics(self) -> Dict[str, Any]:
        """Get SOAR platform metrics"""
        total_playbooks = len(self.playbooks)
        active_playbooks = len([p for p in self.playbooks.values() if p.status == PlaybookStatus.ACTIVE])
        total_executions = len(self.executions)
        
        # Execution status counts
        execution_status_counts = {}
        for execution in self.executions.values():
            status = execution.status.value
            execution_status_counts[status] = execution_status_counts.get(status, 0) + 1
        
        # Success rate calculation
        completed_executions = [e for e in self.executions.values() if e.status == ExecutionStatus.COMPLETED]
        success_rate = len(completed_executions) / total_executions if total_executions > 0 else 0
        
        # Recent activity (last 24 hours)
        cutoff = datetime.now() - timedelta(hours=24)
        recent_executions = [e for e in self.executions.values() if e.started_at > cutoff]
        
        return {
            "total_playbooks": total_playbooks,
            "active_playbooks": active_playbooks,
            "total_executions": total_executions,
            "execution_status_counts": execution_status_counts,
            "success_rate": success_rate,
            "recent_executions": len(recent_executions),
            "pending_approvals": len([req for req in self.approval_queue if req['status'] == 'pending']),
            "platform_uptime": self._get_uptime()
        }
    
    def _get_uptime(self) -> str:
        """Get platform uptime"""
        # Simple uptime calculation - would be more sophisticated in production
        return "24h 15m"

# Global SOAR platform instance
soar_platform = SOARPlatform()

# Initialize default playbooks
async def initialize_default_playbooks():
    """Initialize default security playbooks"""
    
    # Critical Incident Response Playbook
    critical_incident_playbook = {
        "id": "critical_incident_response",
        "name": "Critical Incident Response",
        "description": "Automated response to critical security incidents",
        "version": "1.0",
        "trigger_conditions": {
            "severity": {"operator": "equals", "value": "critical"},
            "confidence": {"operator": "greater_than", "value": 0.8}
        },
        "actions": [
            {
                "id": "isolate_affected_hosts",
                "name": "Isolate Affected Hosts",
                "action_type": "isolate_host",
                "parameters": {
                    "host": "{affected_host}"
                },
                "timeout_seconds": 120,
                "requires_approval": False
            },
            {
                "id": "block_malicious_ips",
                "name": "Block Malicious IPs",
                "action_type": "block_ip",
                "parameters": {
                    "ip_address": "{source_ip}",
                    "duration": 3600
                },
                "timeout_seconds": 60,
                "requires_approval": False
            },
            {
                "id": "send_critical_alert",
                "name": "Send Critical Alert",
                "action_type": "send_alert",
                "parameters": {
                    "recipients": ["security-team@company.com", "soc@company.com"],
                    "subject": "CRITICAL: Security Incident Detected",
                    "message": "Critical security incident detected: {incident_description}"
                },
                "timeout_seconds": 30,
                "requires_approval": False
            },
            {
                "id": "collect_forensic_evidence",
                "name": "Collect Forensic Evidence",
                "action_type": "collect_evidence",
                "parameters": {
                    "target": "{affected_host}",
                    "evidence_types": ["memory_dump", "disk_image", "network_logs"]
                },
                "timeout_seconds": 1800,
                "requires_approval": True,
                "depends_on": ["isolate_affected_hosts"]
            },
            {
                "id": "create_incident_ticket",
                "name": "Create Incident Ticket",
                "action_type": "create_ticket",
                "parameters": {
                    "title": "Critical Security Incident: {incident_type}",
                    "description": "{incident_description}",
                    "priority": "critical"
                },
                "timeout_seconds": 60,
                "requires_approval": False
            }
        ],
        "tags": ["critical", "incident_response", "automated"]
    }
    
    # Malware Detection Response Playbook
    malware_response_playbook = {
        "id": "malware_response",
        "name": "Malware Detection Response",
        "description": "Automated response to malware detection",
        "version": "1.0",
        "trigger_conditions": {
            "threat_type": {"operator": "equals", "value": "malware"},
            "action_required": {"operator": "equals", "value": True}
        },
        "actions": [
            {
                "id": "quarantine_malware",
                "name": "Quarantine Malicious File",
                "action_type": "quarantine_file",
                "parameters": {
                    "file_path": "{file_path}",
                    "file_hash": "{file_hash}"
                },
                "timeout_seconds": 60,
                "requires_approval": False
            },
            {
                "id": "isolate_infected_host",
                "name": "Isolate Infected Host",
                "action_type": "isolate_host",
                "parameters": {
                    "host": "{infected_host}"
                },
                "timeout_seconds": 120,
                "requires_approval": False
            },
            {
                "id": "update_threat_signatures",
                "name": "Update Threat Intelligence",
                "action_type": "update_threat_intel",
                "parameters": {
                    "indicators": ["{file_hash}", "{domain}", "{ip_address}"],
                    "source": "malware_analysis"
                },
                "timeout_seconds": 300,
                "requires_approval": False,
                "depends_on": ["quarantine_malware"]
            },
            {
                "id": "scan_network_for_malware",
                "name": "Network-wide Malware Scan",
                "action_type": "run_scan",
                "parameters": {
                    "scan_type": "malware",
                    "targets": ["all_endpoints"]
                },
                "timeout_seconds": 3600,
                "requires_approval": True,
                "depends_on": ["update_threat_signatures"]
            }
        ],
        "tags": ["malware", "automated", "endpoint_security"]
    }
    
    # Data Breach Response Playbook
    data_breach_playbook = {
        "id": "data_breach_response",
        "name": "Data Breach Response",
        "description": "Response to potential data breach incidents",
        "version": "1.0",
        "trigger_conditions": {
            "incident_type": {"operator": "equals", "value": "data_breach"},
            "severity": {"operator": "in", "value": ["high", "critical"]}
        },
        "actions": [
            {
                "id": "immediate_containment",
                "name": "Immediate Containment",
                "action_type": "isolate_host",
                "parameters": {
                    "host": "{breach_source}"
                },
                "timeout_seconds": 120,
                "requires_approval": False
            },
            {
                "id": "collect_breach_evidence",
                "name": "Collect Breach Evidence",
                "action_type": "collect_evidence",
                "parameters": {
                    "target": "{breach_source}",
                    "evidence_types": ["access_logs", "file_access", "network_traffic"]
                },
                "timeout_seconds": 1800,
                "requires_approval": False,
                "depends_on": ["immediate_containment"]
            },
            {
                "id": "reset_compromised_accounts",
                "name": "Reset Compromised Accounts",
                "action_type": "reset_password",
                "parameters": {
                    "username": "{compromised_users}"
                },
                "timeout_seconds": 300,
                "requires_approval": True,
                "depends_on": ["immediate_containment"]
            },
            {
                "id": "notify_legal_team",
                "name": "Notify Legal and Compliance",
                "action_type": "send_alert",
                "parameters": {
                    "recipients": ["legal@company.com", "compliance@company.com"],
                    "subject": "Data Breach Incident - Legal Review Required",
                    "message": "Potential data breach detected requiring legal review: {incident_description}"
                },
                "timeout_seconds": 60,
                "requires_approval": False
            },
            {
                "id": "create_breach_ticket",
                "name": "Create Data Breach Ticket",
                "action_type": "create_ticket",
                "parameters": {
                    "title": "Data Breach Incident: {affected_data_types}",
                    "description": "{incident_description}",
                    "priority": "critical"
                },
                "timeout_seconds": 60,
                "requires_approval": False
            }
        ],
        "tags": ["data_breach", "compliance", "privacy"]
    }
    
    # Create playbooks
    await soar_platform.create_playbook(critical_incident_playbook)
    await soar_platform.create_playbook(malware_response_playbook)
    await soar_platform.create_playbook(data_breach_playbook)
    
    # Activate playbooks
    for playbook_id in ["critical_incident_response", "malware_response", "data_breach_response"]:
        if playbook_id in soar_platform.playbooks:
            soar_platform.playbooks[playbook_id].status = PlaybookStatus.ACTIVE
    
    async def approve_action(self, approval_id: str, approved: bool, reason: str = "") -> bool:
        """Approve or deny a pending action"""
        for req in self.approval_queue:
            if req['id'] == approval_id:
                req['status'] = 'approved' if approved else 'denied'
                req['reason'] = reason
                req['approved_at'] = datetime.now()
                return True
        return False
    
    async def get_pending_approvals(self) -> List[Dict[str, Any]]:
        """Get all pending approval requests"""
        return [req for req in self.approval_queue if req['status'] == 'pending']
    
    async def cancel_execution(self, execution_id: str) -> bool:
        """Cancel a running playbook execution"""
        if execution_id in self.executions:
            execution = self.executions[execution_id]
            if execution.status == ExecutionStatus.RUNNING:
                execution.status = ExecutionStatus.FAILED
                execution.completed_at = datetime.now()
                execution.add_log("INFO", "Execution cancelled by user")
                return True
        return False
    
    async def get_soar_metrics(self) -> Dict[str, Any]:
        """Get SOAR platform metrics"""
        total_playbooks = len(self.playbooks)
        active_playbooks = len([p for p in self.playbooks.values() if p.status == PlaybookStatus.ACTIVE])
        total_executions = len(self.executions)
        running_executions = len([e for e in self.executions.values() if e.status == ExecutionStatus.RUNNING])
        successful_executions = len([e for e in self.executions.values() if e.status == ExecutionStatus.COMPLETED])
        
        # Calculate success rate
        success_rate = successful_executions / total_executions if total_executions > 0 else 0
        
        # Calculate average execution time
        completed_executions = [e for e in self.executions.values() if e.status == ExecutionStatus.COMPLETED and e.completed_at]
        avg_execution_time = 0
        if completed_executions:
            total_time = sum((e.completed_at - e.started_at).total_seconds() for e in completed_executions)
            avg_execution_time = total_time / len(completed_executions)
        
        return {
            "total_playbooks": total_playbooks,
            "active_playbooks": active_playbooks,
            "total_executions": total_executions,
            "running_executions": running_executions,
            "successful_executions": successful_executions,
            "failed_executions": len([e for e in self.executions.values() if e.status == ExecutionStatus.FAILED]),
            "success_rate": success_rate,
            "avg_execution_time_seconds": avg_execution_time,
            "pending_approvals": len([req for req in self.approval_queue if req['status'] == 'pending']),
            "system_health": 0.95 if running_executions < self.config['max_concurrent_executions'] else 0.7
        }

# Initialize global SOAR platform
soar_platform = SOARPlatform()