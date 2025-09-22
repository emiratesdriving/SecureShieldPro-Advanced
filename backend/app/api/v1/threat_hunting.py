"""
Advanced Threat Hunting API Endpoints
Real-time behavioral analytics and automated incident response
"""

from fastapi import APIRouter, HTTPException, BackgroundTasks, Query
from typing import Dict, Any, List, Optional
import logging
from datetime import datetime, timedelta

from ..services.threat_hunting import (
    AdvancedThreatHunter, 
    ThreatCategory, 
    AlertSeverity,
    HuntingStatus,
    ThreatIndicator,
    ThreatHunt
)

logger = logging.getLogger(__name__)

# Initialize global threat hunter
threat_hunter = AdvancedThreatHunter()

router = APIRouter(prefix="/threat-hunting", tags=["Threat Hunting"])

@router.post("/events/process")
async def process_security_event(
    event: Dict[str, Any],
    background_tasks: BackgroundTasks
) -> Dict[str, Any]:
    """
    Process incoming security event for threat detection
    """
    try:
        # Process event and detect threats
        indicators = await threat_hunter.process_security_event(event)
        
        # Start background analysis for complex patterns
        background_tasks.add_task(analyze_event_patterns, event)
        
        return {
            "status": "processed",
            "event_id": event.get("id", "unknown"),
            "indicators_detected": len(indicators),
            "indicators": [
                {
                    "id": ind.id,
                    "type": ind.type,
                    "confidence": ind.confidence,
                    "severity": ind.severity.value,
                    "category": ind.category.value
                } for ind in indicators
            ]
        }
        
    except Exception as e:
        logger.error(f"Event processing failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Event processing failed: {str(e)}")

async def analyze_event_patterns(event: Dict[str, Any]):
    """Background task for complex event pattern analysis"""
    try:
        # Perform deep analysis
        await threat_hunter.correlation_engine.correlate_events([event])
        logger.info(f"Background analysis completed for event {event.get('id')}")
    except Exception as e:
        logger.error(f"Background analysis failed: {str(e)}")

@router.get("/hunts")
async def get_active_hunts(
    status: Optional[HuntingStatus] = None,
    category: Optional[ThreatCategory] = None,
    limit: int = Query(default=50, le=100)
) -> Dict[str, Any]:
    """
    Get active threat hunts with optional filtering
    """
    try:
        hunts = await threat_hunter.get_active_hunts()
        
        # Apply filters
        if status:
            hunts = [h for h in hunts if h.status == status]
        
        if category:
            hunts = [h for h in hunts if h.category == category]
        
        # Sort by priority and limit results
        hunts.sort(key=lambda x: (x.priority, x.confidence), reverse=True)
        hunts = hunts[:limit]
        
        return {
            "status": "success",
            "total_hunts": len(hunts),
            "hunts": [
                {
                    "id": hunt.id,
                    "name": hunt.name,
                    "category": hunt.category.value,
                    "status": hunt.status.value,
                    "confidence": hunt.confidence,
                    "priority": hunt.priority,
                    "indicators_count": len(hunt.indicators),
                    "created_at": hunt.created_at.isoformat(),
                    "updated_at": hunt.updated_at.isoformat(),
                    "assigned_analyst": hunt.assigned_analyst
                } for hunt in hunts
            ]
        }
        
    except Exception as e:
        logger.error(f"Failed to get hunts: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to get hunts: {str(e)}")

@router.get("/hunts/{hunt_id}")
async def get_hunt_details(hunt_id: str) -> Dict[str, Any]:
    """
    Get detailed information about a specific threat hunt
    """
    try:
        hunt = await threat_hunter.get_hunt_by_id(hunt_id)
        
        if not hunt:
            raise HTTPException(status_code=404, detail="Hunt not found")
        
        return {
            "status": "success",
            "hunt": {
                "id": hunt.id,
                "name": hunt.name,
                "description": hunt.description,
                "category": hunt.category.value,
                "status": hunt.status.value,
                "confidence": hunt.confidence,
                "priority": hunt.priority,
                "created_at": hunt.created_at.isoformat(),
                "updated_at": hunt.updated_at.isoformat(),
                "assigned_analyst": hunt.assigned_analyst,
                "indicators": [
                    {
                        "id": ind.id,
                        "type": ind.type,
                        "value": ind.value,
                        "confidence": ind.confidence,
                        "severity": ind.severity.value,
                        "first_seen": ind.first_seen.isoformat(),
                        "last_seen": ind.last_seen.isoformat(),
                        "occurrences": ind.occurrences
                    } for ind in hunt.indicators
                ],
                "timeline": hunt.timeline,
                "artifacts": hunt.artifacts
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get hunt details: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to get hunt details: {str(e)}")

@router.put("/hunts/{hunt_id}/status")
async def update_hunt_status(
    hunt_id: str,
    status: HuntingStatus,
    analyst: Optional[str] = None
) -> Dict[str, Any]:
    """
    Update threat hunt status and assign analyst
    """
    try:
        success = await threat_hunter.update_hunt_status(hunt_id, status, analyst)
        
        if not success:
            raise HTTPException(status_code=404, detail="Hunt not found")
        
        return {
            "status": "updated",
            "hunt_id": hunt_id,
            "new_status": status.value,
            "assigned_analyst": analyst
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update hunt status: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to update hunt status: {str(e)}")

@router.get("/indicators")
async def get_threat_indicators(
    severity: Optional[AlertSeverity] = None,
    category: Optional[ThreatCategory] = None,
    limit: int = Query(default=100, le=500)
) -> Dict[str, Any]:
    """
    Get threat indicators with optional filtering
    """
    try:
        all_indicators = list(threat_hunter.threat_indicators.values())
        
        # Apply filters
        if severity:
            all_indicators = [i for i in all_indicators if i.severity == severity]
        
        if category:
            all_indicators = [i for i in all_indicators if i.category == category]
        
        # Sort by confidence and limit results
        all_indicators.sort(key=lambda x: (x.confidence, x.last_seen), reverse=True)
        all_indicators = all_indicators[:limit]
        
        return {
            "status": "success",
            "total_indicators": len(all_indicators),
            "indicators": [
                {
                    "id": ind.id,
                    "type": ind.type,
                    "value": ind.value,
                    "confidence": ind.confidence,
                    "severity": ind.severity.value,
                    "category": ind.category.value,
                    "first_seen": ind.first_seen.isoformat(),
                    "last_seen": ind.last_seen.isoformat(),
                    "occurrences": ind.occurrences,
                    "related_indicators": ind.related_indicators
                } for ind in all_indicators
            ]
        }
        
    except Exception as e:
        logger.error(f"Failed to get indicators: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to get indicators: {str(e)}")

@router.get("/metrics")
async def get_threat_hunting_metrics() -> Dict[str, Any]:
    """
    Get threat hunting performance metrics and statistics
    """
    try:
        metrics = await threat_hunter.get_threat_hunting_metrics()
        
        return {
            "status": "success",
            "metrics": metrics
        }
        
    except Exception as e:
        logger.error(f"Failed to get metrics: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to get metrics: {str(e)}")

@router.post("/hunt/create")
async def create_custom_hunt(
    name: str,
    description: str,
    category: ThreatCategory,
    indicators: List[str] = []
) -> Dict[str, Any]:
    """
    Create a custom threat hunt
    """
    try:
        # Create custom hunt
        hunt_id = f"custom_hunt_{datetime.now().timestamp()}"
        
        from ..services.threat_hunting import ThreatHunt
        custom_hunt = ThreatHunt(
            id=hunt_id,
            name=name,
            description=description,
            category=category,
            status=HuntingStatus.ACTIVE,
            confidence=0.5,
            indicators=[],
            anomalies=[],
            timeline=[{
                "timestamp": datetime.now(),
                "event_type": "hunt_created",
                "description": "Custom hunt created"
            }],
            artifacts=[],
            created_at=datetime.now(),
            updated_at=datetime.now(),
            assigned_analyst=None,
            priority=3
        )
        
        threat_hunter.active_hunts[hunt_id] = custom_hunt
        
        return {
            "status": "created",
            "hunt_id": hunt_id,
            "name": name,
            "category": category.value
        }
        
    except Exception as e:
        logger.error(f"Failed to create hunt: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to create hunt: {str(e)}")

@router.get("/analytics/dashboard")
async def get_threat_dashboard_data() -> Dict[str, Any]:
    """
    Get comprehensive threat hunting dashboard data
    """
    try:
        metrics = await threat_hunter.get_threat_hunting_metrics()
        hunts = await threat_hunter.get_active_hunts()
        
        # Calculate time-based metrics
        now = datetime.now()
        last_24h = now - timedelta(hours=24)
        last_week = now - timedelta(days=7)
        
        recent_hunts = [h for h in hunts if h.created_at >= last_24h]
        weekly_hunts = [h for h in hunts if h.created_at >= last_week]
        
        # Threat trends
        threat_trends = {
            "daily_new_hunts": len(recent_hunts),
            "weekly_new_hunts": len(weekly_hunts),
            "avg_hunt_confidence": sum(h.confidence for h in hunts) / len(hunts) if hunts else 0,
            "high_priority_hunts": len([h for h in hunts if h.priority >= 4])
        }
        
        # Top threat categories
        category_stats = {}
        for hunt in hunts:
            category = hunt.category.value
            if category not in category_stats:
                category_stats[category] = {"count": 0, "avg_confidence": 0}
            category_stats[category]["count"] += 1
            category_stats[category]["avg_confidence"] += hunt.confidence
        
        for category in category_stats:
            count = category_stats[category]["count"]
            category_stats[category]["avg_confidence"] /= count
        
        return {
            "status": "success",
            "dashboard": {
                "overview": metrics,
                "trends": threat_trends,
                "category_stats": category_stats,
                "recent_activity": [
                    {
                        "hunt_id": h.id,
                        "name": h.name,
                        "category": h.category.value,
                        "confidence": h.confidence,
                        "created_at": h.created_at.isoformat()
                    } for h in recent_hunts[:10]
                ]
            }
        }
        
    except Exception as e:
        logger.error(f"Failed to get dashboard data: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to get dashboard data: {str(e)}")

@router.post("/simulate/attack")
async def simulate_attack_scenario(
    attack_type: ThreatCategory,
    intensity: str = "medium",  # low, medium, high
    duration_minutes: int = 5
) -> Dict[str, Any]:
    """
    Simulate attack scenarios for testing detection capabilities
    """
    try:
        # Generate simulated events for testing
        simulated_events = await generate_attack_simulation(attack_type, intensity, duration_minutes)
        
        detected_threats = []
        for event in simulated_events:
            indicators = await threat_hunter.process_security_event(event)
            detected_threats.extend(indicators)
        
        return {
            "status": "simulation_completed",
            "attack_type": attack_type.value,
            "intensity": intensity,
            "duration_minutes": duration_minutes,
            "events_generated": len(simulated_events),
            "threats_detected": len(detected_threats),
            "detection_rate": len(detected_threats) / len(simulated_events) if simulated_events else 0,
            "detected_threats": [
                {
                    "id": t.id,
                    "type": t.type,
                    "confidence": t.confidence,
                    "severity": t.severity.value
                } for t in detected_threats[:10]  # Limit output
            ]
        }
        
    except Exception as e:
        logger.error(f"Attack simulation failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Attack simulation failed: {str(e)}")

async def generate_attack_simulation(
    attack_type: ThreatCategory,
    intensity: str,
    duration_minutes: int
) -> List[Dict[str, Any]]:
    """Generate simulated attack events"""
    events = []
    
    # Determine event count based on intensity
    event_counts = {"low": 5, "medium": 15, "high": 30}
    event_count = event_counts.get(intensity, 15)
    
    base_event = {
        "timestamp": datetime.now(),
        "simulation": True,
        "attack_type": attack_type.value
    }
    
    if attack_type == ThreatCategory.LATERAL_MOVEMENT:
        for i in range(event_count):
            events.append({
                **base_event,
                "id": f"sim_lateral_{i}",
                "type": "lateral_movement",
                "source_ip": f"192.168.1.{10 + i}",
                "destination_ip": f"192.168.1.{50 + i}",
                "protocol": "rdp",
                "user": f"user{i % 3}",
                "status": "success" if i % 4 != 0 else "failed"
            })
    
    elif attack_type == ThreatCategory.DATA_EXFILTRATION:
        for i in range(event_count):
            events.append({
                **base_event,
                "id": f"sim_exfil_{i}",
                "type": "data_access",
                "user": f"user{i % 2}",
                "bytes_accessed": 1000000 + (i * 500000),  # Large data access
                "destination": f"external_{i}.com",
                "compression": True
            })
    
    elif attack_type == ThreatCategory.INSIDER_THREAT:
        for i in range(event_count):
            events.append({
                **base_event,
                "id": f"sim_insider_{i}",
                "type": "login",
                "user": "privileged_user",
                "login_count": 3 + i,
                "time_of_day": "02:00",  # Unusual time
                "location": "unusual_location",
                "status": "success"
            })
    
    return events

@router.get("/health")
async def health_check() -> Dict[str, Any]:
    """
    Health check for threat hunting system
    """
    try:
        metrics = await threat_hunter.get_threat_hunting_metrics()
        
        return {
            "status": "healthy",
            "ml_models_loaded": len(threat_hunter.ml_models),
            "detection_rules_active": metrics.get("detection_rules", 0),
            "active_hunts": metrics.get("active_hunts", 0),
            "total_indicators": metrics.get("total_indicators", 0),
            "system_ready": True
        }
        
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        return {
            "status": "unhealthy",
            "error": str(e),
            "system_ready": False
        }