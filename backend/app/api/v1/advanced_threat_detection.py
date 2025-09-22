"""
Advanced Threat Detection API Endpoints
Real-time threat analysis and monitoring
"""

import logging
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from pydantic import BaseModel

from app.db.database import get_db
from app.services.advanced_threat_detection import (
    advanced_threat_detector,
    ThreatEvent,
    ThreatLevel,
    ThreatCategory
)

logger = logging.getLogger(__name__)
router = APIRouter()

class ThreatAnalysisRequest(BaseModel):
    source_ip: str
    target: str
    url: Optional[str] = ""
    payload: Optional[str] = ""
    user_agent: Optional[str] = ""
    user_id: Optional[str] = None
    method: Optional[str] = "GET"
    response_code: Optional[int] = 200
    response_size: Optional[int] = 0
    request_duration: Optional[float] = 0.0
    metadata: Optional[Dict[str, Any]] = {}

class ThreatEventResponse(BaseModel):
    event_id: str
    timestamp: str
    source_ip: str
    target: str
    category: str
    level: str
    confidence: float
    description: str
    mitigation: List[str]
    indicators: List[Dict[str, Any]]

class ThreatSummaryResponse(BaseModel):
    total_threats: int
    threats_by_category: Dict[str, int]
    threats_by_level: Dict[str, int]
    avg_confidence: float
    latest_threats: List[Dict[str, Any]]

@router.post("/analyze", response_model=Optional[ThreatEventResponse])
async def analyze_threat(
    request: ThreatAnalysisRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """Analyze potential security threat"""
    try:
        # Convert request to event data
        event_data = {
            "source_ip": request.source_ip,
            "target": request.target,
            "url": request.url,
            "payload": request.payload,
            "user_agent": request.user_agent,
            "user_id": request.user_id,
            "method": request.method,
            "response_code": request.response_code,
            "response_size": request.response_size,
            "request_duration": request.request_duration,
            **request.metadata
        }
        
        # Analyze for threats
        threat_event = await advanced_threat_detector.analyze_event(event_data)
        
        if threat_event:
            # Update behavioral profiles in background
            if request.user_id:
                background_tasks.add_task(
                    update_user_profile_task,
                    request.user_id,
                    event_data
                )
            
            # Convert to response format
            return ThreatEventResponse(
                event_id=threat_event.event_id,
                timestamp=threat_event.timestamp.isoformat(),
                source_ip=threat_event.source_ip,
                target=threat_event.target,
                category=threat_event.category.value,
                level=threat_event.level.value,
                confidence=threat_event.confidence,
                description=threat_event.description,
                mitigation=threat_event.mitigation,
                indicators=[
                    {
                        "type": ind.indicator_type,
                        "value": ind.value,
                        "confidence": ind.confidence,
                        "metadata": ind.metadata
                    }
                    for ind in threat_event.indicators
                ]
            )
        
        return None
        
    except Exception as e:
        logger.error(f"Threat analysis error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/summary", response_model=ThreatSummaryResponse)
async def get_threat_summary(
    hours: int = 24,
    db: Session = Depends(get_db)
):
    """Get threat detection summary"""
    try:
        time_window = timedelta(hours=hours)
        summary = await advanced_threat_detector.get_threat_summary(time_window)
        
        return ThreatSummaryResponse(**summary)
        
    except Exception as e:
        logger.error(f"Threat summary error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/events")
async def get_threat_events(
    limit: int = 100,
    category: Optional[str] = None,
    level: Optional[str] = None,
    hours: int = 24,
    db: Session = Depends(get_db)
):
    """Get threat events with filtering"""
    try:
        cutoff = datetime.now() - timedelta(hours=hours)
        threats = [
            t for t in advanced_threat_detector.detected_threats
            if t.timestamp > cutoff
        ]
        
        # Apply filters
        if category:
            threats = [t for t in threats if t.category.value == category]
        
        if level:
            threats = [t for t in threats if t.level.value == level]
        
        # Sort by timestamp and limit
        threats = sorted(threats, key=lambda x: x.timestamp, reverse=True)[:limit]
        
        return [
            {
                "event_id": t.event_id,
                "timestamp": t.timestamp.isoformat(),
                "source_ip": t.source_ip,
                "target": t.target,
                "category": t.category.value,
                "level": t.level.value,
                "confidence": t.confidence,
                "description": t.description,
                "mitigation": t.mitigation,
                "indicators_count": len(t.indicators)
            }
            for t in threats
        ]
        
    except Exception as e:
        logger.error(f"Get threat events error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/events/{event_id}")
async def get_threat_event_details(
    event_id: str,
    db: Session = Depends(get_db)
):
    """Get detailed threat event information"""
    try:
        threat = next(
            (t for t in advanced_threat_detector.detected_threats if t.event_id == event_id),
            None
        )
        
        if not threat:
            raise HTTPException(status_code=404, detail="Threat event not found")
        
        return {
            "event_id": threat.event_id,
            "timestamp": threat.timestamp.isoformat(),
            "source_ip": threat.source_ip,
            "target": threat.target,
            "category": threat.category.value,
            "level": threat.level.value,
            "confidence": threat.confidence,
            "description": threat.description,
            "mitigation": threat.mitigation,
            "indicators": [
                {
                    "type": ind.indicator_type,
                    "value": ind.value,
                    "confidence": ind.confidence,
                    "first_seen": ind.first_seen.isoformat(),
                    "last_seen": ind.last_seen.isoformat(),
                    "count": ind.count,
                    "metadata": ind.metadata
                }
                for ind in threat.indicators
            ],
            "raw_data": threat.raw_data
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get threat event details error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/train")
async def train_ml_models(
    normal_events: List[Dict[str, Any]],
    db: Session = Depends(get_db)
):
    """Train ML models on normal/baseline events"""
    try:
        if len(normal_events) < 10:
            raise HTTPException(
                status_code=400,
                detail="At least 10 normal events required for training"
            )
        
        # Train the ML detector
        advanced_threat_detector.ml_detector.train_baseline(normal_events)
        
        return {
            "success": True,
            "message": f"Trained ML models on {len(normal_events)} normal events",
            "models_trained": advanced_threat_detector.ml_detector.models_trained
        }
        
    except Exception as e:
        logger.error(f"ML training error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/stats")
async def get_detection_stats(db: Session = Depends(get_db)):
    """Get threat detection statistics"""
    try:
        total_threats = len(advanced_threat_detector.detected_threats)
        
        if total_threats == 0:
            return {
                "total_threats": 0,
                "models_trained": advanced_threat_detector.ml_detector.models_trained,
                "categories": {},
                "levels": {},
                "recent_activity": []
            }
        
        # Category distribution
        categories = {}
        levels = {}
        
        for threat in advanced_threat_detector.detected_threats:
            cat = threat.category.value
            level = threat.level.value
            categories[cat] = categories.get(cat, 0) + 1
            levels[level] = levels.get(level, 0) + 1
        
        # Recent activity (last 24 hours)
        cutoff = datetime.now() - timedelta(hours=24)
        recent_threats = [
            t for t in advanced_threat_detector.detected_threats
            if t.timestamp > cutoff
        ]
        
        return {
            "total_threats": total_threats,
            "models_trained": advanced_threat_detector.ml_detector.models_trained,
            "categories": categories,
            "levels": levels,
            "recent_activity": len(recent_threats),
            "avg_confidence": sum(t.confidence for t in recent_threats) / len(recent_threats) if recent_threats else 0
        }
        
    except Exception as e:
        logger.error(f"Get detection stats error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/simulate")
async def simulate_threat(
    threat_type: str = "sql_injection",
    db: Session = Depends(get_db)
):
    """Simulate threat for testing (development only)"""
    try:
        # Sample threat simulations
        simulations = {
            "sql_injection": {
                "source_ip": "192.168.1.100",
                "target": "/api/users",
                "url": "/api/users?id=1' UNION SELECT * FROM passwords--",
                "payload": "1' UNION SELECT username,password FROM users--",
                "method": "GET",
                "user_agent": "curl/7.68.0"
            },
            "xss": {
                "source_ip": "10.0.0.50",
                "target": "/search",
                "url": "/search?q=<script>alert('xss')</script>",
                "payload": "<script>alert('xss')</script>",
                "method": "GET",
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
            },
            "command_injection": {
                "source_ip": "172.16.0.25",
                "target": "/execute",
                "url": "/execute",
                "payload": "ls; cat /etc/passwd",
                "method": "POST",
                "user_agent": "python-requests/2.28.0"
            },
            "malicious_ip": {
                "source_ip": "192.168.1.100",  # Known bad IP
                "target": "/admin",
                "url": "/admin/dashboard",
                "payload": "",
                "method": "GET",
                "user_agent": "Nmap NSE"
            }
        }
        
        if threat_type not in simulations:
            raise HTTPException(
                status_code=400,
                detail=f"Unknown threat type. Available: {list(simulations.keys())}"
            )
        
        # Analyze the simulated threat
        threat_event = await advanced_threat_detector.analyze_event(simulations[threat_type])
        
        if threat_event:
            return {
                "success": True,
                "message": f"Simulated {threat_type} threat detected",
                "threat_event": {
                    "event_id": threat_event.event_id,
                    "category": threat_event.category.value,
                    "level": threat_event.level.value,
                    "confidence": threat_event.confidence,
                    "description": threat_event.description
                }
            }
        else:
            return {
                "success": False,
                "message": f"Simulated {threat_type} was not detected as a threat"
            }
        
    except Exception as e:
        logger.error(f"Threat simulation error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

async def update_user_profile_task(user_id: str, activity_data: Dict[str, Any]):
    """Background task to update user behavioral profile"""
    try:
        advanced_threat_detector.behavioral_analyzer.update_user_profile(user_id, activity_data)
        logger.info(f"Updated behavioral profile for user {user_id}")
    except Exception as e:
        logger.error(f"Failed to update user profile: {e}")

@router.get("/health")
async def health_check():
    """Health check for threat detection service"""
    return {
        "status": "healthy",
        "ml_models_trained": advanced_threat_detector.ml_detector.models_trained,
        "total_threats_detected": len(advanced_threat_detector.detected_threats),
        "threat_intelligence_loaded": True,
        "behavioral_analyzer_active": True
    }