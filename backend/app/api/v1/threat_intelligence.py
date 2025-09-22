"""
Advanced Threat Intelligence API endpoints
Provides comprehensive IOC management, threat actor profiling, and intelligence feeds
"""

from fastapi import APIRouter, Depends, HTTPException, Query, BackgroundTasks
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, desc, func
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
import uuid
import ipaddress
import re
import hashlib
from urllib.parse import urlparse

from app.db.database import get_db
from app.db.models import (
    IOC, ThreatActor, ThreatCampaign, IOCDetection, 
    ThreatIntelFeed, ThreatIntelReport,
    IOCType, ThreatActorType, ThreatLevel
)
from app.core.auth import get_current_user

router = APIRouter(prefix="/threat-intelligence", tags=["threat-intelligence"])

# ============================================================================
# IOC MANAGEMENT ENDPOINTS
# ============================================================================

@router.get("/iocs")
async def get_iocs(
    db: Session = Depends(get_db),
    limit: int = Query(100, le=1000),
    offset: int = Query(0, ge=0),
    ioc_type: Optional[str] = Query(None),
    threat_level: Optional[str] = Query(None),
    is_active: Optional[bool] = Query(None),
    search: Optional[str] = Query(None)
):
    """Get IOCs with filtering and pagination"""
    query = db.query(IOC)
    
    # Apply filters
    if ioc_type:
        query = query.filter(IOC.type == ioc_type)
    if threat_level:
        query = query.filter(IOC.threat_level == threat_level)
    if is_active is not None:
        query = query.filter(IOC.is_active == is_active)
    if search:
        query = query.filter(
            or_(
                IOC.value.ilike(f"%{search}%"),
                IOC.description.ilike(f"%{search}%")
            )
        )
    
    # Get total count
    total = query.count()
    
    # Apply pagination and ordering
    iocs = query.order_by(desc(IOC.created_at)).offset(offset).limit(limit).all()
    
    return {
        "iocs": [
            {
                "ioc_id": ioc.ioc_id,
                "type": ioc.type.value if ioc.type else None,
                "value": ioc.value,
                "description": ioc.description,
                "threat_level": ioc.threat_level.value if ioc.threat_level else None,
                "confidence": ioc.confidence,
                "source": ioc.source,
                "tags": ioc.tags,
                "first_seen": ioc.first_seen.isoformat() if ioc.first_seen else None,
                "last_seen": ioc.last_seen.isoformat() if ioc.last_seen else None,
                "detection_count": ioc.detection_count,
                "is_active": ioc.is_active,
                "threat_actor": ioc.threat_actor.name if ioc.threat_actor else None,
                "campaign": ioc.campaign.name if ioc.campaign else None,
                "created_at": ioc.created_at.isoformat()
            }
            for ioc in iocs
        ],
        "total": total,
        "limit": limit,
        "offset": offset
    }

@router.post("/iocs")
async def create_ioc(
    ioc_data: Dict[str, Any],
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Create a new IOC"""
    
    # Validate IOC type and value
    ioc_type = ioc_data.get("type")
    ioc_value = ioc_data.get("value")
    
    if not ioc_type or not ioc_value:
        raise HTTPException(status_code=400, detail="IOC type and value are required")
    
    # Validate IOC format
    validation_result = await validate_ioc_format(ioc_type, ioc_value)
    if not validation_result["valid"]:
        raise HTTPException(status_code=400, detail=validation_result["error"])
    
    # Check for duplicates
    existing_ioc = db.query(IOC).filter(
        and_(IOC.type == ioc_type, IOC.value == ioc_value)
    ).first()
    
    if existing_ioc:
        raise HTTPException(status_code=409, detail="IOC already exists")
    
    # Create new IOC
    new_ioc = IOC(
        ioc_id=str(uuid.uuid4()),
        type=IOCType(ioc_type),
        value=ioc_value,
        description=ioc_data.get("description"),
        threat_level=ThreatLevel(ioc_data.get("threat_level", "medium")),
        confidence=ioc_data.get("confidence", 50),
        source=ioc_data.get("source", "manual"),
        source_url=ioc_data.get("source_url"),
        tags=ioc_data.get("tags", []),
        first_seen=datetime.fromisoformat(ioc_data["first_seen"]) if ioc_data.get("first_seen") else datetime.utcnow(),
        last_seen=datetime.fromisoformat(ioc_data["last_seen"]) if ioc_data.get("last_seen") else None
    )
    
    db.add(new_ioc)
    db.commit()
    db.refresh(new_ioc)
    
    return {
        "message": "IOC created successfully",
        "ioc_id": new_ioc.ioc_id,
        "created_at": new_ioc.created_at.isoformat()
    }

@router.get("/iocs/{ioc_id}")
async def get_ioc_details(
    ioc_id: str,
    db: Session = Depends(get_db)
):
    """Get detailed information about a specific IOC"""
    
    ioc = db.query(IOC).filter(IOC.ioc_id == ioc_id).first()
    if not ioc:
        raise HTTPException(status_code=404, detail="IOC not found")
    
    # Get recent detections
    recent_detections = db.query(IOCDetection).filter(
        IOCDetection.ioc_id == ioc.id
    ).order_by(desc(IOCDetection.detected_at)).limit(10).all()
    
    return {
        "ioc_id": ioc.ioc_id,
        "type": ioc.type.value,
        "value": ioc.value,
        "description": ioc.description,
        "threat_level": ioc.threat_level.value,
        "confidence": ioc.confidence,
        "source": ioc.source,
        "source_url": ioc.source_url,
        "tags": ioc.tags,
        "first_seen": ioc.first_seen.isoformat() if ioc.first_seen else None,
        "last_seen": ioc.last_seen.isoformat() if ioc.last_seen else None,
        "valid_from": ioc.valid_from.isoformat(),
        "valid_until": ioc.valid_until.isoformat() if ioc.valid_until else None,
        "is_active": ioc.is_active,
        "is_whitelist": ioc.is_whitelist,
        "detection_count": ioc.detection_count,
        "last_detection": ioc.last_detection.isoformat() if ioc.last_detection else None,
        "threat_actor": {
            "name": ioc.threat_actor.name,
            "actor_type": ioc.threat_actor.actor_type.value,
            "country": ioc.threat_actor.country
        } if ioc.threat_actor else None,
        "campaign": {
            "name": ioc.campaign.name,
            "description": ioc.campaign.description,
            "is_active": ioc.campaign.is_active
        } if ioc.campaign else None,
        "recent_detections": [
            {
                "detection_id": detection.detection_id,
                "source_system": detection.source_system,
                "detected_at": detection.detected_at.isoformat(),
                "risk_score": detection.risk_score,
                "action_taken": detection.action_taken,
                "is_false_positive": detection.is_false_positive
            }
            for detection in recent_detections
        ],
        "created_at": ioc.created_at.isoformat(),
        "updated_at": ioc.updated_at.isoformat() if ioc.updated_at else None
    }

@router.put("/iocs/{ioc_id}")
async def update_ioc(
    ioc_id: str,
    ioc_data: Dict[str, Any],
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Update an existing IOC"""
    
    ioc = db.query(IOC).filter(IOC.ioc_id == ioc_id).first()
    if not ioc:
        raise HTTPException(status_code=404, detail="IOC not found")
    
    # Update fields
    if "description" in ioc_data:
        ioc.description = ioc_data["description"]
    if "threat_level" in ioc_data:
        ioc.threat_level = ThreatLevel(ioc_data["threat_level"])
    if "confidence" in ioc_data:
        ioc.confidence = ioc_data["confidence"]
    if "tags" in ioc_data:
        ioc.tags = ioc_data["tags"]
    if "is_active" in ioc_data:
        ioc.is_active = ioc_data["is_active"]
    if "is_whitelist" in ioc_data:
        ioc.is_whitelist = ioc_data["is_whitelist"]
    
    ioc.updated_at = datetime.utcnow()
    db.commit()
    
    return {"message": "IOC updated successfully"}

@router.post("/iocs/search")
async def search_iocs(
    search_data: Dict[str, Any],
    db: Session = Depends(get_db)
):
    """Advanced IOC search with multiple criteria"""
    
    query = db.query(IOC)
    
    # Multi-field search
    if search_data.get("values"):
        values = search_data["values"]
        query = query.filter(IOC.value.in_(values))
    
    if search_data.get("types"):
        types = search_data["types"]
        query = query.filter(IOC.type.in_(types))
    
    if search_data.get("threat_levels"):
        levels = search_data["threat_levels"]
        query = query.filter(IOC.threat_level.in_(levels))
    
    if search_data.get("tags"):
        tags = search_data["tags"]
        for tag in tags:
            query = query.filter(func.json_contains(IOC.tags, f'"{tag}"'))
    
    if search_data.get("date_range"):
        start_date = datetime.fromisoformat(search_data["date_range"]["start"])
        end_date = datetime.fromisoformat(search_data["date_range"]["end"])
        query = query.filter(IOC.created_at.between(start_date, end_date))
    
    results = query.limit(1000).all()
    
    return {
        "results": [
            {
                "ioc_id": ioc.ioc_id,
                "type": ioc.type.value,
                "value": ioc.value,
                "threat_level": ioc.threat_level.value,
                "confidence": ioc.confidence,
                "detection_count": ioc.detection_count,
                "is_active": ioc.is_active,
                "created_at": ioc.created_at.isoformat()
            }
            for ioc in results
        ],
        "total_found": len(results)
    }

# ============================================================================
# THREAT ACTOR ENDPOINTS
# ============================================================================

@router.get("/threat-actors")
async def get_threat_actors(
    db: Session = Depends(get_db),
    limit: int = Query(50, le=500),
    offset: int = Query(0, ge=0),
    actor_type: Optional[str] = Query(None),
    is_active: Optional[bool] = Query(None),
    search: Optional[str] = Query(None)
):
    """Get threat actors with filtering"""
    
    query = db.query(ThreatActor)
    
    if actor_type:
        query = query.filter(ThreatActor.actor_type == actor_type)
    if is_active is not None:
        query = query.filter(ThreatActor.is_active == is_active)
    if search:
        query = query.filter(
            or_(
                ThreatActor.name.ilike(f"%{search}%"),
                ThreatActor.description.ilike(f"%{search}%")
            )
        )
    
    total = query.count()
    actors = query.order_by(desc(ThreatActor.last_seen)).offset(offset).limit(limit).all()
    
    return {
        "threat_actors": [
            {
                "actor_id": actor.actor_id,
                "name": actor.name,
                "aliases": actor.aliases,
                "actor_type": actor.actor_type.value,
                "sophistication": actor.sophistication,
                "country": actor.country,
                "motivation": actor.motivation,
                "is_active": actor.is_active,
                "first_seen": actor.first_seen.isoformat() if actor.first_seen else None,
                "last_seen": actor.last_seen.isoformat() if actor.last_seen else None,
                "ioc_count": len(actor.iocs),
                "campaign_count": len(actor.campaigns),
                "created_at": actor.created_at.isoformat()
            }
            for actor in actors
        ],
        "total": total,
        "limit": limit,
        "offset": offset
    }

@router.post("/threat-actors")
async def create_threat_actor(
    actor_data: Dict[str, Any],
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Create a new threat actor profile"""
    
    # Check for duplicate name
    existing_actor = db.query(ThreatActor).filter(
        ThreatActor.name == actor_data.get("name")
    ).first()
    
    if existing_actor:
        raise HTTPException(status_code=409, detail="Threat actor with this name already exists")
    
    new_actor = ThreatActor(
        actor_id=str(uuid.uuid4()),
        name=actor_data["name"],
        aliases=actor_data.get("aliases", []),
        description=actor_data.get("description"),
        actor_type=ThreatActorType(actor_data["actor_type"]),
        sophistication=actor_data.get("sophistication"),
        country=actor_data.get("country"),
        region=actor_data.get("region"),
        motivation=actor_data.get("motivation", []),
        targets=actor_data.get("targets", []),
        ttps=actor_data.get("ttps", []),
        tools=actor_data.get("tools", []),
        first_seen=datetime.fromisoformat(actor_data["first_seen"]) if actor_data.get("first_seen") else datetime.utcnow()
    )
    
    db.add(new_actor)
    db.commit()
    db.refresh(new_actor)
    
    return {
        "message": "Threat actor created successfully",
        "actor_id": new_actor.actor_id,
        "created_at": new_actor.created_at.isoformat()
    }

# ============================================================================
# DETECTION ENDPOINTS
# ============================================================================

@router.post("/detections")
async def create_ioc_detection(
    detection_data: Dict[str, Any],
    db: Session = Depends(get_db)
):
    """Record an IOC detection event"""
    
    # Find the IOC
    ioc = db.query(IOC).filter(IOC.value == detection_data["ioc_value"]).first()
    if not ioc:
        # Auto-create IOC if it doesn't exist
        ioc = IOC(
            ioc_id=str(uuid.uuid4()),
            type=IOCType(detection_data.get("ioc_type", "ip")),
            value=detection_data["ioc_value"],
            threat_level=ThreatLevel.MEDIUM,
            confidence=50,
            source="auto_detection",
            first_seen=datetime.utcnow()
        )
        db.add(ioc)
        db.flush()
    
    # Create detection record
    detection = IOCDetection(
        detection_id=str(uuid.uuid4()),
        ioc_id=ioc.id,
        source_system=detection_data["source_system"],
        detection_method=detection_data.get("detection_method"),
        asset_affected=detection_data.get("asset_affected"),
        user_affected=detection_data.get("user_affected"),
        event_data=detection_data.get("event_data"),
        risk_score=detection_data.get("risk_score", 50),
        action_taken=detection_data.get("action_taken"),
        detected_at=datetime.fromisoformat(detection_data["detected_at"]) if detection_data.get("detected_at") else datetime.utcnow()
    )
    
    # Update IOC statistics
    ioc.detection_count += 1
    ioc.last_detection = detection.detected_at
    ioc.last_seen = detection.detected_at
    
    db.add(detection)
    db.commit()
    
    return {
        "message": "Detection recorded successfully",
        "detection_id": detection.detection_id,
        "ioc_id": ioc.ioc_id
    }

# ============================================================================
# ANALYTICS ENDPOINTS
# ============================================================================

@router.get("/analytics/summary")
async def get_threat_intelligence_summary(db: Session = Depends(get_db)):
    """Get threat intelligence platform summary statistics"""
    
    # IOC statistics
    total_iocs = db.query(IOC).count()
    active_iocs = db.query(IOC).filter(IOC.is_active == True).count()
    
    # IOCs by type
    ioc_by_type = db.query(IOC.type, func.count(IOC.id)).group_by(IOC.type).all()
    
    # IOCs by threat level
    ioc_by_threat_level = db.query(IOC.threat_level, func.count(IOC.id)).group_by(IOC.threat_level).all()
    
    # Recent detections (last 24 hours)
    recent_detections = db.query(IOCDetection).filter(
        IOCDetection.detected_at >= datetime.utcnow() - timedelta(hours=24)
    ).count()
    
    # Threat actors
    total_actors = db.query(ThreatActor).count()
    active_actors = db.query(ThreatActor).filter(ThreatActor.is_active == True).count()
    
    # Campaigns
    total_campaigns = db.query(ThreatCampaign).count()
    active_campaigns = db.query(ThreatCampaign).filter(ThreatCampaign.is_active == True).count()
    
    return {
        "iocs": {
            "total": total_iocs,
            "active": active_iocs,
            "by_type": {ioc_type.value: count for ioc_type, count in ioc_by_type},
            "by_threat_level": {level.value: count for level, count in ioc_by_threat_level}
        },
        "detections": {
            "last_24h": recent_detections
        },
        "threat_actors": {
            "total": total_actors,
            "active": active_actors
        },
        "campaigns": {
            "total": total_campaigns,
            "active": active_campaigns
        }
    }

@router.get("/analytics/trends")
async def get_threat_trends(
    days: int = Query(30, ge=1, le=365),
    db: Session = Depends(get_db)
):
    """Get threat intelligence trends over time"""
    
    start_date = datetime.utcnow() - timedelta(days=days)
    
    # IOC creation trends
    ioc_trends = db.query(
        func.date(IOC.created_at).label('date'),
        func.count(IOC.id).label('count')
    ).filter(
        IOC.created_at >= start_date
    ).group_by(
        func.date(IOC.created_at)
    ).order_by('date').all()
    
    # Detection trends
    detection_trends = db.query(
        func.date(IOCDetection.detected_at).label('date'),
        func.count(IOCDetection.id).label('count')
    ).filter(
        IOCDetection.detected_at >= start_date
    ).group_by(
        func.date(IOCDetection.detected_at)
    ).order_by('date').all()
    
    return {
        "period_days": days,
        "ioc_creation_trends": [
            {"date": trend.date.isoformat(), "count": trend.count}
            for trend in ioc_trends
        ],
        "detection_trends": [
            {"date": trend.date.isoformat(), "count": trend.count}
            for trend in detection_trends
        ]
    }

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

async def validate_ioc_format(ioc_type: str, value: str) -> Dict[str, Any]:
    """Validate IOC format based on type"""
    
    if ioc_type == "ip":
        try:
            ipaddress.ip_address(value)
            return {"valid": True}
        except ValueError:
            return {"valid": False, "error": "Invalid IP address format"}
    
    elif ioc_type == "domain":
        domain_pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        if re.match(domain_pattern, value):
            return {"valid": True}
        return {"valid": False, "error": "Invalid domain format"}
    
    elif ioc_type == "url":
        try:
            result = urlparse(value)
            if result.scheme and result.netloc:
                return {"valid": True}
            return {"valid": False, "error": "Invalid URL format"}
        except:
            return {"valid": False, "error": "Invalid URL format"}
    
    elif ioc_type == "email":
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if re.match(email_pattern, value):
            return {"valid": True}
        return {"valid": False, "error": "Invalid email format"}
    
    elif ioc_type == "file_hash":
        # Support MD5, SHA1, SHA256, SHA512
        if len(value) in [32, 40, 64, 128] and re.match(r'^[a-fA-F0-9]+$', value):
            return {"valid": True}
        return {"valid": False, "error": "Invalid hash format"}
    
    # For other types, assume valid for now
    return {"valid": True}