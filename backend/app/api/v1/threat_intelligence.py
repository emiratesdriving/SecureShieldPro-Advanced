"""
Threat Intelligence API endpoints
Provides REST API for threat intelligence operations including IOC management,
threat actor profiling, and threat analysis.
"""

from fastapi import APIRouter, HTTPException, Query, Depends
from typing import List, Dict, Optional, Any
from datetime import datetime
import json
from pydantic import BaseModel, Field

from app.services.threat_intelligence import (
    threat_intel_platform,
    IOCType,
    ThreatLevel, 
    ConfidenceLevel
)

router = APIRouter(prefix="/api/v1/threat-intelligence", tags=["Threat Intelligence"])

# Pydantic Models
class IOCCreate(BaseModel):
    type: str = Field(..., description="IOC type (ip_address, domain, url, file_hash, etc.)")
    value: str = Field(..., description="IOC value")
    threat_level: str = Field(default="medium", description="Threat level")
    confidence: str = Field(default="medium", description="Confidence level")
    description: str = Field(default="", description="IOC description")
    source: str = Field(default="Manual Entry", description="Source of IOC")
    tags: List[str] = Field(default=[], description="Associated tags")
    related_campaigns: List[str] = Field(default=[], description="Related campaign IDs")
    related_actors: List[str] = Field(default=[], description="Related threat actor IDs")
    attributes: Dict[str, Any] = Field(default={}, description="Additional attributes")

class IOCResponse(BaseModel):
    id: str
    type: str
    value: str
    threat_level: str
    confidence: str
    description: str
    source: str
    first_seen: datetime
    last_seen: datetime
    tags: List[str]
    related_campaigns: List[str]
    related_actors: List[str]
    attributes: Dict[str, Any]
    is_active: bool
    false_positive: bool

class ThreatActorResponse(BaseModel):
    id: str
    name: str
    aliases: List[str]
    description: str
    country: Optional[str]
    motivation: List[str]
    sophistication: str
    targets: List[str]
    ttps: List[str]
    associated_iocs: List[str]
    campaigns: List[str]
    first_observed: datetime
    last_activity: datetime
    is_active: bool

class ThreatCampaignResponse(BaseModel):
    id: str
    name: str
    description: str
    actors: List[str]
    start_date: datetime
    end_date: Optional[datetime]
    targets: List[str]
    objectives: List[str]
    iocs: List[str]
    ttps: List[str]
    is_active: bool

class IOCAnalysisResponse(BaseModel):
    ioc_value: str
    analysis_time: str
    threat_level: str
    confidence: str
    malicious: bool
    sources: List[str]
    attributes: Dict[str, Any]
    validation: Optional[str] = None
    type: Optional[str] = None
    related_actors: Optional[List[str]] = None
    related_campaigns: Optional[List[str]] = None

# API Endpoints

@router.get("/overview", response_model=Dict[str, Any])
async def get_threat_landscape():
    """Get overview of current threat landscape"""
    try:
        landscape = await threat_intel_platform.get_threat_landscape()
        return {
            "status": "success",
            "data": landscape,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get threat landscape: {str(e)}")

@router.get("/iocs", response_model=Dict[str, Any])
async def get_iocs(
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    ioc_type: Optional[str] = Query(None),
    threat_level: Optional[str] = Query(None),
    search: Optional[str] = Query(None)
):
    """Get list of IOCs with optional filtering"""
    try:
        all_iocs = list(threat_intel_platform.iocs.values())
        
        # Apply filters
        if ioc_type:
            all_iocs = [ioc for ioc in all_iocs if ioc.type.value == ioc_type]
        
        if threat_level:
            all_iocs = [ioc for ioc in all_iocs if ioc.threat_level.value == threat_level]
        
        if search:
            search_results = await threat_intel_platform.search_iocs(search, ioc_type, threat_level)
            all_iocs = search_results
        
        # Apply pagination
        total = len(all_iocs)
        paginated_iocs = all_iocs[offset:offset + limit]
        
        # Convert to response format
        ioc_responses = []
        for ioc in paginated_iocs:
            ioc_responses.append(IOCResponse(
                id=ioc.id,
                type=ioc.type.value,
                value=ioc.value,
                threat_level=ioc.threat_level.value,
                confidence=ioc.confidence.value,
                description=ioc.description,
                source=ioc.source,
                first_seen=ioc.first_seen,
                last_seen=ioc.last_seen,
                tags=ioc.tags,
                related_campaigns=ioc.related_campaigns,
                related_actors=ioc.related_actors,
                attributes=ioc.attributes,
                is_active=ioc.is_active,
                false_positive=ioc.false_positive
            ))
        
        return {
            "status": "success",
            "data": {
                "iocs": [ioc.dict() for ioc in ioc_responses],
                "total": total,
                "limit": limit,
                "offset": offset
            },
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get IOCs: {str(e)}")

@router.post("/iocs", response_model=Dict[str, Any])
async def create_ioc(ioc_data: IOCCreate):
    """Create a new IOC"""
    try:
        # Validate IOC type
        if ioc_data.type not in [ioc_type.value for ioc_type in IOCType]:
            raise HTTPException(status_code=400, detail=f"Invalid IOC type: {ioc_data.type}")
        
        # Validate threat level
        if ioc_data.threat_level not in [level.value for level in ThreatLevel]:
            raise HTTPException(status_code=400, detail=f"Invalid threat level: {ioc_data.threat_level}")
        
        # Validate confidence level
        if ioc_data.confidence not in [conf.value for conf in ConfidenceLevel]:
            raise HTTPException(status_code=400, detail=f"Invalid confidence level: {ioc_data.confidence}")
        
        # Create IOC
        ioc = await threat_intel_platform.add_ioc(ioc_data.dict())
        
        ioc_response = IOCResponse(
            id=ioc.id,
            type=ioc.type.value,
            value=ioc.value,
            threat_level=ioc.threat_level.value,
            confidence=ioc.confidence.value,
            description=ioc.description,
            source=ioc.source,
            first_seen=ioc.first_seen,
            last_seen=ioc.last_seen,
            tags=ioc.tags,
            related_campaigns=ioc.related_campaigns,
            related_actors=ioc.related_actors,
            attributes=ioc.attributes,
            is_active=ioc.is_active,
            false_positive=ioc.false_positive
        )
        
        return {
            "status": "success",
            "data": ioc_response.dict(),
            "message": "IOC created successfully",
            "timestamp": datetime.now().isoformat()
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to create IOC: {str(e)}")

@router.get("/iocs/{ioc_id}", response_model=Dict[str, Any])
async def get_ioc(ioc_id: str):
    """Get specific IOC by ID"""
    try:
        ioc = threat_intel_platform.iocs.get(ioc_id)
        if not ioc:
            raise HTTPException(status_code=404, detail="IOC not found")
        
        ioc_response = IOCResponse(
            id=ioc.id,
            type=ioc.type.value,
            value=ioc.value,
            threat_level=ioc.threat_level.value,
            confidence=ioc.confidence.value,
            description=ioc.description,
            source=ioc.source,
            first_seen=ioc.first_seen,
            last_seen=ioc.last_seen,
            tags=ioc.tags,
            related_campaigns=ioc.related_campaigns,
            related_actors=ioc.related_actors,
            attributes=ioc.attributes,
            is_active=ioc.is_active,
            false_positive=ioc.false_positive
        )
        
        return {
            "status": "success",
            "data": ioc_response.dict(),
            "timestamp": datetime.now().isoformat()
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get IOC: {str(e)}")

@router.post("/analyze", response_model=Dict[str, Any])
async def analyze_ioc(data: Dict[str, str]):
    """Analyze an IOC value"""
    try:
        ioc_value = data.get("ioc_value")
        if not ioc_value:
            raise HTTPException(status_code=400, detail="ioc_value is required")
        
        analysis = await threat_intel_platform.analyze_ioc(ioc_value)
        
        return {
            "status": "success",
            "data": analysis,
            "timestamp": datetime.now().isoformat()
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to analyze IOC: {str(e)}")

@router.get("/actors", response_model=Dict[str, Any])
async def get_threat_actors(
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0)
):
    """Get list of threat actors"""
    try:
        all_actors = list(threat_intel_platform.threat_actors.values())
        total = len(all_actors)
        
        # Apply pagination
        paginated_actors = all_actors[offset:offset + limit]
        
        # Convert to response format
        actor_responses = []
        for actor in paginated_actors:
            actor_responses.append(ThreatActorResponse(
                id=actor.id,
                name=actor.name,
                aliases=actor.aliases,
                description=actor.description,
                country=actor.country,
                motivation=actor.motivation,
                sophistication=actor.sophistication,
                targets=actor.targets,
                ttps=actor.ttps,
                associated_iocs=actor.associated_iocs,
                campaigns=actor.campaigns,
                first_observed=actor.first_observed,
                last_activity=actor.last_activity,
                is_active=actor.is_active
            ))
        
        return {
            "status": "success",
            "data": {
                "threat_actors": [actor.dict() for actor in actor_responses],
                "total": total,
                "limit": limit,
                "offset": offset
            },
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get threat actors: {str(e)}")

@router.get("/actors/{actor_id}", response_model=Dict[str, Any])
async def get_threat_actor(actor_id: str):
    """Get specific threat actor profile"""
    try:
        actor = await threat_intel_platform.get_threat_actor_profile(actor_id)
        if not actor:
            raise HTTPException(status_code=404, detail="Threat actor not found")
        
        # Get related IOCs
        related_iocs = await threat_intel_platform.get_related_iocs(actor_id)
        
        actor_response = ThreatActorResponse(
            id=actor.id,
            name=actor.name,
            aliases=actor.aliases,
            description=actor.description,
            country=actor.country,
            motivation=actor.motivation,
            sophistication=actor.sophistication,
            targets=actor.targets,
            ttps=actor.ttps,
            associated_iocs=actor.associated_iocs,
            campaigns=actor.campaigns,
            first_observed=actor.first_observed,
            last_activity=actor.last_activity,
            is_active=actor.is_active
        )
        
        return {
            "status": "success",
            "data": {
                "actor": actor_response.dict(),
                "related_iocs": [
                    {
                        "id": ioc.id,
                        "type": ioc.type.value,
                        "value": ioc.value,
                        "threat_level": ioc.threat_level.value,
                        "description": ioc.description
                    } for ioc in related_iocs
                ]
            },
            "timestamp": datetime.now().isoformat()
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get threat actor: {str(e)}")

@router.get("/campaigns", response_model=Dict[str, Any])
async def get_threat_campaigns(
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0)
):
    """Get list of threat campaigns"""
    try:
        all_campaigns = list(threat_intel_platform.campaigns.values())
        total = len(all_campaigns)
        
        # Apply pagination
        paginated_campaigns = all_campaigns[offset:offset + limit]
        
        # Convert to response format
        campaign_responses = []
        for campaign in paginated_campaigns:
            campaign_responses.append(ThreatCampaignResponse(
                id=campaign.id,
                name=campaign.name,
                description=campaign.description,
                actors=campaign.actors,
                start_date=campaign.start_date,
                end_date=campaign.end_date,
                targets=campaign.targets,
                objectives=campaign.objectives,
                iocs=campaign.iocs,
                ttps=campaign.ttps,
                is_active=campaign.is_active
            ))
        
        return {
            "status": "success",
            "data": {
                "campaigns": [campaign.dict() for campaign in campaign_responses],
                "total": total,
                "limit": limit,
                "offset": offset
            },
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get threat campaigns: {str(e)}")

@router.get("/attribution/{ioc_value}", response_model=Dict[str, Any])
async def get_ioc_attribution(ioc_value: str):
    """Get threat actor attribution for an IOC"""
    try:
        attributions = await threat_intel_platform.get_actor_attribution(ioc_value)
        
        return {
            "status": "success",
            "data": {
                "ioc_value": ioc_value,
                "attributions": attributions
            },
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get IOC attribution: {str(e)}")

@router.get("/search", response_model=Dict[str, Any])
async def search_threat_intelligence(
    query: str = Query(..., description="Search query"),
    search_type: str = Query("all", description="Search type: all, iocs, actors, campaigns"),
    limit: int = Query(50, ge=1, le=1000)
):
    """Search across threat intelligence data"""
    try:
        results = {
            "query": query,
            "search_type": search_type,
            "results": {}
        }
        
        if search_type in ["all", "iocs"]:
            ioc_results = await threat_intel_platform.search_iocs(query)
            results["results"]["iocs"] = [
                {
                    "id": ioc.id,
                    "type": ioc.type.value,
                    "value": ioc.value,
                    "threat_level": ioc.threat_level.value,
                    "description": ioc.description,
                    "tags": ioc.tags
                } for ioc in ioc_results[:limit]
            ]
        
        if search_type in ["all", "actors"]:
            actor_results = []
            for actor in threat_intel_platform.threat_actors.values():
                if (query.lower() in actor.name.lower() or 
                    query.lower() in actor.description.lower() or
                    any(query.lower() in alias.lower() for alias in actor.aliases)):
                    actor_results.append({
                        "id": actor.id,
                        "name": actor.name,
                        "aliases": actor.aliases,
                        "country": actor.country,
                        "description": actor.description
                    })
            results["results"]["actors"] = actor_results[:limit]
        
        if search_type in ["all", "campaigns"]:
            campaign_results = []
            for campaign in threat_intel_platform.campaigns.values():
                if (query.lower() in campaign.name.lower() or 
                    query.lower() in campaign.description.lower()):
                    campaign_results.append({
                        "id": campaign.id,
                        "name": campaign.name,
                        "description": campaign.description,
                        "actors": campaign.actors,
                        "targets": campaign.targets
                    })
            results["results"]["campaigns"] = campaign_results[:limit]
        
        return {
            "status": "success",
            "data": results,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to search threat intelligence: {str(e)}")

@router.get("/statistics", response_model=Dict[str, Any])
async def get_threat_statistics():
    """Get threat intelligence statistics"""
    try:
        stats = {
            "ioc_statistics": {
                "total_iocs": len(threat_intel_platform.iocs),
                "active_iocs": sum(1 for ioc in threat_intel_platform.iocs.values() if ioc.is_active),
                "by_type": {},
                "by_threat_level": {},
                "by_confidence": {}
            },
            "actor_statistics": {
                "total_actors": len(threat_intel_platform.threat_actors),
                "active_actors": sum(1 for actor in threat_intel_platform.threat_actors.values() if actor.is_active),
                "by_country": {},
                "by_sophistication": {}
            },
            "campaign_statistics": {
                "total_campaigns": len(threat_intel_platform.campaigns),
                "active_campaigns": sum(1 for campaign in threat_intel_platform.campaigns.values() if campaign.is_active)
            }
        }
        
        # IOC statistics by type
        for ioc in threat_intel_platform.iocs.values():
            ioc_type = ioc.type.value
            threat_level = ioc.threat_level.value
            confidence = ioc.confidence.value
            
            stats["ioc_statistics"]["by_type"][ioc_type] = stats["ioc_statistics"]["by_type"].get(ioc_type, 0) + 1
            stats["ioc_statistics"]["by_threat_level"][threat_level] = stats["ioc_statistics"]["by_threat_level"].get(threat_level, 0) + 1
            stats["ioc_statistics"]["by_confidence"][confidence] = stats["ioc_statistics"]["by_confidence"].get(confidence, 0) + 1
        
        # Actor statistics
        for actor in threat_intel_platform.threat_actors.values():
            country = actor.country or "Unknown"
            sophistication = actor.sophistication
            
            stats["actor_statistics"]["by_country"][country] = stats["actor_statistics"]["by_country"].get(country, 0) + 1
            stats["actor_statistics"]["by_sophistication"][sophistication] = stats["actor_statistics"]["by_sophistication"].get(sophistication, 0) + 1
        
        return {
            "status": "success",
            "data": stats,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get threat statistics: {str(e)}")