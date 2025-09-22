"""
Advanced Threat Intelligence Platform
Provides comprehensive threat intelligence capabilities including IOC management,
threat actor profiling, and integration with external threat feeds.
"""

import json
import asyncio
import aiohttp
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, asdict
from enum import Enum
import hashlib
import ipaddress
import re
from urllib.parse import urlparse

class IOCType(Enum):
    """Indicator of Compromise types"""
    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    URL = "url"
    FILE_HASH = "file_hash"
    EMAIL = "email"
    REGISTRY_KEY = "registry_key"
    MUTEX = "mutex"
    USER_AGENT = "user_agent"
    CERTIFICATE = "certificate"

class ThreatLevel(Enum):
    """Threat severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class ConfidenceLevel(Enum):
    """Confidence in threat intelligence"""
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"

@dataclass
class IOC:
    """Indicator of Compromise data structure"""
    id: str
    type: IOCType
    value: str
    threat_level: ThreatLevel
    confidence: ConfidenceLevel
    description: str
    source: str
    first_seen: datetime
    last_seen: datetime
    tags: List[str]
    related_campaigns: List[str]
    related_actors: List[str]
    attributes: Dict[str, Any]
    is_active: bool = True
    false_positive: bool = False

@dataclass
class ThreatActor:
    """Threat actor profile"""
    id: str
    name: str
    aliases: List[str]
    description: str
    country: Optional[str]
    motivation: List[str]  # financial, espionage, activism, etc.
    sophistication: str  # basic, intermediate, advanced, expert
    targets: List[str]  # sectors/industries
    ttps: List[str]  # Tactics, Techniques, and Procedures
    associated_iocs: List[str]
    campaigns: List[str]
    first_observed: datetime
    last_activity: datetime
    is_active: bool = True

@dataclass
class ThreatCampaign:
    """Threat campaign information"""
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
    is_active: bool = True

class ThreatIntelligencePlatform:
    """Advanced Threat Intelligence Platform"""
    
    def __init__(self):
        self.iocs: Dict[str, IOC] = {}
        self.threat_actors: Dict[str, ThreatActor] = {}
        self.campaigns: Dict[str, ThreatCampaign] = {}
        self.threat_feeds: List[Dict] = []
        self.session: Optional[aiohttp.ClientSession] = None
        
        # Initialize with some sample data
        self._initialize_sample_data()
    
    def _initialize_sample_data(self):
        """Initialize with sample threat intelligence data"""
        # Sample IOCs
        sample_iocs = [
            {
                "id": "ioc_001",
                "type": IOCType.IP_ADDRESS,
                "value": "192.168.1.100",
                "threat_level": ThreatLevel.HIGH,
                "confidence": ConfidenceLevel.HIGH,
                "description": "Command and Control server",
                "source": "Internal Analysis",
                "tags": ["c2", "malware", "botnet"],
                "related_campaigns": ["campaign_001"],
                "related_actors": ["apt29"]
            },
            {
                "id": "ioc_002", 
                "type": IOCType.DOMAIN,
                "value": "malicious-domain.com",
                "threat_level": ThreatLevel.CRITICAL,
                "confidence": ConfidenceLevel.HIGH,
                "description": "Phishing domain impersonating legitimate service",
                "source": "Threat Feed",
                "tags": ["phishing", "credential_theft"],
                "related_campaigns": ["campaign_002"],
                "related_actors": ["lazarus"]
            },
            {
                "id": "ioc_003",
                "type": IOCType.FILE_HASH,
                "value": "d41d8cd98f00b204e9800998ecf8427e",
                "threat_level": ThreatLevel.HIGH,
                "confidence": ConfidenceLevel.MEDIUM,
                "description": "Malicious payload MD5 hash",
                "source": "Sandbox Analysis",
                "tags": ["malware", "trojan", "ransomware"],
                "related_campaigns": ["campaign_001"],
                "related_actors": ["apt29"]
            }
        ]
        
        for ioc_data in sample_iocs:
            ioc = IOC(
                id=ioc_data["id"],
                type=ioc_data["type"],
                value=ioc_data["value"],
                threat_level=ioc_data["threat_level"],
                confidence=ioc_data["confidence"],
                description=ioc_data["description"],
                source=ioc_data["source"],
                first_seen=datetime.now() - timedelta(days=7),
                last_seen=datetime.now(),
                tags=ioc_data["tags"],
                related_campaigns=ioc_data["related_campaigns"],
                related_actors=ioc_data["related_actors"],
                attributes={}
            )
            self.iocs[ioc.id] = ioc
        
        # Sample Threat Actors
        sample_actors = [
            {
                "id": "apt29",
                "name": "APT29",
                "aliases": ["Cozy Bear", "The Dukes"],
                "description": "State-sponsored threat group",
                "country": "Russia",
                "motivation": ["espionage", "intelligence_gathering"],
                "sophistication": "expert",
                "targets": ["government", "healthcare", "technology"],
                "ttps": ["spear_phishing", "zero_day_exploits", "living_off_land"]
            },
            {
                "id": "lazarus",
                "name": "Lazarus Group",
                "aliases": ["HIDDEN COBRA", "Guardians of Peace"],
                "description": "State-sponsored cyber threat group",
                "country": "North Korea",
                "motivation": ["financial", "espionage", "disruption"],
                "sophistication": "advanced",
                "targets": ["financial", "entertainment", "cryptocurrency"],
                "ttps": ["destructive_malware", "financial_theft", "supply_chain_attacks"]
            }
        ]
        
        for actor_data in sample_actors:
            actor = ThreatActor(
                id=actor_data["id"],
                name=actor_data["name"],
                aliases=actor_data["aliases"],
                description=actor_data["description"],
                country=actor_data["country"],
                motivation=actor_data["motivation"],
                sophistication=actor_data["sophistication"],
                targets=actor_data["targets"],
                ttps=actor_data["ttps"],
                associated_iocs=[ioc.id for ioc in self.iocs.values() if actor_data["id"] in ioc.related_actors],
                campaigns=["campaign_001", "campaign_002"],
                first_observed=datetime.now() - timedelta(days=30),
                last_activity=datetime.now() - timedelta(days=1)
            )
            self.threat_actors[actor.id] = actor
        
        # Sample Campaigns
        sample_campaigns = [
            {
                "id": "campaign_001",
                "name": "Operation Cyber Storm",
                "description": "Large-scale espionage campaign targeting government entities",
                "actors": ["apt29"],
                "targets": ["government", "military", "defense_contractors"],
                "objectives": ["intelligence_gathering", "persistence"]
            },
            {
                "id": "campaign_002", 
                "name": "Financial Sector Attack",
                "description": "Coordinated attacks against banking infrastructure",
                "actors": ["lazarus"],
                "targets": ["banks", "financial_services", "payment_processors"],
                "objectives": ["financial_theft", "disruption"]
            }
        ]
        
        for campaign_data in sample_campaigns:
            campaign = ThreatCampaign(
                id=campaign_data["id"],
                name=campaign_data["name"],
                description=campaign_data["description"],
                actors=campaign_data["actors"],
                start_date=datetime.now() - timedelta(days=14),
                end_date=None,
                targets=campaign_data["targets"],
                objectives=campaign_data["objectives"],
                iocs=[ioc.id for ioc in self.iocs.values() if campaign_data["id"] in ioc.related_campaigns],
                ttps=["spear_phishing", "credential_harvesting", "lateral_movement"]
            )
            self.campaigns[campaign.id] = campaign
    
    async def add_ioc(self, ioc_data: Dict) -> IOC:
        """Add a new Indicator of Compromise"""
        ioc_id = f"ioc_{len(self.iocs) + 1:03d}"
        
        ioc = IOC(
            id=ioc_id,
            type=IOCType(ioc_data["type"]),
            value=ioc_data["value"],
            threat_level=ThreatLevel(ioc_data.get("threat_level", "medium")),
            confidence=ConfidenceLevel(ioc_data.get("confidence", "medium")),
            description=ioc_data.get("description", ""),
            source=ioc_data.get("source", "Manual Entry"),
            first_seen=datetime.now(),
            last_seen=datetime.now(),
            tags=ioc_data.get("tags", []),
            related_campaigns=ioc_data.get("related_campaigns", []),
            related_actors=ioc_data.get("related_actors", []),
            attributes=ioc_data.get("attributes", {})
        )
        
        self.iocs[ioc_id] = ioc
        return ioc
    
    async def search_iocs(self, query: str, ioc_type: Optional[str] = None, 
                         threat_level: Optional[str] = None) -> List[IOC]:
        """Search IOCs by various criteria"""
        results = []
        
        for ioc in self.iocs.values():
            # Filter by type if specified
            if ioc_type and ioc.type.value != ioc_type:
                continue
            
            # Filter by threat level if specified
            if threat_level and ioc.threat_level.value != threat_level:
                continue
            
            # Search in value, description, and tags
            if (query.lower() in ioc.value.lower() or 
                query.lower() in ioc.description.lower() or
                any(query.lower() in tag.lower() for tag in ioc.tags)):
                results.append(ioc)
        
        return results
    
    async def get_threat_actor_profile(self, actor_id: str) -> Optional[ThreatActor]:
        """Get detailed threat actor profile"""
        return self.threat_actors.get(actor_id)
    
    async def get_related_iocs(self, actor_id: str) -> List[IOC]:
        """Get all IOCs related to a specific threat actor"""
        return [ioc for ioc in self.iocs.values() if actor_id in ioc.related_actors]
    
    async def analyze_ioc(self, ioc_value: str) -> Dict[str, Any]:
        """Perform analysis on an IOC"""
        analysis_result = {
            "ioc_value": ioc_value,
            "analysis_time": datetime.now().isoformat(),
            "threat_level": "unknown",
            "confidence": "low",
            "malicious": False,
            "sources": [],
            "attributes": {}
        }
        
        # Check if IOC exists in our database
        existing_ioc = None
        for ioc in self.iocs.values():
            if ioc.value == ioc_value:
                existing_ioc = ioc
                break
        
        if existing_ioc:
            analysis_result.update({
                "threat_level": existing_ioc.threat_level.value,
                "confidence": existing_ioc.confidence.value,
                "malicious": existing_ioc.threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL],
                "sources": [existing_ioc.source],
                "attributes": existing_ioc.attributes,
                "related_actors": existing_ioc.related_actors,
                "related_campaigns": existing_ioc.related_campaigns
            })
        else:
            # Perform basic validation
            analysis_result.update(self._basic_ioc_validation(ioc_value))
        
        return analysis_result
    
    def _basic_ioc_validation(self, ioc_value: str) -> Dict[str, Any]:
        """Perform basic validation on IOC value"""
        result = {
            "validation": "passed",
            "type": "unknown",
            "attributes": {}
        }
        
        # IP Address validation
        try:
            ip = ipaddress.ip_address(ioc_value)
            result["type"] = "ip_address"
            result["attributes"] = {
                "version": f"IPv{ip.version}",
                "is_private": ip.is_private,
                "is_multicast": ip.is_multicast,
                "is_loopback": ip.is_loopback
            }
        except ValueError:
            pass
        
        # Domain validation
        domain_pattern = re.compile(
            r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        )
        if domain_pattern.match(ioc_value):
            result["type"] = "domain"
            result["attributes"] = {
                "length": len(ioc_value),
                "subdomain_count": ioc_value.count('.'),
                "suspicious_tld": ioc_value.split('.')[-1] in ['tk', 'ml', 'ga', 'cf']
            }
        
        # URL validation
        try:
            parsed_url = urlparse(ioc_value)
            if parsed_url.scheme and parsed_url.netloc:
                result["type"] = "url"
                result["attributes"] = {
                    "scheme": parsed_url.scheme,
                    "domain": parsed_url.netloc,
                    "path": parsed_url.path,
                    "has_query": bool(parsed_url.query)
                }
        except Exception:
            pass
        
        # Hash validation (MD5, SHA1, SHA256)
        if re.match(r'^[a-fA-F0-9]{32}$', ioc_value):
            result["type"] = "file_hash"
            result["attributes"] = {"hash_type": "MD5"}
        elif re.match(r'^[a-fA-F0-9]{40}$', ioc_value):
            result["type"] = "file_hash"
            result["attributes"] = {"hash_type": "SHA1"}
        elif re.match(r'^[a-fA-F0-9]{64}$', ioc_value):
            result["type"] = "file_hash"
            result["attributes"] = {"hash_type": "SHA256"}
        
        return result
    
    async def get_threat_landscape(self) -> Dict[str, Any]:
        """Get overview of current threat landscape"""
        total_iocs = len(self.iocs)
        active_iocs = sum(1 for ioc in self.iocs.values() if ioc.is_active)
        
        # Count by threat level
        threat_level_counts = {}
        for level in ThreatLevel:
            threat_level_counts[level.value] = sum(
                1 for ioc in self.iocs.values() 
                if ioc.threat_level == level and ioc.is_active
            )
        
        # Count by IOC type
        ioc_type_counts = {}
        for ioc_type in IOCType:
            ioc_type_counts[ioc_type.value] = sum(
                1 for ioc in self.iocs.values() 
                if ioc.type == ioc_type and ioc.is_active
            )
        
        # Active threat actors
        active_actors = sum(1 for actor in self.threat_actors.values() if actor.is_active)
        
        # Active campaigns
        active_campaigns = sum(1 for campaign in self.campaigns.values() if campaign.is_active)
        
        return {
            "overview": {
                "total_iocs": total_iocs,
                "active_iocs": active_iocs,
                "active_threat_actors": active_actors,
                "active_campaigns": active_campaigns
            },
            "threat_levels": threat_level_counts,
            "ioc_types": ioc_type_counts,
            "recent_activity": {
                "new_iocs_24h": sum(
                    1 for ioc in self.iocs.values() 
                    if ioc.first_seen > datetime.now() - timedelta(hours=24)
                ),
                "updated_iocs_24h": sum(
                    1 for ioc in self.iocs.values() 
                    if ioc.last_seen > datetime.now() - timedelta(hours=24)
                )
            }
        }
    
    async def get_actor_attribution(self, ioc_value: str) -> List[Dict[str, Any]]:
        """Get threat actor attribution for an IOC"""
        attributions = []
        
        # Find IOC
        target_ioc = None
        for ioc in self.iocs.values():
            if ioc.value == ioc_value:
                target_ioc = ioc
                break
        
        if target_ioc:
            for actor_id in target_ioc.related_actors:
                actor = self.threat_actors.get(actor_id)
                if actor:
                    attributions.append({
                        "actor_id": actor.id,
                        "actor_name": actor.name,
                        "confidence": target_ioc.confidence.value,
                        "country": actor.country,
                        "motivation": actor.motivation,
                        "sophistication": actor.sophistication
                    })
        
        return attributions
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert platform data to dictionary"""
        return {
            "iocs": {ioc_id: asdict(ioc) for ioc_id, ioc in self.iocs.items()},
            "threat_actors": {actor_id: asdict(actor) for actor_id, actor in self.threat_actors.items()},
            "campaigns": {campaign_id: asdict(campaign) for campaign_id, campaign in self.campaigns.items()}
        }

# Global instance
threat_intel_platform = ThreatIntelligencePlatform()