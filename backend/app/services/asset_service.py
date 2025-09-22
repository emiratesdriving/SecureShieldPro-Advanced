"""
Advanced Asset Management Service
Comprehensive asset discovery, vulnerability tracking, and risk assessment
"""

import logging
import psutil
import socket
import json
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from pathlib import Path

# Graceful import of optional dependencies
try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    nmap = None
    NMAP_AVAILABLE = False

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    requests = None
    REQUESTS_AVAILABLE = False

import asyncio
import ipaddress
import socket
import subprocess
import nmap
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from fastapi import HTTPException
import logging
import json
import uuid

from app.models.asset_models import (
    Asset, AssetService, AssetVulnerability, ComplianceCheck,
    AssetCreate, AssetUpdate, AssetResponse, AssetSummary,
    AssetType, RiskLevel, ComplianceStatus
)

logger = logging.getLogger(__name__)

class AssetDiscoveryService:
    """Asset discovery and network scanning service"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        # Initialize nmap scanner only if available
        if NMAP_AVAILABLE and nmap:
            try:
                self.nm = nmap.PortScanner()
                self.scanner_available = True
            except Exception as e:
                self.logger.warning(f"Failed to initialize nmap scanner: {e}")
                self.nm = None
                self.scanner_available = False
        else:
            self.nm = None
            self.scanner_available = False
            self.logger.warning("Nmap scanner not available - using limited asset discovery")
    
    async def discover_network_assets(self, network_range: str = "192.168.1.0/24") -> List[Dict[str, Any]]:
        """Discover assets in network range using available tools"""
        try:
            logger.info(f"Starting network discovery for range: {network_range}")
            
            # Validate network range
            try:
                import ipaddress
                network = ipaddress.ip_network(network_range, strict=False)
            except ValueError as e:
                from fastapi import HTTPException
                raise HTTPException(status_code=400, detail=f"Invalid network range: {e}")
            
            discovered_assets = []
            
            if self.scanner_available and self.nm:
                # Use nmap for comprehensive scanning
                try:
                    scan_result = self.nm.scan(hosts=network_range, arguments='-sn -T4')
                    
                    for host in scan_result['scan']:
                        if scan_result['scan'][host]['status']['state'] == 'up':
                            asset_info = await self._gather_host_info(host)
                            discovered_assets.append(asset_info)
                except Exception as e:
                    logger.error(f"Nmap scan failed: {e}")
                    # Fall back to basic discovery
                    discovered_assets = await self._basic_network_discovery()
            else:
                # Use basic discovery method
                logger.info("Using basic network discovery (nmap not available)")
                discovered_assets = await self._basic_network_discovery()
            
            logger.info(f"Discovered {len(discovered_assets)} assets")
            return discovered_assets
            
        except Exception as e:
            logger.error(f"Network discovery failed: {e}")
            from fastapi import HTTPException
            raise HTTPException(status_code=500, detail=f"Discovery failed: {e}")
    
    async def _basic_network_discovery(self) -> List[Dict[str, Any]]:
        """Basic network discovery without external tools"""
        discovered_assets = []
        
        try:
            # Get local host information
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            
            asset_info = {
                "ip_address": local_ip,
                "hostname": hostname,
                "mac_address": "unknown",
                "operating_system": "unknown",
                "os_version": "unknown",
                "services": [],
                "asset_type": "server",
                "discovery_method": "basic_scan",
                "discovery_date": datetime.now().isoformat()
            }
            discovered_assets.append(asset_info)
            
        except Exception as e:
            logger.error(f"Basic discovery failed: {e}")
            
        return discovered_assets
    
    async def _gather_host_info(self, host: str) -> Dict[str, Any]:
        """Gather detailed information about a host"""
        asset_info = {
            "ip_address": host,
            "hostname": None,
            "mac_address": None,
            "operating_system": None,
            "os_version": None,
            "services": [],
            "asset_type": "unknown",
            "discovery_method": "basic_scan",
            "discovery_date": datetime.now().isoformat()
        }
        
        try:
            # Reverse DNS lookup
            try:
                hostname = socket.gethostbyaddr(host)[0]
                asset_info["hostname"] = hostname
            except:
                pass
            
            # Enhanced scanning if nmap is available
            if self.scanner_available and self.nm:
                try:
                    # Service scan
                    scan_result = self.nm.scan(host, arguments='-sS -O -sV -T4')
                    
                    if host in scan_result['scan']:
                        host_data = scan_result['scan'][host]
                        
                        # Operating system detection
                        if 'osmatch' in host_data and host_data['osmatch']:
                            os_match = host_data['osmatch'][0]
                            asset_info["operating_system"] = os_match.get('name', '')
                            asset_info["os_version"] = os_match.get('osclass', [{}])[0].get('osfamily', '')
                        
                        # Service detection
                        if 'tcp' in host_data:
                            for port, port_data in host_data['tcp'].items():
                                if port_data['state'] == 'open':
                                    service = {
                                        "port": port,
                                        "protocol": "tcp",
                                        "service_name": port_data.get('name', 'unknown'),
                                        "version": port_data.get('version', ''),
                                        "banner": port_data.get('product', '') + ' ' + port_data.get('version', ''),
                                        "is_encrypted": self._is_encrypted_service(port, port_data.get('name', ''))
                                    }
                                    asset_info["services"].append(service)
                        
                        asset_info["discovery_method"] = "nmap_scan"
                        
                except Exception as e:
                    logger.warning(f"Nmap scan failed for {host}: {e}")
                    # Continue with basic info
            
            # Determine asset type based on available information
            asset_info["asset_type"] = self._determine_asset_type(asset_info)
                
        except Exception as e:
            logger.warning(f"Failed to gather detailed info for {host}: {e}")
        
        return asset_info
    
    def _is_encrypted_service(self, port: int, service_name: str) -> bool:
        """Determine if a service is encrypted"""
        encrypted_ports = {443, 993, 995, 636, 989, 990, 5986}
        encrypted_services = {'https', 'imaps', 'pop3s', 'ldaps', 'ftps', 'winrm-https'}
        
        return port in encrypted_ports or service_name.lower() in encrypted_services
    
    def _determine_asset_type(self, asset_info: Dict[str, Any]) -> str:
        """Determine asset type based on services and OS"""
        services = {s['service_name'].lower() for s in asset_info.get('services', [])}
        os_name = asset_info.get('operating_system', '').lower()
        
        # Database servers
        if any(db in services for db in ['mysql', 'postgresql', 'mssql', 'oracle', 'mongodb']):
            return AssetType.DATABASE.value
        
        # Web servers/applications
        if any(web in services for web in ['http', 'https', 'apache', 'nginx']):
            return AssetType.APPLICATION.value
        
        # Network devices
        if any(net in services for net in ['snmp', 'telnet', 'ssh']) and 'cisco' in os_name:
            return AssetType.NETWORK_DEVICE.value
        
        # Servers
        if any(srv in services for srv in ['ssh', 'rdp', 'winrm', 'smb']):
            if 'windows' in os_name:
                return AssetType.SERVER.value
            elif 'linux' in os_name or 'unix' in os_name:
                return AssetType.SERVER.value
        
        # Default to workstation
        return AssetType.WORKSTATION.value

class AssetManagementService:
    """Core asset management service"""
    
    def __init__(self, db: Session):
        self.db = db
        self.discovery_service = AssetDiscoveryService()
    
    async def create_asset(self, asset_data: AssetCreate) -> AssetResponse:
        """Create a new asset"""
        try:
            # Generate unique asset ID
            asset_id = f"ASSET-{uuid.uuid4().hex[:8].upper()}"
            
            # Create asset
            db_asset = Asset(
                asset_id=asset_id,
                name=asset_data.name,
                asset_type=asset_data.asset_type.value,
                ip_address=asset_data.ip_address,
                mac_address=asset_data.mac_address,
                hostname=asset_data.hostname,
                domain=asset_data.domain,
                operating_system=asset_data.operating_system,
                os_version=asset_data.os_version,
                manufacturer=asset_data.manufacturer,
                model=asset_data.model,
                owner=asset_data.owner,
                department=asset_data.department,
                location=asset_data.location,
                environment=asset_data.environment,
                tags=asset_data.tags or {},
                discovery_method=asset_data.discovery_method,
                discovery_date=datetime.now(timezone.utc),
                last_updated=datetime.now(timezone.utc)
            )
            
            self.db.add(db_asset)
            self.db.commit()
            self.db.refresh(db_asset)
            
            logger.info(f"Created asset: {asset_id}")
            return AssetResponse.from_orm(db_asset)
            
        except Exception as e:
            self.db.rollback()
            logger.error(f"Failed to create asset: {e}")
            raise HTTPException(status_code=500, detail=f"Failed to create asset: {e}")
    
    async def get_asset(self, asset_id: str) -> AssetResponse:
        """Get asset by ID"""
        asset = self.db.query(Asset).filter(Asset.asset_id == asset_id).first()
        if not asset:
            raise HTTPException(status_code=404, detail="Asset not found")
        
        return AssetResponse.from_orm(asset)
    
    async def list_assets(self, 
                         asset_type: Optional[str] = None,
                         risk_level: Optional[str] = None,
                         environment: Optional[str] = None,
                         limit: int = 100,
                         offset: int = 0) -> List[AssetResponse]:
        """List assets with filters"""
        query = self.db.query(Asset).filter(Asset.is_active == True)
        
        if asset_type:
            query = query.filter(Asset.asset_type == asset_type)
        if risk_level:
            query = query.filter(Asset.risk_level == risk_level)
        if environment:
            query = query.filter(Asset.environment == environment)
        
        assets = query.offset(offset).limit(limit).all()
        return [AssetResponse.from_orm(asset) for asset in assets]
    
    async def update_asset(self, asset_id: str, asset_update: AssetUpdate) -> AssetResponse:
        """Update asset"""
        asset = self.db.query(Asset).filter(Asset.asset_id == asset_id).first()
        if not asset:
            raise HTTPException(status_code=404, detail="Asset not found")
        
        # Update fields
        update_data = asset_update.dict(exclude_unset=True)
        for field, value in update_data.items():
            if hasattr(asset, field):
                setattr(asset, field, value)
        
        asset.last_updated = datetime.now(timezone.utc)
        
        self.db.commit()
        self.db.refresh(asset)
        
        logger.info(f"Updated asset: {asset_id}")
        return AssetResponse.from_orm(asset)
    
    async def delete_asset(self, asset_id: str) -> bool:
        """Soft delete asset"""
        asset = self.db.query(Asset).filter(Asset.asset_id == asset_id).first()
        if not asset:
            raise HTTPException(status_code=404, detail="Asset not found")
        
        asset.is_active = False
        asset.last_updated = datetime.now(timezone.utc)
        
        self.db.commit()
        logger.info(f"Deleted asset: {asset_id}")
        return True
    
    async def discover_assets(self, network_range: str) -> List[AssetResponse]:
        """Discover and import new assets"""
        try:
            # Discover assets
            discovered = await self.discovery_service.discover_network_assets(network_range)
            
            created_assets = []
            for asset_data in discovered:
                # Check if asset already exists
                existing = self.db.query(Asset).filter(
                    Asset.ip_address == asset_data['ip_address']
                ).first()
                
                if not existing:
                    # Create new asset
                    asset_create = AssetCreate(
                        name=asset_data.get('hostname') or f"Host-{asset_data['ip_address']}",
                        asset_type=AssetType(asset_data['asset_type']),
                        ip_address=asset_data['ip_address'],
                        hostname=asset_data.get('hostname'),
                        operating_system=asset_data.get('operating_system'),
                        os_version=asset_data.get('os_version'),
                        discovery_method="network_scan"
                    )
                    
                    new_asset = await self.create_asset(asset_create)
                    created_assets.append(new_asset)
                    
                    # Add services
                    for service_data in asset_data.get('services', []):
                        service = AssetService(
                            asset_id=new_asset.id,
                            service_name=service_data['service_name'],
                            port=service_data['port'],
                            protocol=service_data['protocol'],
                            version=service_data.get('version'),
                            banner=service_data.get('banner'),
                            is_encrypted=service_data.get('is_encrypted', False),
                            last_detected=datetime.now(timezone.utc)
                        )
                        self.db.add(service)
                else:
                    # Update existing asset
                    existing.last_updated = datetime.now(timezone.utc)
                    if asset_data.get('hostname'):
                        existing.hostname = asset_data['hostname']
                    if asset_data.get('operating_system'):
                        existing.operating_system = asset_data['operating_system']
            
            self.db.commit()
            logger.info(f"Discovery imported {len(created_assets)} new assets")
            return created_assets
            
        except Exception as e:
            self.db.rollback()
            logger.error(f"Asset discovery failed: {e}")
            raise HTTPException(status_code=500, detail=f"Discovery failed: {e}")
    
    async def get_asset_summary(self) -> AssetSummary:
        """Get asset inventory summary"""
        try:
            total_assets = self.db.query(Asset).filter(Asset.is_active == True).count()
            
            # Assets by type
            type_counts = {}
            for asset_type in AssetType:
                count = self.db.query(Asset).filter(
                    Asset.asset_type == asset_type.value,
                    Asset.is_active == True
                ).count()
                type_counts[asset_type.value] = count
            
            # Assets by risk level
            risk_counts = {}
            for risk_level in RiskLevel:
                count = self.db.query(Asset).filter(
                    Asset.risk_level == risk_level.value,
                    Asset.is_active == True
                ).count()
                risk_counts[risk_level.value] = count
            
            # Compliance status
            compliance_counts = {}
            for status in ComplianceStatus:
                count = self.db.query(Asset).filter(
                    Asset.compliance_status == status.value,
                    Asset.is_active == True
                ).count()
                compliance_counts[status.value] = count
            
            # Recent discoveries (last 7 days)
            recent_date = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0) - timedelta(days=7)
            recent_discoveries = self.db.query(Asset).filter(
                Asset.discovery_date >= recent_date,
                Asset.is_active == True
            ).count()
            
            # Vulnerability counts
            total_vulns = self.db.query(AssetVulnerability).filter(
                AssetVulnerability.status == "open"
            ).count()
            
            critical_vulns = self.db.query(AssetVulnerability).filter(
                AssetVulnerability.status == "open",
                AssetVulnerability.severity == "critical"
            ).count()
            
            return AssetSummary(
                total_assets=total_assets,
                by_type=type_counts,
                by_risk_level=risk_counts,
                by_compliance_status=compliance_counts,
                recent_discoveries=recent_discoveries,
                total_vulnerabilities=total_vulns,
                critical_vulnerabilities=critical_vulns
            )
            
        except Exception as e:
            logger.error(f"Failed to get asset summary: {e}")
            raise HTTPException(status_code=500, detail=f"Failed to get summary: {e}")

# Global service instance
asset_service: Optional[AssetManagementService] = None

def get_asset_service() -> AssetManagementService:
    """Get asset management service instance"""
    return asset_service