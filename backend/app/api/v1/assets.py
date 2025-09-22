"""
Asset Management API Endpoints
Comprehensive asset inventory and risk management
"""

from fastapi import APIRouter, Depends, HTTPException, Query, BackgroundTasks
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime

from app.core.auth import get_current_user
from app.db.database import get_db
from app.services.asset_service import AssetManagementService
from app.models.asset_models import (
    AssetCreate, AssetUpdate, AssetResponse, AssetSummary,
    AssetServiceResponse, VulnerabilityResponse, ComplianceCheckResponse,
    AssetType, RiskLevel, ComplianceStatus
)

router = APIRouter()

def get_asset_service(db: Session = Depends(get_db)) -> AssetManagementService:
    """Get asset management service"""
    return AssetManagementService(db)

@router.get("/summary", response_model=AssetSummary)
async def get_asset_summary(
    current_user: dict = Depends(get_current_user),
    asset_service: AssetManagementService = Depends(get_asset_service)
):
    """
    Get comprehensive asset inventory summary
    
    Returns overview of all assets, risk levels, compliance status, and key metrics
    """
    return await asset_service.get_asset_summary()

@router.get("/", response_model=List[AssetResponse])
async def list_assets(
    asset_type: Optional[str] = Query(None, description="Filter by asset type"),
    risk_level: Optional[str] = Query(None, description="Filter by risk level"),
    environment: Optional[str] = Query(None, description="Filter by environment"),
    limit: int = Query(100, ge=1, le=1000, description="Number of assets to return"),
    offset: int = Query(0, ge=0, description="Number of assets to skip"),
    current_user: dict = Depends(get_current_user),
    asset_service: AssetManagementService = Depends(get_asset_service)
):
    """
    List assets with optional filtering
    
    Supports filtering by:
    - Asset type (server, workstation, database, etc.)
    - Risk level (critical, high, medium, low)
    - Environment (prod, dev, test, staging)
    """
    return await asset_service.list_assets(
        asset_type=asset_type,
        risk_level=risk_level,
        environment=environment,
        limit=limit,
        offset=offset
    )

@router.post("/", response_model=AssetResponse, status_code=201)
async def create_asset(
    asset: AssetCreate,
    current_user: dict = Depends(get_current_user),
    asset_service: AssetManagementService = Depends(get_asset_service)
):
    """
    Create a new asset manually
    
    Allows manual asset registration with full details including:
    - Basic information (name, type, IP, hostname)
    - System details (OS, version, manufacturer)
    - Ownership and location information
    - Custom tags and attributes
    """
    return await asset_service.create_asset(asset)

@router.get("/{asset_id}", response_model=AssetResponse)
async def get_asset(
    asset_id: str,
    current_user: dict = Depends(get_current_user),
    asset_service: AssetManagementService = Depends(get_asset_service)
):
    """
    Get detailed asset information by ID
    
    Returns complete asset details including:
    - System specifications
    - Network configuration
    - Risk and compliance status
    - Discovery and update history
    """
    return await asset_service.get_asset(asset_id)

@router.put("/{asset_id}", response_model=AssetResponse)
async def update_asset(
    asset_id: str,
    asset_update: AssetUpdate,
    current_user: dict = Depends(get_current_user),
    asset_service: AssetManagementService = Depends(get_asset_service)
):
    """
    Update asset information
    
    Supports updating:
    - Owner and department assignments
    - Location and environment classification
    - Risk level and compliance status
    - Custom tags and metadata
    """
    return await asset_service.update_asset(asset_id, asset_update)

@router.delete("/{asset_id}")
async def delete_asset(
    asset_id: str,
    current_user: dict = Depends(get_current_user),
    asset_service: AssetManagementService = Depends(get_asset_service)
):
    """
    Delete (deactivate) an asset
    
    Performs soft delete to maintain audit trail
    """
    success = await asset_service.delete_asset(asset_id)
    return {"message": "Asset deleted successfully", "success": success}

@router.post("/discover", response_model=List[AssetResponse])
async def discover_assets(
    network_range: str = Query(..., description="Network range to scan (e.g., 192.168.1.0/24)"),
    background_tasks: BackgroundTasks = BackgroundTasks(),
    current_user: dict = Depends(get_current_user),
    asset_service: AssetManagementService = Depends(get_asset_service)
):
    """
    Discover assets in specified network range
    
    Performs network scanning to automatically discover:
    - Live hosts and IP addresses
    - Open services and ports
    - Operating system fingerprinting
    - Service version detection
    
    Results are automatically imported into asset inventory
    """
    return await asset_service.discover_assets(network_range)

@router.get("/{asset_id}/services", response_model=List[AssetServiceResponse])
async def get_asset_services(
    asset_id: str,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get all services running on an asset
    
    Returns detailed service information including:
    - Service names and versions
    - Port numbers and protocols
    - Encryption status
    - Risk assessments
    """
    # Get asset
    from app.models.asset_models import Asset, AssetService
    asset = db.query(Asset).filter(Asset.asset_id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    
    # Get services
    services = db.query(AssetService).filter(AssetService.asset_id == asset.id).all()
    return [AssetServiceResponse.from_orm(service) for service in services]

@router.get("/{asset_id}/vulnerabilities", response_model=List[VulnerabilityResponse])
async def get_asset_vulnerabilities(
    asset_id: str,
    severity: Optional[str] = Query(None, description="Filter by severity"),
    status: Optional[str] = Query(None, description="Filter by status"),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get vulnerabilities for an asset
    
    Returns vulnerability information including:
    - CVE identifiers and CVSS scores
    - Severity levels and descriptions
    - Detection and resolution status
    - Remediation guidance
    """
    # Get asset
    from app.models.asset_models import Asset, AssetVulnerability
    asset = db.query(Asset).filter(Asset.asset_id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    
    # Get vulnerabilities
    query = db.query(AssetVulnerability).filter(AssetVulnerability.asset_id == asset.id)
    
    if severity:
        query = query.filter(AssetVulnerability.severity == severity)
    if status:
        query = query.filter(AssetVulnerability.status == status)
    
    vulnerabilities = query.all()
    return [VulnerabilityResponse.from_orm(vuln) for vuln in vulnerabilities]

@router.get("/{asset_id}/compliance", response_model=List[ComplianceCheckResponse])
async def get_asset_compliance(
    asset_id: str,
    framework: Optional[str] = Query(None, description="Filter by compliance framework"),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get compliance check results for an asset
    
    Returns compliance information including:
    - Framework requirements (NIST, SOC2, ISO27001)
    - Control implementation status
    - Evidence and remediation details
    - Next assessment dates
    """
    # Get asset
    from app.models.asset_models import Asset, ComplianceCheck
    asset = db.query(Asset).filter(Asset.asset_id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    
    # Get compliance checks
    query = db.query(ComplianceCheck).filter(ComplianceCheck.asset_id == asset.id)
    
    if framework:
        query = query.filter(ComplianceCheck.framework == framework)
    
    checks = query.all()
    return [ComplianceCheckResponse.from_orm(check) for check in checks]

@router.post("/{asset_id}/risk-assessment")
async def perform_risk_assessment(
    asset_id: str,
    current_user: dict = Depends(get_current_user),
    asset_service: AssetManagementService = Depends(get_asset_service),
    db: Session = Depends(get_db)
):
    """
    Perform comprehensive risk assessment for an asset
    
    Analyzes:
    - Vulnerability exposure
    - Service attack surface
    - Compliance gaps
    - Network positioning
    
    Returns updated risk level and detailed findings
    """
    # Get asset
    from app.models.asset_models import Asset
    asset = db.query(Asset).filter(Asset.asset_id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    
    # Perform risk calculation
    risk_score = 0
    risk_factors = []
    
    # Vulnerability risk
    critical_vulns = db.query("AssetVulnerability").filter_by(
        asset_id=asset.id,
        severity="critical",
        status="open"
    ).count()
    high_vulns = db.query("AssetVulnerability").filter_by(
        asset_id=asset.id,
        severity="high", 
        status="open"
    ).count()
    
    vuln_risk = (critical_vulns * 10) + (high_vulns * 5)
    risk_score += vuln_risk
    risk_factors.append(f"Vulnerability risk: {vuln_risk} (Critical: {critical_vulns}, High: {high_vulns})")
    
    # Service exposure risk
    services = db.query("AssetService").filter_by(asset_id=asset.id).all()
    exposed_services = [s for s in services if not s.is_encrypted]
    service_risk = len(exposed_services) * 2
    risk_score += service_risk
    risk_factors.append(f"Service exposure risk: {service_risk} ({len(exposed_services)} unencrypted services)")
    
    # Determine risk level
    if risk_score >= 50:
        risk_level = RiskLevel.CRITICAL
    elif risk_score >= 30:
        risk_level = RiskLevel.HIGH
    elif risk_score >= 15:
        risk_level = RiskLevel.MEDIUM
    else:
        risk_level = RiskLevel.LOW
    
    # Update asset
    asset.risk_level = risk_level.value
    asset.last_updated = datetime.now()
    db.commit()
    
    return {
        "asset_id": asset_id,
        "risk_level": risk_level.value,
        "risk_score": risk_score,
        "risk_factors": risk_factors,
        "assessment_date": datetime.now().isoformat(),
        "recommendations": [
            "Address critical vulnerabilities immediately" if critical_vulns > 0 else None,
            "Encrypt unencrypted services" if exposed_services else None,
            "Review compliance controls" if asset.compliance_status != ComplianceStatus.COMPLIANT else None
        ]
    }

# Network mapping endpoints
@router.get("/network/topology")
async def get_network_topology(
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get network topology and asset relationships
    
    Returns network mapping data for visualization including:
    - Subnet organization
    - Asset interconnections  
    - Risk distribution across network segments
    """
    from app.models.asset_models import Asset
    
    # Get all active assets
    assets = db.query(Asset).filter(Asset.is_active == True).all()
    
    # Group by subnet
    subnets = {}
    for asset in assets:
        if asset.ip_address:
            # Extract subnet (simplified)
            ip_parts = asset.ip_address.split('.')
            if len(ip_parts) >= 3:
                subnet = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
                if subnet not in subnets:
                    subnets[subnet] = []
                subnets[subnet].append({
                    "asset_id": asset.asset_id,
                    "name": asset.name,
                    "ip_address": asset.ip_address,
                    "asset_type": asset.asset_type,
                    "risk_level": asset.risk_level
                })
    
    return {
        "subnets": subnets,
        "total_assets": len(assets),
        "network_segments": len(subnets),
        "topology_generated": datetime.now().isoformat()
    }