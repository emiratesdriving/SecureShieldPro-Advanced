"""
Security Findings API Endpoints
Comprehensive vulnerability and security findings management
"""

from fastapi import APIRouter, HTTPException, Query, Depends
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/findings", tags=["Security Findings"])

# Mock data for findings (replace with actual database integration)
SAMPLE_FINDINGS = [
    {
        "id": "CVE-2023-12345",
        "title": "SQL Injection Vulnerability",
        "description": "SQL injection vulnerability found in user authentication module",
        "severity": "HIGH",
        "status": "OPEN",
        "affected_asset": "auth-service",
        "discovered_date": "2024-01-15",
        "last_updated": "2024-01-15",
        "remediation": "Use parameterized queries",
        "cvss_score": 7.8,
        "category": "INJECTION"
    },
    {
        "id": "SEC-2024-001",
        "title": "Hardcoded API Key",
        "description": "API key found hardcoded in configuration file",
        "severity": "MEDIUM",
        "status": "IN_PROGRESS",
        "affected_asset": "api-gateway",
        "discovered_date": "2024-01-12",
        "last_updated": "2024-01-14",
        "remediation": "Move API key to environment variable",
        "cvss_score": 5.4,
        "category": "EXPOSURE"
    },
    {
        "id": "XSS-2024-002",
        "title": "Cross-Site Scripting (XSS)",
        "description": "Reflected XSS vulnerability in search functionality",
        "severity": "MEDIUM",
        "status": "RESOLVED",
        "affected_asset": "web-frontend",
        "discovered_date": "2024-01-10",
        "last_updated": "2024-01-13",
        "remediation": "Implement input validation and output encoding",
        "cvss_score": 6.1,
        "category": "XSS"
    },
    {
        "id": "AUTH-2024-003",
        "title": "Weak Password Policy",
        "description": "Password policy allows weak passwords",
        "severity": "LOW",
        "status": "OPEN",
        "affected_asset": "user-management",
        "discovered_date": "2024-01-08",
        "last_updated": "2024-01-08",
        "remediation": "Implement stronger password requirements",
        "cvss_score": 3.2,
        "category": "AUTHENTICATION"
    },
    {
        "id": "CRYPTO-2024-004",
        "title": "Weak Cryptographic Algorithm",
        "description": "Use of deprecated MD5 hash algorithm",
        "severity": "HIGH",
        "status": "OPEN",
        "affected_asset": "payment-service",
        "discovered_date": "2024-01-05",
        "last_updated": "2024-01-05",
        "remediation": "Replace MD5 with SHA-256 or better",
        "cvss_score": 7.5,
        "category": "CRYPTOGRAPHY"
    }
]

@router.get("/")
async def get_security_findings(
    severity: Optional[str] = None,
    status: Optional[str] = None,
    category: Optional[str] = None,
    limit: int = Query(default=50, le=100)
) -> Dict[str, Any]:
    """
    Get security findings with optional filtering
    """
    try:
        findings = SAMPLE_FINDINGS.copy()
        
        # Apply filters
        if severity:
            findings = [f for f in findings if f["severity"] == severity.upper()]
        
        if status:
            findings = [f for f in findings if f["status"] == status.upper()]
        
        if category:
            findings = [f for f in findings if f["category"] == category.upper()]
        
        # Sort by severity and date
        severity_order = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
        findings.sort(key=lambda x: (severity_order.get(x["severity"], 0), x["discovered_date"]), reverse=True)
        
        # Apply limit
        findings = findings[:limit]
        
        # Calculate statistics
        total_findings = len(SAMPLE_FINDINGS)
        high_severity = len([f for f in SAMPLE_FINDINGS if f["severity"] == "HIGH"])
        medium_severity = len([f for f in SAMPLE_FINDINGS if f["severity"] == "MEDIUM"])
        low_severity = len([f for f in SAMPLE_FINDINGS if f["severity"] == "LOW"])
        open_findings = len([f for f in SAMPLE_FINDINGS if f["status"] == "OPEN"])
        
        return {
            "status": "success",
            "findings": findings,
            "statistics": {
                "total_findings": total_findings,
                "high_severity": high_severity,
                "medium_severity": medium_severity,
                "low_severity": low_severity,
                "open_findings": open_findings,
                "resolution_rate": ((total_findings - open_findings) / total_findings * 100) if total_findings > 0 else 0
            }
        }
        
    except Exception as e:
        logger.error(f"Failed to get security findings: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to get security findings: {str(e)}")

@router.get("/{finding_id}")
async def get_finding_details(finding_id: str) -> Dict[str, Any]:
    """
    Get detailed information about a specific finding
    """
    try:
        finding = next((f for f in SAMPLE_FINDINGS if f["id"] == finding_id), None)
        
        if not finding:
            raise HTTPException(status_code=404, detail="Finding not found")
        
        # Add detailed information
        detailed_finding = {
            **finding,
            "technical_details": {
                "affected_endpoints": ["/api/login", "/api/register"],
                "proof_of_concept": "' OR '1'='1' -- ",
                "impact_assessment": "Potential unauthorized access to user accounts",
                "exploitation_complexity": "Low"
            },
            "remediation_steps": [
                "Use parameterized queries or prepared statements",
                "Implement input validation",
                "Apply principle of least privilege to database users",
                "Regular security testing"
            ],
            "references": [
                "https://owasp.org/www-project-top-ten/2017/A1_2017-Injection",
                "https://cwe.mitre.org/data/definitions/89.html"
            ]
        }
        
        return {
            "status": "success",
            "finding": detailed_finding
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get finding details: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to get finding details: {str(e)}")

@router.put("/{finding_id}/status")
async def update_finding_status(
    finding_id: str,
    status: str,
    resolution_notes: Optional[str] = None
) -> Dict[str, Any]:
    """
    Update the status of a security finding
    """
    try:
        # Find the finding in our mock data
        finding_index = next((i for i, f in enumerate(SAMPLE_FINDINGS) if f["id"] == finding_id), None)
        
        if finding_index is None:
            raise HTTPException(status_code=404, detail="Finding not found")
        
        # Update status
        SAMPLE_FINDINGS[finding_index]["status"] = status.upper()
        SAMPLE_FINDINGS[finding_index]["last_updated"] = datetime.now().strftime("%Y-%m-%d")
        
        if resolution_notes:
            SAMPLE_FINDINGS[finding_index]["resolution_notes"] = resolution_notes
        
        return {
            "status": "updated",
            "finding_id": finding_id,
            "new_status": status.upper(),
            "resolution_notes": resolution_notes
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update finding status: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to update finding status: {str(e)}")

@router.get("/analytics/dashboard")
async def get_findings_dashboard() -> Dict[str, Any]:
    """
    Get dashboard analytics for security findings
    """
    try:
        # Calculate trending data
        now = datetime.now()
        last_week = now - timedelta(days=7)
        last_month = now - timedelta(days=30)
        
        # Simulate trending data
        trending_vulnerabilities = [
            {"name": "SQL Injection", "count": 12, "trend": "+25%"},
            {"name": "XSS", "count": 8, "trend": "-10%"},
            {"name": "Authentication Issues", "count": 6, "trend": "+15%"},
            {"name": "Cryptographic Issues", "count": 4, "trend": "+5%"}
        ]
        
        severity_distribution = {
            "HIGH": len([f for f in SAMPLE_FINDINGS if f["severity"] == "HIGH"]),
            "MEDIUM": len([f for f in SAMPLE_FINDINGS if f["severity"] == "MEDIUM"]),
            "LOW": len([f for f in SAMPLE_FINDINGS if f["severity"] == "LOW"])
        }
        
        category_distribution = {}
        for finding in SAMPLE_FINDINGS:
            category = finding["category"]
            if category not in category_distribution:
                category_distribution[category] = 0
            category_distribution[category] += 1
        
        return {
            "status": "success",
            "dashboard": {
                "total_findings": len(SAMPLE_FINDINGS),
                "open_findings": len([f for f in SAMPLE_FINDINGS if f["status"] == "OPEN"]),
                "resolved_findings": len([f for f in SAMPLE_FINDINGS if f["status"] == "RESOLVED"]),
                "in_progress_findings": len([f for f in SAMPLE_FINDINGS if f["status"] == "IN_PROGRESS"]),
                "severity_distribution": severity_distribution,
                "category_distribution": category_distribution,
                "trending_vulnerabilities": trending_vulnerabilities,
                "mean_time_to_resolution": "5.2 days",
                "critical_findings_percentage": (severity_distribution["HIGH"] / len(SAMPLE_FINDINGS) * 100) if SAMPLE_FINDINGS else 0
            }
        }
        
    except Exception as e:
        logger.error(f"Failed to get findings dashboard: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to get findings dashboard: {str(e)}")

@router.post("/bulk-update")
async def bulk_update_findings(
    finding_ids: List[str],
    status: str,
    resolution_notes: Optional[str] = None
) -> Dict[str, Any]:
    """
    Update multiple findings at once
    """
    try:
        updated_count = 0
        
        for finding_id in finding_ids:
            finding_index = next((i for i, f in enumerate(SAMPLE_FINDINGS) if f["id"] == finding_id), None)
            
            if finding_index is not None:
                SAMPLE_FINDINGS[finding_index]["status"] = status.upper()
                SAMPLE_FINDINGS[finding_index]["last_updated"] = datetime.now().strftime("%Y-%m-%d")
                
                if resolution_notes:
                    SAMPLE_FINDINGS[finding_index]["resolution_notes"] = resolution_notes
                
                updated_count += 1
        
        return {
            "status": "success",
            "updated_count": updated_count,
            "total_requested": len(finding_ids),
            "new_status": status.upper()
        }
        
    except Exception as e:
        logger.error(f"Failed to bulk update findings: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to bulk update findings: {str(e)}")

@router.get("/export/csv")
async def export_findings_csv() -> Dict[str, Any]:
    """
    Export findings to CSV format
    """
    try:
        # In a real implementation, you would generate actual CSV content
        csv_data = "ID,Title,Severity,Status,Category,CVSS Score,Discovered Date\n"
        
        for finding in SAMPLE_FINDINGS:
            csv_data += f"{finding['id']},{finding['title']},{finding['severity']},{finding['status']},{finding['category']},{finding['cvss_score']},{finding['discovered_date']}\n"
        
        return {
            "status": "success",
            "export_format": "CSV",
            "data": csv_data,
            "filename": f"security_findings_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        }
        
    except Exception as e:
        logger.error(f"Failed to export findings: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to export findings: {str(e)}")

@router.get("/health")
async def health_check() -> Dict[str, Any]:
    """
    Health check for findings service
    """
    return {
        "status": "healthy",
        "service": "security_findings",
        "findings_loaded": len(SAMPLE_FINDINGS),
        "timestamp": datetime.now().isoformat()
    }