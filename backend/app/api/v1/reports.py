"""
Professional Report Generation API Endpoints
Enterprise-grade reporting system matching industry standards
"""

from fastapi import APIRouter, HTTPException, Depends, Query, Response
from fastapi.responses import FileResponse, StreamingResponse
from typing import List, Dict, Any, Optional
from pathlib import Path
import tempfile
import json
from datetime import datetime
import io

from app.api.v1.auth import get_current_user
from app.services.professional_report_generator import SecurityReportGenerator
from app.db.models import User

router = APIRouter()

# Initialize report generator
report_generator = SecurityReportGenerator()


@router.post("/generate/pdf")
async def generate_pdf_report(
    scan_data: Dict[str, Any],
    report_type: str = "executive",
    template: str = "burpsuite",
    current_user: User = Depends(get_current_user)
):
    """
    Generate professional PDF security report
    Templates: burpsuite, nessus, greenbone, custom
    Types: executive, technical, compliance
    """
    try:
        # Validate report type and template
        valid_types = ["executive", "technical", "compliance", "pentest"]
        valid_templates = ["burpsuite", "nessus", "greenbone", "owasp", "nist", "custom"]
        
        if report_type not in valid_types:
            raise HTTPException(status_code=400, detail=f"Invalid report type. Must be one of: {valid_types}")
        
        if template not in valid_templates:
            raise HTTPException(status_code=400, detail=f"Invalid template. Must be one of: {valid_templates}")
        
        # Generate PDF report
        pdf_buffer = await report_generator.generate_pdf_report(
            scan_data,
            report_type=report_type,
            template=template,
            user_info={
                'name': current_user.username,
                'organization': getattr(current_user, 'organization', 'SecureShield Pro'),
                'email': getattr(current_user, 'email', '')
            }
        )
        
        # Create filename with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"security_report_{report_type}_{template}_{timestamp}.pdf"
        
        return StreamingResponse(
            io.BytesIO(pdf_buffer),
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"PDF generation failed: {str(e)}")


@router.post("/generate/html")
async def generate_html_report(
    scan_data: Dict[str, Any],
    report_type: str = "technical",
    template: str = "modern",
    current_user: User = Depends(get_current_user)
):
    """
    Generate interactive HTML security report
    Templates: modern, dark, light, dashboard
    """
    try:
        # Generate HTML report
        html_content = await report_generator.generate_html_report(
            scan_data,
            report_type=report_type,
            template=template,
            user_info={
                'name': current_user.username,
                'organization': getattr(current_user, 'organization', 'SecureShield Pro')
            }
        )
        
        # Create filename with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"security_report_{report_type}_{timestamp}.html"
        
        return Response(
            content=html_content,
            media_type="text/html",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"HTML generation failed: {str(e)}")


@router.post("/generate/csv")
async def generate_csv_report(
    scan_data: Dict[str, Any],
    include_details: bool = True,
    current_user: User = Depends(get_current_user)
):
    """
    Generate CSV report for data analysis
    """
    try:
        # Generate CSV report
        csv_content = await report_generator.generate_csv_report(
            scan_data,
            include_details=include_details
        )
        
        # Create filename with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"security_findings_{timestamp}.csv"
        
        return Response(
            content=csv_content,
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"CSV generation failed: {str(e)}")


@router.post("/generate/sarif")
async def generate_sarif_report(
    scan_data: Dict[str, Any],
    current_user: User = Depends(get_current_user)
):
    """
    Generate SARIF (Static Analysis Results Interchange Format) report
    Standard format for security tools integration
    """
    try:
        # Generate SARIF report
        sarif_content = await report_generator.generate_sarif_report(scan_data)
        
        # Create filename with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"security_results_{timestamp}.sarif"
        
        return Response(
            content=json.dumps(sarif_content, indent=2),
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"SARIF generation failed: {str(e)}")


@router.post("/generate/json")
async def generate_json_report(
    scan_data: Dict[str, Any],
    format_style: str = "detailed",
    current_user: User = Depends(get_current_user)
):
    """
    Generate JSON report with configurable detail level
    Formats: detailed, summary, compact
    """
    try:
        # Generate JSON report
        json_content = await report_generator.generate_json_report(
            scan_data,
            format_style=format_style
        )
        
        # Create filename with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"security_report_{format_style}_{timestamp}.json"
        
        return Response(
            content=json.dumps(json_content, indent=2),
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"JSON generation failed: {str(e)}")


@router.post("/generate/xml")
async def generate_xml_report(
    scan_data: Dict[str, Any],
    schema: str = "nessus",
    current_user: User = Depends(get_current_user)
):
    """
    Generate XML report in various industry schemas
    Schemas: nessus, openvas, nmap, custom
    """
    try:
        # Generate XML report
        xml_content = await report_generator.generate_xml_report(
            scan_data,
            schema=schema
        )
        
        # Create filename with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"security_report_{schema}_{timestamp}.xml"
        
        return Response(
            content=xml_content,
            media_type="application/xml",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"XML generation failed: {str(e)}")


@router.post("/generate/dashboard")
async def generate_dashboard_report(
    scan_data: Dict[str, Any],
    dashboard_type: str = "executive",
    current_user: User = Depends(get_current_user)
):
    """
    Generate interactive dashboard report
    Types: executive, technical, compliance, metrics
    """
    try:
        # Generate dashboard HTML with embedded charts
        dashboard_content = await report_generator.generate_dashboard_report(
            scan_data,
            dashboard_type=dashboard_type,
            user_info={
                'name': current_user.username,
                'organization': getattr(current_user, 'organization', 'SecureShield Pro')
            }
        )
        
        # Create filename with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"security_dashboard_{dashboard_type}_{timestamp}.html"
        
        return Response(
            content=dashboard_content,
            media_type="text/html",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Dashboard generation failed: {str(e)}")


@router.post("/generate/compliance")
async def generate_compliance_report(
    scan_data: Dict[str, Any],
    framework: str = "nist",
    current_user: User = Depends(get_current_user)
):
    """
    Generate compliance framework report
    Frameworks: nist, iso27001, pci_dss, sox, hipaa, gdpr
    """
    try:
        valid_frameworks = ["nist", "iso27001", "pci_dss", "sox", "hipaa", "gdpr", "cis", "owasp"]
        
        if framework not in valid_frameworks:
            raise HTTPException(
                status_code=400, 
                detail=f"Invalid framework. Must be one of: {valid_frameworks}"
            )
        
        # Generate compliance report
        compliance_content = await report_generator.generate_compliance_report(
            scan_data,
            framework=framework,
            user_info={
                'name': current_user.username,
                'organization': getattr(current_user, 'organization', 'SecureShield Pro')
            }
        )
        
        # Create filename with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"compliance_report_{framework}_{timestamp}.pdf"
        
        return StreamingResponse(
            io.BytesIO(compliance_content),
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Compliance report generation failed: {str(e)}")


@router.get("/templates")
async def get_available_templates(current_user: User = Depends(get_current_user)):
    """Get list of available report templates and formats"""
    return {
        'pdf_templates': ['burpsuite', 'nessus', 'greenbone', 'owasp', 'nist', 'custom'],
        'html_templates': ['modern', 'dark', 'light', 'dashboard', 'minimal'],
        'report_types': ['executive', 'technical', 'compliance', 'pentest'],
        'compliance_frameworks': ['nist', 'iso27001', 'pci_dss', 'sox', 'hipaa', 'gdpr', 'cis', 'owasp'],
        'output_formats': ['pdf', 'html', 'csv', 'json', 'xml', 'sarif'],
        'dashboard_types': ['executive', 'technical', 'compliance', 'metrics']
    }


@router.post("/generate/batch")
async def generate_batch_reports(
    scan_data: Dict[str, Any],
    formats: List[str] = ["pdf", "html", "csv"],
    report_type: str = "technical",
    current_user: User = Depends(get_current_user)
):
    """
    Generate multiple report formats in a single request
    Returns a ZIP file containing all requested formats
    """
    try:
        import zipfile
        import tempfile
        
        # Create temporary directory for batch generation
        temp_dir = tempfile.mkdtemp()
        zip_path = Path(temp_dir) / "security_reports.zip"
        
        with zipfile.ZipFile(zip_path, 'w') as zip_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            for format_type in formats:
                if format_type == "pdf":
                    content = await report_generator.generate_pdf_report(scan_data, report_type)
                    filename = f"security_report_{timestamp}.pdf"
                    zip_file.writestr(filename, content)
                
                elif format_type == "html":
                    content = await report_generator.generate_html_report(scan_data, report_type)
                    filename = f"security_report_{timestamp}.html"
                    zip_file.writestr(filename, content)
                
                elif format_type == "csv":
                    content = await report_generator.generate_csv_report(scan_data)
                    filename = f"security_findings_{timestamp}.csv"
                    zip_file.writestr(filename, content)
                
                elif format_type == "json":
                    content = await report_generator.generate_json_report(scan_data)
                    filename = f"security_report_{timestamp}.json"
                    zip_file.writestr(filename, json.dumps(content, indent=2))
                
                elif format_type == "sarif":
                    content = await report_generator.generate_sarif_report(scan_data)
                    filename = f"security_results_{timestamp}.sarif"
                    zip_file.writestr(filename, json.dumps(content, indent=2))
        
        return FileResponse(
            path=str(zip_path),
            filename=f"security_reports_batch_{timestamp}.zip",
            media_type="application/zip"
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Batch generation failed: {str(e)}")


@router.get("/sample-data")
async def get_sample_report_data(current_user: User = Depends(get_current_user)):
    """Get sample scan data for testing report generation"""
    return {
        'scan_metadata': {
            'scan_id': 'sample_scan_001',
            'timestamp': datetime.now().isoformat(),
            'duration': '00:05:42',
            'target': 'Sample Application',
            'tools_used': ['semgrep', 'bandit', 'safety', 'trivy']
        },
        'vulnerabilities': [
            {
                'id': 'VULN-001',
                'severity': 'HIGH',
                'title': 'SQL Injection Vulnerability',
                'description': 'User input is directly concatenated into SQL queries without proper sanitization',
                'file': 'app/models.py',
                'line': 42,
                'tool': 'semgrep',
                'cwe': 'CWE-89',
                'cvss_score': 8.1,
                'remediation': 'Use parameterized queries or ORM methods'
            },
            {
                'id': 'VULN-002',
                'severity': 'MEDIUM',
                'title': 'Hardcoded API Key',
                'description': 'API key found hardcoded in source code',
                'file': 'config.py',
                'line': 15,
                'tool': 'bandit',
                'cwe': 'CWE-798',
                'cvss_score': 6.5,
                'remediation': 'Move API keys to environment variables'
            },
            {
                'id': 'VULN-003',
                'severity': 'LOW',
                'title': 'Weak Cryptographic Hash',
                'description': 'MD5 hash function is cryptographically weak',
                'file': 'utils.py',
                'line': 28,
                'tool': 'bandit',
                'cwe': 'CWE-327',
                'cvss_score': 3.7,
                'remediation': 'Use SHA-256 or stronger hash functions'
            }
        ],
        'dependencies': [
            {
                'name': 'requests',
                'version': '2.25.1',
                'vulnerability': 'CVE-2023-32681',
                'severity': 'MEDIUM',
                'description': 'Potential security vulnerability in older version'
            }
        ],
        'statistics': {
            'total_files_scanned': 156,
            'total_vulnerabilities': 23,
            'high_severity': 3,
            'medium_severity': 8,
            'low_severity': 12,
            'info_severity': 0
        }
    }