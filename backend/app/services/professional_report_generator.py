"""
Professional Security Report Generator
Generates detailed security reports in multiple formats (PDF, HTML, CSV) 
Similar to industry tools like BurpSuite Pro, Nessus, Greenbone, etc.
"""

import os
import json
import asyncio
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, asdict
from enum import Enum
import base64
import io

# PDF Generation
try:
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.colors import HexColor, red, orange, yellow, green, blue, black, white
    from reportlab.lib.units import inch
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image
    from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT, TA_JUSTIFY
    from reportlab.graphics.shapes import Drawing, Rect
    from reportlab.graphics.charts.piecharts import Pie
    from reportlab.graphics.charts.barcharts import VerticalBarChart
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False
    # Create mock classes for type hints when ReportLab is not available
    class HexColor:
        def __init__(self, color_str: str):
            self.color_str = color_str

# HTML Template Engine
try:
    from jinja2 import Template, Environment, FileSystemLoader
    JINJA2_AVAILABLE = True
except ImportError:
    JINJA2_AVAILABLE = False

import csv
import xml.etree.ElementTree as ET
from xml.dom import minidom

logger = logging.getLogger(__name__)

class ReportFormat(Enum):
    """Supported report output formats"""
    PDF = "pdf"
    HTML = "html"
    CSV = "csv"
    JSON = "json"
    XML = "xml"
    SARIF = "sarif"  # Static Analysis Results Interchange Format
    JUNIT = "junit"   # JUnit XML for CI/CD integration

class ReportTemplate(Enum):
    """Professional report templates"""
    EXECUTIVE_SUMMARY = "executive"
    TECHNICAL_DETAILED = "technical"
    COMPLIANCE_AUDIT = "compliance"
    PENETRATION_TEST = "pentest"
    VULNERABILITY_ASSESSMENT = "vuln_assessment"
    CODE_REVIEW = "code_review"
    INCIDENT_RESPONSE = "incident"

@dataclass
class ReportMetadata:
    """Report metadata and configuration"""
    title: str
    subtitle: str = ""
    organization: str = "SecureShield Pro"
    analyst: str = "Security Team"
    scan_date: Optional[datetime] = None
    report_date: Optional[datetime] = None
    classification: str = "CONFIDENTIAL"
    version: str = "1.0"
    template: ReportTemplate = ReportTemplate.TECHNICAL_DETAILED
    include_charts: bool = True
    include_remediation: bool = True
    include_executive_summary: bool = True
    logo_path: Optional[str] = None

@dataclass
class VulnerabilityData:
    """Standardized vulnerability data for reporting"""
    id: str
    title: str
    description: str
    severity: str
    cvss_score: Optional[float]
    cve_id: Optional[str]
    cwe_id: Optional[str]
    file_path: str
    line_number: Optional[int]
    tool_detected: str
    remediation: str
    references: List[str]
    evidence: Dict[str, Any]
    first_detected: datetime
    status: str = "Open"

@dataclass
class ScanStatistics:
    """Scan statistics for reporting"""
    total_files_scanned: int
    total_vulnerabilities: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    false_positive_count: int
    scan_duration: float
    tools_used: List[str]
    file_types_scanned: List[str]

class SecurityReportGenerator:
    """Professional security report generator"""
    
    def __init__(self):
        self.templates_dir = Path(__file__).parent / "report_templates"
        self.templates_dir.mkdir(exist_ok=True)
        self.create_default_templates()
        
    def create_default_templates(self):
        """Create default HTML templates"""
        executive_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ metadata.title }} - Executive Summary</title>
    <style>
        {{ css_styles }}
    </style>
</head>
<body>
    <div class="header">
        <img src="{{ metadata.logo_path or 'logo.png' }}" alt="Logo" class="logo">
        <h1>{{ metadata.title }}</h1>
        <p class="classification">{{ metadata.classification }}</p>
    </div>
    
    <div class="executive-summary">
        <h2>Executive Summary</h2>
        <div class="summary-stats">
            <div class="stat-box critical">
                <h3>{{ statistics.critical_count }}</h3>
                <p>Critical</p>
            </div>
            <div class="stat-box high">
                <h3>{{ statistics.high_count }}</h3>
                <p>High</p>
            </div>
            <div class="stat-box medium">
                <h3>{{ statistics.medium_count }}</h3>
                <p>Medium</p>
            </div>
            <div class="stat-box low">
                <h3>{{ statistics.low_count }}</h3>
                <p>Low</p>
            </div>
        </div>
        
        <div class="key-findings">
            <h3>Key Security Findings</h3>
            {% for vuln in critical_vulnerabilities[:5] %}
            <div class="finding-item critical">
                <h4>{{ vuln.title }}</h4>
                <p>{{ vuln.description }}</p>
                <p><strong>Risk:</strong> {{ vuln.severity }} | <strong>CVSS:</strong> {{ vuln.cvss_score or 'N/A' }}</p>
            </div>
            {% endfor %}
        </div>
    </div>
    
    <div class="recommendations">
        <h2>Immediate Actions Required</h2>
        <ol>
            {% for recommendation in priority_recommendations %}
            <li>{{ recommendation }}</li>
            {% endfor %}
        </ol>
    </div>
</body>
</html>
        """
        
        technical_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ metadata.title }} - Technical Report</title>
    <style>
        {{ css_styles }}
    </style>
</head>
<body>
    <div class="header">
        <img src="{{ metadata.logo_path or 'logo.png' }}" alt="Logo" class="logo">
        <h1>{{ metadata.title }}</h1>
        <p class="classification">{{ metadata.classification }}</p>
        <div class="metadata">
            <p><strong>Analyst:</strong> {{ metadata.analyst }}</p>
            <p><strong>Scan Date:</strong> {{ metadata.scan_date.strftime('%Y-%m-%d %H:%M:%S') }}</p>
            <p><strong>Report Date:</strong> {{ metadata.report_date.strftime('%Y-%m-%d %H:%M:%S') }}</p>
        </div>
    </div>
    
    <div class="toc">
        <h2>Table of Contents</h2>
        <ul>
            <li><a href="#summary">Executive Summary</a></li>
            <li><a href="#methodology">Methodology</a></li>
            <li><a href="#findings">Detailed Findings</a></li>
            <li><a href="#recommendations">Recommendations</a></li>
            <li><a href="#appendix">Appendix</a></li>
        </ul>
    </div>
    
    <div id="summary" class="section">
        <h2>Executive Summary</h2>
        <div class="summary-stats">
            <table class="stats-table">
                <tr>
                    <th>Metric</th>
                    <th>Count</th>
                </tr>
                <tr>
                    <td>Files Scanned</td>
                    <td>{{ statistics.total_files_scanned }}</td>
                </tr>
                <tr>
                    <td>Total Vulnerabilities</td>
                    <td>{{ statistics.total_vulnerabilities }}</td>
                </tr>
                <tr class="critical">
                    <td>Critical</td>
                    <td>{{ statistics.critical_count }}</td>
                </tr>
                <tr class="high">
                    <td>High</td>
                    <td>{{ statistics.high_count }}</td>
                </tr>
                <tr class="medium">
                    <td>Medium</td>
                    <td>{{ statistics.medium_count }}</td>
                </tr>
                <tr class="low">
                    <td>Low</td>
                    <td>{{ statistics.low_count }}</td>
                </tr>
            </table>
        </div>
    </div>
    
    <div id="methodology" class="section">
        <h2>Methodology</h2>
        <h3>Tools Used</h3>
        <ul>
            {% for tool in statistics.tools_used %}
            <li>{{ tool }}</li>
            {% endfor %}
        </ul>
        
        <h3>File Types Analyzed</h3>
        <ul>
            {% for file_type in statistics.file_types_scanned %}
            <li>{{ file_type }}</li>
            {% endfor %}
        </ul>
        
        <p><strong>Scan Duration:</strong> {{ "%.2f"|format(statistics.scan_duration) }} seconds</p>
    </div>
    
    <div id="findings" class="section">
        <h2>Detailed Findings</h2>
        {% for vuln in vulnerabilities %}
        <div class="vulnerability {{ vuln.severity.lower() }}">
            <h3>{{ vuln.title }} <span class="severity-badge {{ vuln.severity.lower() }}">{{ vuln.severity }}</span></h3>
            
            <div class="vuln-details">
                <table>
                    <tr>
                        <td><strong>File:</strong></td>
                        <td>{{ vuln.file_path }}</td>
                    </tr>
                    {% if vuln.line_number %}
                    <tr>
                        <td><strong>Line:</strong></td>
                        <td>{{ vuln.line_number }}</td>
                    </tr>
                    {% endif %}
                    <tr>
                        <td><strong>Tool:</strong></td>
                        <td>{{ vuln.tool_detected }}</td>
                    </tr>
                    {% if vuln.cvss_score %}
                    <tr>
                        <td><strong>CVSS Score:</strong></td>
                        <td>{{ vuln.cvss_score }}</td>
                    </tr>
                    {% endif %}
                    {% if vuln.cve_id %}
                    <tr>
                        <td><strong>CVE:</strong></td>
                        <td><a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name={{ vuln.cve_id }}">{{ vuln.cve_id }}</a></td>
                    </tr>
                    {% endif %}
                    {% if vuln.cwe_id %}
                    <tr>
                        <td><strong>CWE:</strong></td>
                        <td><a href="https://cwe.mitre.org/data/definitions/{{ vuln.cwe_id.replace('CWE-', '') }}.html">{{ vuln.cwe_id }}</a></td>
                    </tr>
                    {% endif %}
                </table>
            </div>
            
            <div class="description">
                <h4>Description</h4>
                <p>{{ vuln.description }}</p>
            </div>
            
            <div class="remediation">
                <h4>Remediation</h4>
                <p>{{ vuln.remediation }}</p>
            </div>
            
            {% if vuln.references %}
            <div class="references">
                <h4>References</h4>
                <ul>
                    {% for ref in vuln.references %}
                    <li><a href="{{ ref }}">{{ ref }}</a></li>
                    {% endfor %}
                </ul>
            </div>
            {% endif %}
        </div>
        {% endfor %}
    </div>
</body>
</html>
        """
        
        css_styles = """
        body {
            font-family: 'Arial', sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            color: #333;
        }
        
        .header {
            border-bottom: 3px solid #2c3e50;
            padding-bottom: 20px;
            margin-bottom: 30px;
            text-align: center;
        }
        
        .logo {
            height: 60px;
            margin-bottom: 10px;
        }
        
        .classification {
            background: #e74c3c;
            color: white;
            padding: 5px 15px;
            display: inline-block;
            border-radius: 3px;
            font-weight: bold;
        }
        
        .summary-stats {
            display: flex;
            justify-content: space-around;
            margin: 20px 0;
        }
        
        .stat-box {
            text-align: center;
            padding: 20px;
            border-radius: 8px;
            color: white;
            min-width: 100px;
        }
        
        .stat-box.critical { background: #e74c3c; }
        .stat-box.high { background: #e67e22; }
        .stat-box.medium { background: #f39c12; }
        .stat-box.low { background: #27ae60; }
        
        .vulnerability {
            border: 1px solid #ddd;
            margin: 20px 0;
            border-radius: 8px;
            overflow: hidden;
        }
        
        .vulnerability.critical { border-left: 5px solid #e74c3c; }
        .vulnerability.high { border-left: 5px solid #e67e22; }
        .vulnerability.medium { border-left: 5px solid #f39c12; }
        .vulnerability.low { border-left: 5px solid #27ae60; }
        
        .vulnerability h3 {
            background: #f8f9fa;
            margin: 0;
            padding: 15px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .severity-badge {
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: bold;
            text-transform: uppercase;
        }
        
        .severity-badge.critical { background: #e74c3c; color: white; }
        .severity-badge.high { background: #e67e22; color: white; }
        .severity-badge.medium { background: #f39c12; color: white; }
        .severity-badge.low { background: #27ae60; color: white; }
        
        .vuln-details {
            padding: 15px;
        }
        
        .vuln-details table {
            width: 100%;
            border-collapse: collapse;
        }
        
        .vuln-details td {
            padding: 5px 0;
            border-bottom: 1px solid #eee;
        }
        
        .description, .remediation, .references {
            padding: 15px;
            border-top: 1px solid #eee;
        }
        
        .stats-table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }
        
        .stats-table th, .stats-table td {
            border: 1px solid #ddd;
            padding: 8px;
            text-align: left;
        }
        
        .stats-table th {
            background: #f2f2f2;
        }
        
        .stats-table tr.critical { background: #fdf2f2; }
        .stats-table tr.high { background: #fef7f0; }
        .stats-table tr.medium { background: #fffbf0; }
        .stats-table tr.low { background: #f0fdf4; }
        
        .section {
            margin: 40px 0;
        }
        
        .toc ul {
            list-style-type: none;
            padding-left: 0;
        }
        
        .toc li {
            margin: 5px 0;
        }
        
        .toc a {
            color: #2c3e50;
            text-decoration: none;
        }
        
        .toc a:hover {
            text-decoration: underline;
        }
        
        @media print {
            body { font-size: 12px; }
            .vulnerability { page-break-inside: avoid; }
        }
        """
        
        # Save templates
        with open(self.templates_dir / "executive.html", "w") as f:
            f.write(executive_template)
        
        with open(self.templates_dir / "technical.html", "w") as f:
            f.write(technical_template)
        
        with open(self.templates_dir / "styles.css", "w") as f:
            f.write(css_styles)
    
    async def generate_report(
        self,
        vulnerabilities: List[VulnerabilityData],
        statistics: ScanStatistics,
        metadata: ReportMetadata,
        output_format: ReportFormat,
        output_path: str
    ) -> str:
        """Generate a professional security report"""
        
        if metadata.report_date is None:
            metadata.report_date = datetime.now(timezone.utc)
        
        if output_format == ReportFormat.PDF:
            return await self._generate_pdf_report(vulnerabilities, statistics, metadata, output_path)
        elif output_format == ReportFormat.HTML:
            return await self._generate_html_report(vulnerabilities, statistics, metadata, output_path)
        elif output_format == ReportFormat.CSV:
            return await self._generate_csv_report(vulnerabilities, statistics, metadata, output_path)
        elif output_format == ReportFormat.JSON:
            return await self._generate_json_report(vulnerabilities, statistics, metadata, output_path)
        elif output_format == ReportFormat.XML:
            return await self._generate_xml_report(vulnerabilities, statistics, metadata, output_path)
        elif output_format == ReportFormat.SARIF:
            return await self._generate_sarif_report(vulnerabilities, statistics, metadata, output_path)
        else:
            raise ValueError(f"Unsupported report format: {output_format}")

    # API convenience methods for FastAPI endpoints
    async def generate_pdf_report(self, scan_data: Dict[str, Any], report_type: str = "technical", template: str = "burpsuite", user_info: Optional[Dict[str, str]] = None) -> bytes:
        """Generate PDF report from scan data"""
        vulnerabilities, statistics, metadata = self._parse_scan_data(scan_data, user_info, report_type)
        
        # Create temp file for PDF generation
        import tempfile
        with tempfile.NamedTemporaryFile(suffix='.pdf', delete=False) as tmp_file:
            output_path = tmp_file.name
        
        await self._generate_pdf_report(vulnerabilities, statistics, metadata, output_path)
        
        # Read the generated PDF file
        with open(output_path, 'rb') as f:
            pdf_content = f.read()
        
        # Cleanup temp file
        os.unlink(output_path)
        return pdf_content

    async def generate_html_report(self, scan_data: Dict[str, Any], report_type: str = "technical", template: str = "modern", user_info: Optional[Dict[str, str]] = None) -> str:
        """Generate HTML report from scan data"""
        vulnerabilities, statistics, metadata = self._parse_scan_data(scan_data, user_info, report_type)
        
        # Create temp file for HTML generation
        import tempfile
        with tempfile.NamedTemporaryFile(suffix='.html', delete=False) as tmp_file:
            output_path = tmp_file.name
        
        await self._generate_html_report(vulnerabilities, statistics, metadata, output_path)
        
        # Read the generated HTML file
        with open(output_path, 'r', encoding='utf-8') as f:
            html_content = f.read()
        
        # Cleanup temp file
        os.unlink(output_path)
        return html_content

    async def generate_csv_report(self, scan_data: Dict[str, Any], include_details: bool = True) -> str:
        """Generate CSV report from scan data"""
        vulnerabilities, statistics, metadata = self._parse_scan_data(scan_data)
        
        # Create temp file for CSV generation
        import tempfile
        with tempfile.NamedTemporaryFile(suffix='.csv', delete=False) as tmp_file:
            output_path = tmp_file.name
        
        await self._generate_csv_report(vulnerabilities, statistics, metadata, output_path)
        
        # Read the generated CSV file
        with open(output_path, 'r', encoding='utf-8') as f:
            csv_content = f.read()
        
        # Cleanup temp file
        os.unlink(output_path)
        return csv_content

    async def generate_json_report(self, scan_data: Dict[str, Any], format_style: str = "detailed") -> Dict[str, Any]:
        """Generate JSON report from scan data"""
        vulnerabilities, statistics, metadata = self._parse_scan_data(scan_data)
        
        # Create temp file for JSON generation
        import tempfile
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as tmp_file:
            output_path = tmp_file.name
        
        await self._generate_json_report(vulnerabilities, statistics, metadata, output_path)
        
        # Read the generated JSON file
        with open(output_path, 'r', encoding='utf-8') as f:
            json_content = json.load(f)
        
        # Cleanup temp file
        os.unlink(output_path)
        return json_content

    async def generate_sarif_report(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate SARIF report from scan data"""
        vulnerabilities, statistics, metadata = self._parse_scan_data(scan_data)
        
        # Create temp file for SARIF generation
        import tempfile
        with tempfile.NamedTemporaryFile(suffix='.sarif', delete=False) as tmp_file:
            output_path = tmp_file.name
        
        await self._generate_sarif_report(vulnerabilities, statistics, metadata, output_path)
        
        # Read the generated SARIF file
        with open(output_path, 'r', encoding='utf-8') as f:
            sarif_content = json.load(f)
        
        # Cleanup temp file
        os.unlink(output_path)
        return sarif_content

    async def generate_xml_report(self, scan_data: Dict[str, Any], schema: str = "nessus") -> str:
        """Generate XML report from scan data"""
        vulnerabilities, statistics, metadata = self._parse_scan_data(scan_data)
        
        # Create temp file for XML generation
        import tempfile
        with tempfile.NamedTemporaryFile(suffix='.xml', delete=False) as tmp_file:
            output_path = tmp_file.name
        
        await self._generate_xml_report(vulnerabilities, statistics, metadata, output_path)
        
        # Read the generated XML file
        with open(output_path, 'r', encoding='utf-8') as f:
            xml_content = f.read()
        
        # Cleanup temp file
        os.unlink(output_path)
        return xml_content

    async def generate_dashboard_report(self, scan_data: Dict[str, Any], dashboard_type: str = "executive", user_info: Optional[Dict[str, str]] = None) -> str:
        """Generate interactive dashboard report"""
        # Use HTML report with dashboard template
        return await self.generate_html_report(scan_data, dashboard_type, "dashboard", user_info)

    async def generate_compliance_report(self, scan_data: Dict[str, Any], framework: str = "nist", user_info: Optional[Dict[str, str]] = None) -> bytes:
        """Generate compliance framework report"""
        # Use PDF report with compliance template
        return await self.generate_pdf_report(scan_data, "compliance", framework, user_info)

    def _parse_scan_data(self, scan_data: Dict[str, Any], user_info: Optional[Dict[str, str]] = None, report_type: str = "technical") -> tuple[List[VulnerabilityData], ScanStatistics, ReportMetadata]:
        """Parse scan data into report components"""
        # Extract vulnerabilities
        vulnerabilities = []
        for vuln_data in scan_data.get('vulnerabilities', []):
            vuln = VulnerabilityData(
                id=vuln_data.get('id', ''),
                title=vuln_data.get('title', ''),
                severity=vuln_data.get('severity', 'UNKNOWN'),
                description=vuln_data.get('description', ''),
                file_path=vuln_data.get('file', ''),
                line_number=vuln_data.get('line', 0),
                cvss_score=vuln_data.get('cvss_score', 0.0),
                cve_id=vuln_data.get('cve', ''),
                cwe_id=vuln_data.get('cwe', ''),
                remediation=vuln_data.get('remediation', ''),
                tool_detected=vuln_data.get('tool', 'Unknown'),
                references=vuln_data.get('references', []),
                evidence={},
                first_detected=datetime.now(timezone.utc)
            )
            vulnerabilities.append(vuln)
        
        # Extract statistics
        stats_data = scan_data.get('statistics', {})
        statistics = ScanStatistics(
            total_files_scanned=stats_data.get('total_files_scanned', 0),
            total_vulnerabilities=stats_data.get('total_vulnerabilities', len(vulnerabilities)),
            critical_count=stats_data.get('critical_severity', 0),
            high_count=stats_data.get('high_severity', 0),
            medium_count=stats_data.get('medium_severity', 0),
            low_count=stats_data.get('low_severity', 0),
            info_count=stats_data.get('info_severity', 0),
            false_positive_count=0,
            scan_duration=stats_data.get('scan_duration_seconds', 0),
            tools_used=scan_data.get('tools_used', []),
            file_types_scanned=[]
        )
        
        # Create metadata
        metadata = ReportMetadata(
            title=scan_data.get('scan_metadata', {}).get('target', 'Security Assessment Report'),
            organization=user_info.get('organization', 'SecureShield Pro') if user_info else 'SecureShield Pro',
            analyst=user_info.get('name', 'SecureShield Pro') if user_info else 'SecureShield Pro',
            scan_date=datetime.now(timezone.utc),
            report_date=datetime.now(timezone.utc)
        )
        
        return vulnerabilities, statistics, metadata
    
    async def _generate_pdf_report(
        self,
        vulnerabilities: List[VulnerabilityData],
        statistics: ScanStatistics,
        metadata: ReportMetadata,
        output_path: str
    ) -> str:
        """Generate PDF report using ReportLab"""
        
        if not PDF_AVAILABLE:
            raise ImportError("ReportLab not available. Install with: pip install reportlab")
        
        doc = SimpleDocTemplate(output_path, pagesize=A4)
        styles = getSampleStyleSheet()
        story = []
        
        # Custom styles
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            alignment=TA_CENTER,
            textColor=HexColor('#2c3e50')
        )
        
        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=16,
            spaceAfter=12,
            textColor=HexColor('#34495e')
        )
        
        # Title Page
        story.append(Paragraph(metadata.title, title_style))
        story.append(Spacer(1, 0.5*inch))
        story.append(Paragraph(f"<b>Organization:</b> {metadata.organization}", styles['Normal']))
        story.append(Paragraph(f"<b>Analyst:</b> {metadata.analyst}", styles['Normal']))
        story.append(Paragraph(f"<b>Report Date:</b> {metadata.report_date.strftime('%Y-%m-%d') if metadata.report_date else datetime.now(timezone.utc).strftime('%Y-%m-%d')}", styles['Normal']))
        story.append(Paragraph(f"<b>Classification:</b> {metadata.classification}", styles['Normal']))
        story.append(PageBreak())
        
        # Executive Summary
        story.append(Paragraph("Executive Summary", heading_style))
        
        # Statistics Table
        stats_data = [
            ['Metric', 'Count'],
            ['Total Files Scanned', str(statistics.total_files_scanned)],
            ['Total Vulnerabilities', str(statistics.total_vulnerabilities)],
            ['Critical', str(statistics.critical_count)],
            ['High', str(statistics.high_count)],
            ['Medium', str(statistics.medium_count)],
            ['Low', str(statistics.low_count)]
        ]
        
        stats_table = Table(stats_data, colWidths=[3*inch, 1*inch])
        stats_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), HexColor('#34495e')),
            ('TEXTCOLOR', (0, 0), (-1, 0), white),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), HexColor('#ecf0f1')),
            ('GRID', (0, 0), (-1, -1), 1, black)
        ]))
        
        story.append(stats_table)
        story.append(Spacer(1, 0.3*inch))
        
        # Vulnerability Details
        story.append(Paragraph("Vulnerability Details", heading_style))
        
        for vuln in vulnerabilities:
            # Vulnerability header
            severity_color = self._get_severity_color(vuln.severity)
            vuln_title = f"<b>{vuln.title}</b> ({vuln.severity})"
            story.append(Paragraph(vuln_title, styles['Heading3']))
            
            # Vulnerability details table
            vuln_data = [
                ['File', vuln.file_path],
                ['Line', str(vuln.line_number) if vuln.line_number else 'N/A'],
                ['Tool', vuln.tool_detected],
                ['CVSS Score', str(vuln.cvss_score) if vuln.cvss_score else 'N/A'],
                ['CVE ID', vuln.cve_id or 'N/A'],
                ['CWE ID', vuln.cwe_id or 'N/A']
            ]
            
            vuln_table = Table(vuln_data, colWidths=[1.5*inch, 4*inch])
            vuln_table.setStyle(TableStyle([
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('GRID', (0, 0), (-1, -1), 1, black)
            ]))
            
            story.append(vuln_table)
            story.append(Spacer(1, 0.1*inch))
            
            # Description
            story.append(Paragraph("<b>Description:</b>", styles['Normal']))
            story.append(Paragraph(vuln.description, styles['Normal']))
            story.append(Spacer(1, 0.1*inch))
            
            # Remediation
            story.append(Paragraph("<b>Remediation:</b>", styles['Normal']))
            story.append(Paragraph(vuln.remediation, styles['Normal']))
            story.append(Spacer(1, 0.2*inch))
        
        # Build PDF
        doc.build(story)
        return output_path
    
    async def _generate_html_report(
        self,
        vulnerabilities: List[VulnerabilityData],
        statistics: ScanStatistics,
        metadata: ReportMetadata,
        output_path: str
    ) -> str:
        """Generate HTML report using Jinja2 templates"""
        
        if JINJA2_AVAILABLE:
            env = Environment(loader=FileSystemLoader(self.templates_dir))
            
            if metadata.template == ReportTemplate.EXECUTIVE_SUMMARY:
                template = env.get_template('executive.html')
            else:
                template = env.get_template('technical.html')
            
            # Prepare template data
            critical_vulnerabilities = [v for v in vulnerabilities if v.severity == 'CRITICAL']
            priority_recommendations = self._generate_priority_recommendations(vulnerabilities)
            
            # Read CSS styles
            with open(self.templates_dir / "styles.css", "r") as f:
                css_styles = f.read()
            
            html_content = template.render(
                vulnerabilities=vulnerabilities,
                statistics=statistics,
                metadata=metadata,
                critical_vulnerabilities=critical_vulnerabilities,
                priority_recommendations=priority_recommendations,
                css_styles=css_styles
            )
        else:
            # Fallback simple HTML generation
            html_content = self._generate_simple_html(vulnerabilities, statistics, metadata)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return output_path
    
    async def _generate_csv_report(
        self,
        vulnerabilities: List[VulnerabilityData],
        statistics: ScanStatistics,
        metadata: ReportMetadata,
        output_path: str
    ) -> str:
        """Generate CSV report for data analysis"""
        
        with open(output_path, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = [
                'ID', 'Title', 'Severity', 'CVSS_Score', 'CVE_ID', 'CWE_ID',
                'File_Path', 'Line_Number', 'Tool_Detected', 'Description',
                'Remediation', 'Status', 'First_Detected'
            ]
            
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            for vuln in vulnerabilities:
                writer.writerow({
                    'ID': vuln.id,
                    'Title': vuln.title,
                    'Severity': vuln.severity,
                    'CVSS_Score': vuln.cvss_score,
                    'CVE_ID': vuln.cve_id,
                    'CWE_ID': vuln.cwe_id,
                    'File_Path': vuln.file_path,
                    'Line_Number': vuln.line_number,
                    'Tool_Detected': vuln.tool_detected,
                    'Description': vuln.description,
                    'Remediation': vuln.remediation,
                    'Status': vuln.status,
                    'First_Detected': vuln.first_detected.isoformat()
                })
        
        return output_path
    
    async def _generate_json_report(
        self,
        vulnerabilities: List[VulnerabilityData],
        statistics: ScanStatistics,
        metadata: ReportMetadata,
        output_path: str
    ) -> str:
        """Generate JSON report for API integration"""
        
        report_data = {
            'metadata': asdict(metadata),
            'statistics': asdict(statistics),
            'vulnerabilities': [asdict(vuln) for vuln in vulnerabilities],
            'generated_at': datetime.now(timezone.utc).isoformat()
        }
        
        # Convert datetime objects to strings
        def datetime_handler(obj):
            if isinstance(obj, datetime):
                return obj.isoformat()
            raise TypeError(f"Object of type {type(obj)} is not JSON serializable")
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, default=datetime_handler)
        
        return output_path
    
    async def _generate_sarif_report(
        self,
        vulnerabilities: List[VulnerabilityData],
        statistics: ScanStatistics,
        metadata: ReportMetadata,
        output_path: str
    ) -> str:
        """Generate SARIF (Static Analysis Results Interchange Format) report"""
        
        sarif_data = {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "SecureShield Pro",
                            "version": metadata.version,
                            "informationUri": "https://secureshield.pro",
                            "rules": []
                        }
                    },
                    "results": []
                }
            ]
        }
        
        # Create rules for each unique vulnerability type
        rules_map = {}
        for vuln in vulnerabilities:
            if vuln.cwe_id and vuln.cwe_id not in rules_map:
                rules_map[vuln.cwe_id] = {
                    "id": vuln.cwe_id,
                    "name": vuln.title,
                    "shortDescription": {"text": vuln.title},
                    "fullDescription": {"text": vuln.description},
                    "helpUri": f"https://cwe.mitre.org/data/definitions/{vuln.cwe_id.replace('CWE-', '')}.html" if vuln.cwe_id.startswith('CWE-') else None
                }
        
        sarif_data["runs"][0]["tool"]["driver"]["rules"] = list(rules_map.values())
        
        # Convert vulnerabilities to SARIF results
        for vuln in vulnerabilities:
            result = {
                "ruleId": vuln.cwe_id or vuln.id,
                "message": {"text": vuln.description},
                "level": self._map_severity_to_sarif(vuln.severity),
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": vuln.file_path},
                            "region": {
                                "startLine": vuln.line_number or 1
                            }
                        }
                    }
                ]
            }
            
            if vuln.cve_id:
                result["properties"] = {"cve": vuln.cve_id}
            
            sarif_data["runs"][0]["results"].append(result)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(sarif_data, f, indent=2)
        
        return output_path
    
    async def _generate_xml_report(
        self,
        vulnerabilities: List[VulnerabilityData],
        statistics: ScanStatistics,
        metadata: ReportMetadata,
        output_path: str
    ) -> str:
        """Generate XML report in various industry schemas"""
        
        # Create root element
        root = ET.Element("security_report")
        root.set("version", "1.0")
        root.set("generated", datetime.now(timezone.utc).isoformat())
        
        # Add metadata
        meta_elem = ET.SubElement(root, "metadata")
        ET.SubElement(meta_elem, "title").text = metadata.title
        ET.SubElement(meta_elem, "organization").text = metadata.organization
        ET.SubElement(meta_elem, "analyst").text = metadata.analyst
        ET.SubElement(meta_elem, "scan_date").text = metadata.scan_date.isoformat() if metadata.scan_date else datetime.now(timezone.utc).isoformat()
        
        # Add statistics
        stats_elem = ET.SubElement(root, "statistics")
        ET.SubElement(stats_elem, "total_vulnerabilities").text = str(statistics.total_vulnerabilities)
        ET.SubElement(stats_elem, "critical_count").text = str(statistics.critical_count)
        ET.SubElement(stats_elem, "high_count").text = str(statistics.high_count)
        ET.SubElement(stats_elem, "medium_count").text = str(statistics.medium_count)
        ET.SubElement(stats_elem, "low_count").text = str(statistics.low_count)
        ET.SubElement(stats_elem, "files_scanned").text = str(statistics.total_files_scanned)
        
        # Add vulnerabilities
        vulns_elem = ET.SubElement(root, "vulnerabilities")
        for vuln in vulnerabilities:
            vuln_elem = ET.SubElement(vulns_elem, "vulnerability")
            vuln_elem.set("id", vuln.id)
            vuln_elem.set("severity", vuln.severity)
            
            ET.SubElement(vuln_elem, "title").text = vuln.title
            ET.SubElement(vuln_elem, "description").text = vuln.description
            ET.SubElement(vuln_elem, "file").text = vuln.file_path
            ET.SubElement(vuln_elem, "line").text = str(vuln.line_number) if vuln.line_number else "0"
            ET.SubElement(vuln_elem, "cvss_score").text = str(vuln.cvss_score)
            ET.SubElement(vuln_elem, "cwe_id").text = vuln.cwe_id
            ET.SubElement(vuln_elem, "tool").text = vuln.tool_detected
            ET.SubElement(vuln_elem, "remediation").text = vuln.remediation
            
            # Add references
            if vuln.references:
                refs_elem = ET.SubElement(vuln_elem, "references")
                for ref in vuln.references:
                    ET.SubElement(refs_elem, "reference").text = ref
        
        # Format XML with proper indentation
        xml_str = ET.tostring(root, encoding='unicode')
        dom = minidom.parseString(xml_str)
        formatted_xml = dom.toprettyxml(indent="  ")
        
        # Remove empty lines
        formatted_xml = '\n'.join([line for line in formatted_xml.split('\n') if line.strip()])
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(formatted_xml)
        
        return output_path
    
    def _map_severity_to_sarif(self, severity: str) -> str:
        """Map severity levels to SARIF levels"""
        mapping = {
            'CRITICAL': 'error',
            'HIGH': 'error',
            'MEDIUM': 'warning',
            'LOW': 'note',
            'INFO': 'note'
        }
        return mapping.get(severity.upper(), 'warning')
    
    def _get_severity_color(self, severity: str):
        """Get color for severity level"""
        if not PDF_AVAILABLE:
            return "#95a5a6"  # Return hex string if ReportLab not available
            
        colors = {
            'CRITICAL': HexColor('#e74c3c'),
            'HIGH': HexColor('#e67e22'),
            'MEDIUM': HexColor('#f39c12'),
            'LOW': HexColor('#27ae60'),
            'INFO': HexColor('#3498db')
        }
        return colors.get(severity.upper(), HexColor('#95a5a6'))
    
    def _generate_priority_recommendations(self, vulnerabilities: List[VulnerabilityData]) -> List[str]:
        """Generate priority recommendations based on vulnerabilities"""
        recommendations = []
        
        critical_count = len([v for v in vulnerabilities if v.severity == 'CRITICAL'])
        high_count = len([v for v in vulnerabilities if v.severity == 'HIGH'])
        
        if critical_count > 0:
            recommendations.append(f"Immediately address {critical_count} critical vulnerabilities before production deployment")
        
        if high_count > 0:
            recommendations.append(f"Prioritize resolution of {high_count} high-severity issues within 48 hours")
        
        # Check for common vulnerability types
        vuln_titles = [v.title.lower() for v in vulnerabilities]
        
        if any('sql' in title for title in vuln_titles):
            recommendations.append("Implement parameterized queries to prevent SQL injection attacks")
        
        if any('xss' in title for title in vuln_titles):
            recommendations.append("Enable content security policy and output encoding to prevent XSS attacks")
        
        if any('secret' in title or 'password' in title for title in vuln_titles):
            recommendations.append("Implement secure secret management and remove hardcoded credentials")
        
        recommendations.append("Conduct regular security code reviews and implement automated security testing")
        recommendations.append("Provide security training for development team members")
        
        return recommendations[:5]  # Limit to top 5 recommendations
    
    def _generate_simple_html(
        self,
        vulnerabilities: List[VulnerabilityData],
        statistics: ScanStatistics,
        metadata: ReportMetadata
    ) -> str:
        """Generate simple HTML report without Jinja2"""
        
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>{metadata.title}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        .header {{ text-align: center; border-bottom: 2px solid #333; padding-bottom: 20px; }}
        .vulnerability {{ border: 1px solid #ddd; margin: 20px 0; padding: 15px; }}
        .critical {{ border-left: 5px solid #e74c3c; }}
        .high {{ border-left: 5px solid #e67e22; }}
        .medium {{ border-left: 5px solid #f39c12; }}
        .low {{ border-left: 5px solid #27ae60; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>{{ metadata.title }}</h1>
        <p>Generated on {{ report_date }}</p>
    </div>
    
    <h2>Summary</h2>
    <table>
        <tr><th>Metric</th><th>Count</th></tr>
        <tr><td>Total Vulnerabilities</td><td>{statistics.total_vulnerabilities}</td></tr>
        <tr><td>Critical</td><td>{statistics.critical_count}</td></tr>
        <tr><td>High</td><td>{statistics.high_count}</td></tr>
        <tr><td>Medium</td><td>{statistics.medium_count}</td></tr>
        <tr><td>Low</td><td>{statistics.low_count}</td></tr>
    </table>
    
    <h2>Vulnerabilities</h2>
        """
        
        for vuln in vulnerabilities:
            html += f"""
    <div class="vulnerability {vuln.severity.lower()}">
        <h3>{vuln.title} ({vuln.severity})</h3>
        <p><strong>File:</strong> {vuln.file_path}</p>
        <p><strong>Line:</strong> {vuln.line_number or 'N/A'}</p>
        <p><strong>Description:</strong> {vuln.description}</p>
        <p><strong>Remediation:</strong> {vuln.remediation}</p>
    </div>
            """
        
        html += """
</body>
</html>
        """
        
        return html

# Global instance
report_generator = SecurityReportGenerator()