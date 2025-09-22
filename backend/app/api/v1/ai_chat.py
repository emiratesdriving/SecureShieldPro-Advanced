"""
AI Chat API for security analysis and assistance
"""

from fastapi import APIRouter, HTTPException, Depends
from typing import Dict, Any, Optional, List
from pydantic import BaseModel
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ai-chat", tags=["AI Chat"])

# Import the AI service with fallback
try:
    from app.services.enhanced_ai_analyst import enhanced_ai_analyst
    ai_service_available = True
except ImportError:
    enhanced_ai_analyst = None
    ai_service_available = False
    logger.warning("Enhanced AI Analyst service not available")


class ChatMessage(BaseModel):
    message: str
    context: Optional[Dict[str, Any]] = None
    session_id: Optional[str] = None


class VulnerabilityAnalysisRequest(BaseModel):
    vulnerability_data: Dict[str, Any]
    include_remediation: bool = True
    context: Optional[Dict[str, Any]] = None


@router.post("/chat")
async def ai_security_chat(request: ChatMessage) -> Dict[str, Any]:
    """
    Chat with AI Security Analyst - Enhanced and Fast Response
    """
    try:
        # Quick fallback response if service unavailable
        if not ai_service_available or not enhanced_ai_analyst:
            return {
                "success": True,
                "data": {
                    "response": _get_fallback_response(request.message),
                    "timestamp": datetime.now().isoformat(),
                    "confidence": 0.8,
                    "suggestions": [
                        "Check system security status",
                        "Review recent vulnerability scans",
                        "Generate compliance report"
                    ],
                    "fallback": True
                },
                "session_id": request.session_id
            }
        
        # Use enhanced AI service
        response = await enhanced_ai_analyst.security_chat(
            message=request.message,
            context=request.context
        )
        
        return {
            "success": True,
            "data": response,
            "session_id": request.session_id
        }
        
    except Exception as e:
        logger.error(f"AI chat error: {str(e)}")
        # Return helpful error response instead of HTTP error
        return {
            "success": False,
            "data": {
                "response": "I'm experiencing some technical difficulties right now. Let me try to help you with a basic response.",
                "timestamp": datetime.now().isoformat(),
                "confidence": 0.5,
                "suggestions": [
                    "Try asking your question again",
                    "Check system status",
                    "Contact support if issue persists"
                ],
                "error": True
            },
            "session_id": request.session_id,
            "error_details": str(e)
        }


def _get_fallback_response(message: str) -> str:
    """Generate fallback response when AI service is unavailable"""
    message_lower = message.lower()
    
    if any(term in message_lower for term in ["scan", "vulnerability", "security scan"]):
        return "I can help you with security scanning! You can run SAST scans for code analysis, dependency scans for third-party vulnerabilities, and comprehensive security assessments. Check the Security Dashboard for available scan options."
    
    elif any(term in message_lower for term in ["compliance", "report", "framework"]):
        return "For compliance reporting, I can help you generate reports for OWASP Top 10, NIST, ISO 27001, and other frameworks. Visit the Compliance section to view current status and generate detailed reports."
    
    elif any(term in message_lower for term in ["vulnerability", "vuln", "cve"]):
        return "I can assist with vulnerability management! Check the Security Findings page to view detected vulnerabilities, their severity levels, and remediation guidance. Critical issues should be addressed immediately."
    
    elif any(term in message_lower for term in ["risk", "assessment", "analysis"]):
        return "Risk assessment is crucial for security posture! I can help you understand your risk profile based on identified vulnerabilities, asset criticality, and threat landscape. Check the Risk Dashboard for detailed insights."
    
    elif any(term in message_lower for term in ["fix", "remediate", "patch"]):
        return "For remediation guidance, I provide step-by-step instructions for fixing vulnerabilities. Each finding includes specific remediation steps, code examples, and best practices. Prioritize critical and high-severity issues first."
    
    else:
        return "Hello! I'm your AI Security Analyst. I can help with vulnerability analysis, compliance checking, risk assessment, and security guidance. What security topic would you like to explore?"


@router.post("/analyze-vulnerability")
async def analyze_vulnerability(request: VulnerabilityAnalysisRequest) -> Dict[str, Any]:
    """
    Analyze vulnerability with AI insights
    """
    try:
        if not ai_service_available or not enhanced_ai_analyst:
            # Provide basic analysis without AI service
            return {
                "success": True,
                "data": _get_basic_vulnerability_analysis(request.vulnerability_data),
                "include_remediation": request.include_remediation,
                "fallback": True
            }
        
        analysis = await enhanced_ai_analyst.analyze_vulnerability(
            vulnerability_data=request.vulnerability_data
        )
        
        return {
            "success": True,
            "data": analysis,
            "include_remediation": request.include_remediation
        }
        
    except Exception as e:
        logger.error(f"Vulnerability analysis error: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail={
                "error": "Failed to analyze vulnerability",
                "message": str(e),
                "timestamp": datetime.now().isoformat()
            }
        )


def _get_basic_vulnerability_analysis(vuln_data: Dict[str, Any]) -> Dict[str, Any]:
    """Provide basic vulnerability analysis without AI service"""
    severity = vuln_data.get("severity", "UNKNOWN")
    vuln_type = vuln_data.get("type", "unknown")
    
    return {
        "vulnerability_id": vuln_data.get("id", "N/A"),
        "type": vuln_type,
        "severity": severity,
        "risk_score": vuln_data.get("cvss_score", 5.0),
        "priority": "HIGH" if severity in ["CRITICAL", "HIGH"] else "MEDIUM",
        "basic_remediation": f"Address this {severity.lower()} severity {vuln_type} vulnerability according to security best practices.",
        "timeline": "Immediate" if severity == "CRITICAL" else "Within 30 days",
        "analysis_timestamp": datetime.now().isoformat(),
        "fallback_analysis": True
    }


@router.get("/health")
async def ai_service_health() -> Dict[str, Any]:
    """
    Check AI service health and capabilities
    """
    try:
        if not ai_service_available or not enhanced_ai_analyst:
            return {
                "success": True,
                "data": {
                    "status": "limited",
                    "service": "ai_analyst_fallback",
                    "message": "AI service running in fallback mode with basic responses",
                    "capabilities": [
                        "basic_chat_responses",
                        "vulnerability_identification",
                        "general_security_guidance"
                    ],
                    "timestamp": datetime.now().isoformat(),
                    "fallback_mode": True
                }
            }
        
        health_status = await enhanced_ai_analyst.get_health_status()
        
        return {
            "success": True,
            "data": health_status
        }
        
    except Exception as e:
        logger.error(f"AI health check error: {str(e)}")
        return {
            "success": False,
            "data": {
                "status": "error",
                "service": "ai_analyst",
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }
        }


@router.get("/quick-help")
async def get_quick_help() -> Dict[str, Any]:
    """
    Get quick help and common security questions
    """
    return {
        "success": True,
        "data": {
            "common_questions": [
                {
                    "question": "How do I run a security scan?",
                    "category": "scanning",
                    "quick_answer": "Visit the Security Dashboard and click 'Start Scan' to run SAST, dependency, or comprehensive scans."
                },
                {
                    "question": "What are critical vulnerabilities?",
                    "category": "vulnerabilities",
                    "quick_answer": "Critical vulnerabilities have CVSS scores 9.0-10.0 and require immediate attention within 24 hours."
                },
                {
                    "question": "How do I check compliance status?",
                    "category": "compliance",
                    "quick_answer": "Go to Compliance Reports to view OWASP Top 10, NIST, and ISO 27001 compliance status."
                },
                {
                    "question": "What should I prioritize for remediation?",
                    "category": "remediation",
                    "quick_answer": "Prioritize critical and high-severity vulnerabilities, especially those with public exploits."
                }
            ],
            "security_tips": [
                "Regularly update dependencies to patch known vulnerabilities",
                "Enable automated security scanning in your CI/CD pipeline",
                "Review and address critical findings within 24 hours",
                "Implement multi-factor authentication for all user accounts"
            ],
            "timestamp": datetime.now().isoformat()
        }
    }

from typing import Dict, List, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from fastapi.security import HTTPBearer
from pydantic import BaseModel, Field
from datetime import datetime
import logging

from app.core.auth import get_current_user
from app.db.database import get_db  
from app.db.models import User
from app.services.ai_analyst import ai_analyst

logger = logging.getLogger(__name__)
security = HTTPBearer()

router = APIRouter()

# Pydantic models for request/response
class ChatMessage(BaseModel):
    message: str = Field(..., min_length=1, max_length=2000, description="User message")
    context: Optional[Dict[str, Any]] = Field(None, description="Additional context for the chat")

class ChatResponse(BaseModel):
    response: str
    timestamp: datetime
    confidence: Optional[float] = None
    suggestions: Optional[List[str]] = None

class VulnerabilityAnalysisRequest(BaseModel):
    vulnerability_id: str
    vulnerability_data: Dict[str, Any]

class SecurityReportRequest(BaseModel):
    scan_results: List[Dict[str, Any]]
    report_type: str = "comprehensive"

class ComplianceCheckRequest(BaseModel):
    scan_results: List[Dict[str, Any]]
    framework: str = Field("OWASP", description="Compliance framework (OWASP, NIST, ISO27001)")

# AI Chat endpoint
@router.post("/chat", response_model=ChatResponse)
async def security_chat(
    message: ChatMessage,
    current_user: User = Depends(get_current_user)
):
    """
    Interactive security consultation chat with AI analyst
    
    Provides expert security advice, vulnerability explanations,
    and threat intelligence insights.
    """
    try:
        # Get user context if available
        user_context = {
            "user_id": current_user.id,
            "user_role": getattr(current_user, 'role', 'user'),
            "recent_scans": 0,  # This would come from database query
            "active_vulnerabilities": 0,  # This would come from database query
            "last_scan_date": "Never",  # This would come from database query
            "system_info": "SecureShield Pro Platform"
        }
        
        # Enhance context with provided data
        if message.context:
            user_context.update(message.context)
        
        # Get AI response
        ai_response = await ai_analyst.security_chat(
            user_message=message.message,
            context=user_context
        )
        
        if "error" in ai_response:
            raise HTTPException(
                status_code=500,
                detail=f"AI chat error: {ai_response.get('message', 'Unknown error')}"
            )
        
        # Extract suggestions from AI response if available
        suggestions = []
        response_text = ai_response.get("ai_response", "")
        
        # Simple suggestion extraction (in production, this would be more sophisticated)
        if "recommend" in response_text.lower():
            suggestions.append("Review the recommended security practices")
        if "scan" in response_text.lower():
            suggestions.append("Consider running a security scan")
        if "update" in response_text.lower():
            suggestions.append("Check for security updates")
        
        return ChatResponse(
            response=response_text,
            timestamp=datetime.fromisoformat(ai_response.get("timestamp")),
            confidence=0.85,  # AI confidence score
            suggestions=suggestions if suggestions else None
        )
        
    except Exception as e:
        logger.error(f"Chat error: {e}")
        raise HTTPException(
            status_code=500,
            detail="Failed to process chat message"
        )

# Vulnerability Analysis endpoint
@router.post("/analyze-vulnerability")
async def analyze_vulnerability(
    request: VulnerabilityAnalysisRequest,
    current_user: User = Depends(get_current_user)
):
    """
    AI-powered analysis of specific vulnerabilities
    
    Provides detailed risk assessment, attack scenarios,
    and remediation guidance.
    """
    try:
        analysis = await ai_analyst.analyze_vulnerability(request.vulnerability_data)
        
        if "error" in analysis:
            raise HTTPException(
                status_code=500,
                detail=f"Vulnerability analysis failed: {analysis.get('message')}"
            )
        
        return {
            "vulnerability_id": request.vulnerability_id,
            "analysis": analysis,
            "analyzed_by": current_user.username,
            "analysis_timestamp": datetime.now()
        }
        
    except Exception as e:
        logger.error(f"Vulnerability analysis error: {e}")
        raise HTTPException(
            status_code=500,
            detail="Failed to analyze vulnerability"
        )

# Security Report Generation endpoint
@router.post("/generate-report")
async def generate_security_report(
    request: SecurityReportRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user)
):
    """
    Generate AI-powered comprehensive security reports
    
    Creates executive summaries, risk assessments,
    and strategic recommendations.
    """
    try:
        # Start report generation in background
        background_tasks.add_task(
            _generate_report_background,
            request.scan_results,
            current_user.id,
            request.report_type
        )
        
        # Return immediate response
        report = await ai_analyst.generate_security_report(request.scan_results)
        
        if "error" in report:
            raise HTTPException(
                status_code=500,
                detail=f"Report generation failed: {report.get('message')}"
            )
        
        return {
            "report": report,
            "generated_by": current_user.username,
            "generation_timestamp": datetime.now(),
            "status": "completed"
        }
        
    except Exception as e:
        logger.error(f"Report generation error: {e}")
        raise HTTPException(
            status_code=500,
            detail="Failed to generate security report"
        )

# Threat Intelligence endpoint
@router.get("/threat-intelligence")
async def get_threat_intelligence(
    current_user: User = Depends(get_current_user)
):
    """
    Get current threat intelligence briefing
    
    Provides up-to-date threat landscape analysis,
    critical CVEs, and defensive recommendations.
    """
    try:
        intelligence = await ai_analyst.threat_intelligence_update()
        
        if "error" in intelligence:
            raise HTTPException(
                status_code=500,
                detail=f"Threat intelligence failed: {intelligence.get('message')}"
            )
        
        return {
            "threat_intelligence": intelligence,
            "requested_by": current_user.username,
            "request_timestamp": datetime.now()
        }
        
    except Exception as e:
        logger.error(f"Threat intelligence error: {e}")
        raise HTTPException(
            status_code=500,
            detail="Failed to retrieve threat intelligence"
        )

# Compliance Checker endpoint
@router.post("/compliance-check")
async def check_compliance(
    request: ComplianceCheckRequest,
    current_user: User = Depends(get_current_user)
):
    """
    AI-powered compliance assessment
    
    Evaluates scan results against security frameworks
    like OWASP, NIST, and ISO 27001.
    """
    try:
        compliance = await ai_analyst.compliance_checker(
            request.scan_results,
            request.framework
        )
        
        if "error" in compliance:
            raise HTTPException(
                status_code=500,
                detail=f"Compliance check failed: {compliance.get('message')}"
            )
        
        return {
            "compliance_assessment": compliance,
            "assessed_by": current_user.username,
            "assessment_timestamp": datetime.now(),
            "framework": request.framework
        }
        
    except Exception as e:
        logger.error(f"Compliance check error: {e}")
        raise HTTPException(
            status_code=500,
            detail="Failed to perform compliance check"
        )

# AI Health Check endpoint
@router.get("/health")
async def ai_health_check(
    current_user: User = Depends(get_current_user)
):
    """
    Check AI service health and capabilities
    
    Verifies connectivity to AI models and
    returns available features.
    """
    try:
        # Test AI connection with simple prompt
        test_response = await ai_analyst._call_ai_model(
            "Respond with 'AI service operational' if you can process this message."
        )
        
        health_status = {
            "status": "healthy" if "operational" in test_response.lower() else "degraded",
            "ai_model": ai_analyst.model_preference,
            "ollama_url": ai_analyst.ollama_url,
            "features": [
                "security_chat",
                "vulnerability_analysis", 
                "report_generation",
                "threat_intelligence",
                "compliance_checking"
            ],
            "last_check": datetime.now(),
            "response_sample": test_response[:100] + "..." if len(test_response) > 100 else test_response
        }
        
        return health_status
        
    except Exception as e:
        logger.error(f"AI health check error: {e}")
        return {
            "status": "unhealthy",
            "error": str(e),
            "last_check": datetime.now(),
            "features": ["limited_functionality"]
        }

# AI Configuration endpoint
@router.get("/config")
async def get_ai_config(
    current_user: User = Depends(get_current_user)
):
    """
    Get current AI configuration and settings
    
    Returns AI model settings, preferences,
    and available capabilities.
    """
    try:
        config = {
            "model_preference": ai_analyst.model_preference,
            "default_model": ai_analyst.default_model,
            "ollama_configured": bool(ai_analyst.ollama_url),
            "openai_configured": bool(ai_analyst.openai_api_key),
            "capabilities": {
                "vulnerability_analysis": True,
                "security_chat": True,
                "report_generation": True,
                "threat_intelligence": True,
                "compliance_checking": True,
                "real_time_analysis": True
            },
            "performance_settings": {
                "max_tokens": 2048,
                "temperature": 0.7,
                "timeout_seconds": 60
            }
        }
        
        return config
        
    except Exception as e:
        logger.error(f"AI config error: {e}")
        raise HTTPException(
            status_code=500,
            detail="Failed to retrieve AI configuration"
        )

# Background task functions
async def _generate_report_background(
    scan_results: List[Dict[str, Any]], 
    user_id: int, 
    report_type: str
):
    """Background task for intensive report generation"""
    try:
        logger.info(f"Starting background report generation for user {user_id}")
        
        # This would save the report to database in production
        # For now, we'll just log completion
        report = await ai_analyst.generate_security_report(scan_results)
        
        logger.info(f"Background report completed for user {user_id}: {len(str(report))} characters")
        
    except Exception as e:
        logger.error(f"Background report generation failed: {e}")

# Chat suggestions endpoint  
@router.get("/chat-suggestions")
async def get_chat_suggestions(
    current_user: User = Depends(get_current_user)
):
    """
    Get suggested questions for security chat
    
    Returns contextual question suggestions based on
    current system state and common security topics.
    """
    suggestions = [
        "What are the most critical vulnerabilities in my latest scan?",
        "How can I improve my security posture?",
        "What are the current top cybersecurity threats?",
        "How do I comply with OWASP Top 10 requirements?",
        "What security controls should I implement first?",
        "How often should I run security scans?",
        "What is the risk of this SQL injection vulnerability?",
        "How do I create a security incident response plan?",
        "What are the best practices for secure coding?",
        "How do I perform a security risk assessment?"
    ]
    
    return {
        "suggestions": suggestions,
        "categories": [
            "Vulnerability Management",
            "Threat Intelligence", 
            "Compliance",
            "Risk Assessment",
            "Security Controls",
            "Incident Response"
        ],
        "generated_at": datetime.now()
    }