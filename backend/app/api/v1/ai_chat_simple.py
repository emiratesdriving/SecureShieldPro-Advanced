"""AI Chat API endpoints"""

import logging
from typing import Dict, Any, Optional
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from pydantic import BaseModel
from app.db.database import get_db

logger = logging.getLogger(__name__)
router = APIRouter()

class ChatRequest(BaseModel):
    message: str
    context: Optional[Dict[str, Any]] = None

@router.post("/chat/message")
async def send_chat_message(request: ChatRequest, db: Session = Depends(get_db)):
    """Send message to AI"""
    try:
        from app.services.ai_service_manager import ai_service_manager, AIRequest
        
        if not request.message.strip():
            return {"error": "Message cannot be empty"}
        
        ai_request = AIRequest(
            message=request.message,
            context=request.context or {}
        )
        
        response = await ai_service_manager.process_request(ai_request)
        
        return {
            "message": response.message,
            "suggestions": response.suggestions or [],
            "model_used": response.model_used,
            "confidence": response.confidence
        }
        
    except Exception as e:
        logger.error(f"AI chat error: {e}")
        return {"error": str(e)}

@router.get("/health")
async def health_check():
    """Health check"""
    return {"status": "healthy"}

@router.post("/initialize")
async def initialize_ai():
    """Initialize AI providers"""
    try:
        from app.services.ai_service_manager import ai_service_manager
        await ai_service_manager.initialize()
        status = await ai_service_manager.get_status()
        return {"success": True, "status": status}
    except Exception as e:
        logger.error(f"AI initialization error: {e}")
        return {"error": str(e), "success": False}

@router.get("/status")
async def get_ai_status():
    """Get AI service status"""
    try:
        from app.services.ai_service_manager import ai_service_manager
        status = await ai_service_manager.get_status()
        return status
    except Exception as e:
        logger.error(f"Status error: {e}")
        return {"error": str(e)}

@router.post("/remediation/execute")
async def execute_remediation(request: ChatRequest, db: Session = Depends(get_db)):
    """Execute auto-remediation"""
    try:
        from app.services.ai_service_manager import ai_service_manager, AIRequest
        
        if not request.message.strip():
            return {"error": "Message cannot be empty"}
        
        # Add remediation context
        context = request.context or {}
        context["action"] = "remediation"
        context["tab"] = "remediation"
        
        ai_request = AIRequest(
            message=request.message,
            context=context
        )
        
        response = await ai_service_manager.process_request(ai_request)
        
        return {
            "success": True,
            "message": response.message,
            "remediation_steps": response.suggestions or [],
            "model_used": response.model_used,
            "confidence": response.confidence
        }
        
    except Exception as e:
        logger.error(f"Remediation error: {e}")
        return {"error": str(e), "success": False}
