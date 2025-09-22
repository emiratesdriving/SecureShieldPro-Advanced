"""
Enhanced AI Service Manager
Integrates OpenRouter API, Ollama, Auto-Remediation, and OCR capabilities
"""

import asyncio
import aiohttp
import logging
import os
import base64
import subprocess
from PIL import Image
from typing import Dict, List, Optional, Any, Union
from datetime import datetime
from pydantic import BaseModel
import json

# Import settings after fixing the import
try:
    from app.core.config import settings
except ImportError:
    # Fallback configuration if import fails
    class Settings:
        OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY", "")
        OPENROUTER_MODEL = os.getenv("OPENROUTER_MODEL", "openai/gpt-4o-mini")
        OLLAMA_URL = os.getenv("OLLAMA_URL", "http://127.0.0.1:11434")
        MODEL_NAME = os.getenv("MODEL_NAME", "llama3.2:3b")
        EMBEDDING_MODEL = os.getenv("EMBEDDING_MODEL", "nomic-embed-text:latest")
        VISION_MODEL = os.getenv("VISION_MODEL", "llava:13b")
    
    settings = Settings()

# Try to import pytesseract, fallback if not available
try:
    import pytesseract
    TESSERACT_AVAILABLE = True
except ImportError:
    TESSERACT_AVAILABLE = False
    pytesseract = None

logger = logging.getLogger(__name__)

class AIRequest(BaseModel):
    model_config = {"protected_namespaces": ()}
    
    message: str
    context: Optional[Dict] = None
    model_preference: str = "auto"  # auto, openrouter, ollama
    task_type: str = "chat"  # chat, analysis, remediation, ocr
    files: Optional[List[str]] = None

class AIResponse(BaseModel):
    model_config = {"protected_namespaces": ()}
    
    message: str
    confidence: float
    model_used: str
    execution_time: float
    suggestions: List[str] = []
    remediation: Optional[Dict] = None
    metadata: Dict[str, Any] = {}

class AIServiceManager:
    """Comprehensive AI service integrating multiple providers and capabilities"""
    
    def __init__(self):
        self.openrouter_api_key = getattr(settings, 'OPENROUTER_API_KEY', os.getenv("OPENROUTER_API_KEY", ""))
        self.openrouter_model = getattr(settings, 'OPENROUTER_MODEL', os.getenv("OPENROUTER_MODEL", "openai/gpt-4o-mini"))
        self.ollama_url = getattr(settings, 'OLLAMA_URL', os.getenv("OLLAMA_URL", "http://127.0.0.1:11434"))
        self.ollama_model = getattr(settings, 'MODEL_NAME', os.getenv("MODEL_NAME", "llama3.2:3b"))
        self.embedding_model = getattr(settings, 'EMBEDDING_MODEL', os.getenv("EMBEDDING_MODEL", "nomic-embed-text:latest"))
        self.vision_model = getattr(settings, 'VISION_MODEL', os.getenv("VISION_MODEL", "llava:13b"))
        self.providers_status = {}
        
    async def initialize(self):
        """Initialize and test all AI providers"""
        await self._test_providers()
        logger.info("AI Service Manager initialized successfully")
        
    async def _test_providers(self):
        """Test connectivity to all AI providers"""
        # Test OpenRouter
        try:
            async with aiohttp.ClientSession() as session:
                headers = {
                    "Authorization": f"Bearer {self.openrouter_api_key}",
                    "Content-Type": "application/json"
                }
                data = {
                    "model": self.openrouter_model,
                    "messages": [{"role": "user", "content": "test"}],
                    "max_tokens": 10
                }
                async with session.post(
                    "https://openrouter.ai/api/v1/chat/completions",
                    headers=headers,
                    json=data,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    if response.status == 200:
                        self.providers_status["openrouter"] = "online"
                        logger.info("OpenRouter API connection successful")
                    else:
                        self.providers_status["openrouter"] = "error"
                        logger.warning(f"OpenRouter API error: {response.status}")
        except Exception as e:
            self.providers_status["openrouter"] = "offline"
            logger.error(f"OpenRouter connection failed: {e}")
            
        # Test Ollama
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{self.ollama_url}/api/tags",
                    timeout=aiohttp.ClientTimeout(total=5)
                ) as response:
                    if response.status == 200:
                        self.providers_status["ollama"] = "online"
                        logger.info("Ollama connection successful")
                    else:
                        self.providers_status["ollama"] = "error"
        except Exception as e:
            self.providers_status["ollama"] = "offline"
            logger.error(f"Ollama connection failed: {e}")
            
    async def process_request(self, request: AIRequest) -> AIResponse:
        """Process AI request using best available provider"""
        start_time = datetime.now()
        
        try:
            # Ensure providers are initialized
            if not self.providers_status:
                logger.info("Auto-initializing AI providers")
                await self.initialize()
            
            # Determine best provider
            provider = await self._select_provider(request)
            
            # Route to appropriate handler
            if request.task_type == "chat":
                response = await self._handle_chat(request, provider)
            elif request.task_type == "analysis":
                response = await self._handle_analysis(request, provider)
            elif request.task_type == "remediation":
                response = await self._handle_remediation(request, provider)
            elif request.task_type == "ocr":
                response = await self._handle_ocr(request)
            else:
                response = await self._handle_chat(request, provider)
                
            execution_time = (datetime.now() - start_time).total_seconds()
            response.execution_time = execution_time
            
            return response
            
        except Exception as e:
            logger.error(f"AI request processing failed: {e}")
            return AIResponse(
                message="I apologize, but I encountered an error processing your request. Please try again.",
                confidence=0.0,
                model_used="error",
                execution_time=(datetime.now() - start_time).total_seconds(),
                metadata={"error": str(e)}
            )
    
    async def _select_provider(self, request: AIRequest) -> str:
        """Select the best provider based on request and availability"""
        logger.info(f"Provider selection - Request preference: {request.model_preference}, Providers status: {self.providers_status}")
        
        if request.model_preference == "openrouter" and self.providers_status.get("openrouter") == "online":
            logger.info("Selected OpenRouter (preference)")
            return "openrouter"
        elif request.model_preference == "ollama" and self.providers_status.get("ollama") == "online":
            logger.info("Selected Ollama (preference)")
            return "ollama"
        else:
            # Auto-select based on availability and task type
            if request.task_type in ["analysis", "remediation"] and self.providers_status.get("openrouter") == "online":
                logger.info("Selected OpenRouter (auto - complex task)")
                return "openrouter"  # Better for complex tasks
            elif self.providers_status.get("ollama") == "online":
                logger.info("Selected Ollama (auto - available)")
                return "ollama"  # Local and fast
            elif self.providers_status.get("openrouter") == "online":
                logger.info("Selected OpenRouter (auto - fallback)")
                return "openrouter"
            else:
                logger.info("Using fallback - no providers available")
                return "fallback"
    
    async def _handle_chat(self, request: AIRequest, provider: str) -> AIResponse:
        """Handle chat requests"""
        logger.info(f"Handling chat with provider: {provider}")
        if provider == "openrouter":
            return await self._chat_openrouter(request)
        elif provider == "ollama":
            return await self._chat_ollama(request)
        else:
            logger.info("Using fallback chat")
            return await self._chat_fallback(request)
            
    async def _chat_openrouter(self, request: AIRequest) -> AIResponse:
        """Process chat using OpenRouter API"""
        try:
            system_prompt = self._build_system_prompt(request)
            
            async with aiohttp.ClientSession() as session:
                headers = {
                    "Authorization": f"Bearer {self.openrouter_api_key}",
                    "Content-Type": "application/json"
                }
                
                messages = [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": request.message}
                ]
                
                data = {
                    "model": self.openrouter_model,
                    "messages": messages,
                    "max_tokens": 1000,
                    "temperature": 0.7
                }
                
                async with session.post(
                    "https://openrouter.ai/api/v1/chat/completions",
                    headers=headers,
                    json=data,
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as response:
                    if response.status == 200:
                        result = await response.json()
                        message = result["choices"][0]["message"]["content"]
                        
                        # Parse suggestions and remediation from response
                        suggestions = self._extract_suggestions(message)
                        remediation = self._extract_remediation(message)
                        
                        return AIResponse(
                            message=message,
                            confidence=0.9,
                            model_used=f"openrouter/{self.openrouter_model}",
                            execution_time=0.0,
                            suggestions=suggestions,
                            remediation=remediation
                        )
                    else:
                        logger.error(f"OpenRouter API error: {response.status}")
                        return await self._chat_fallback(request)
                        
        except Exception as e:
            logger.error(f"OpenRouter chat error: {e}")
            return await self._chat_fallback(request)
    
    async def _chat_ollama(self, request: AIRequest) -> AIResponse:
        """Process chat using Ollama"""
        try:
            # Simplified system prompt for faster processing
            system_prompt = "You are a helpful AI security assistant. Provide concise, accurate responses."
            
            logger.info(f"Calling Ollama with model: {self.ollama_model}")
            
            async with aiohttp.ClientSession() as session:
                # Optimized data with shorter prompt and lower token limits
                data = {
                    "model": self.ollama_model,
                    "prompt": f"{system_prompt}\n\nUser: {request.message}\nAssistant:",
                    "stream": False,
                    "options": {
                        "temperature": 0.3,  # Lower for faster, more focused responses
                        "top_p": 0.8,
                        "num_predict": 200,   # Limit response length for speed
                        "top_k": 20,
                        "repeat_penalty": 1.1
                    }
                }
                
                logger.info(f"Making optimized request to {self.ollama_url}/api/generate")
                async with session.post(
                    f"{self.ollama_url}/api/generate",
                    json=data,
                    timeout=aiohttp.ClientTimeout(total=15)  # Reduced timeout for faster response
                ) as response:
                    logger.info(f"Ollama response status: {response.status}")
                    if response.status == 200:
                        result = await response.json()
                        message = result.get("response", "")
                        logger.info(f"Ollama response received: {len(message)} characters")
                        
                        # Quick suggestions extraction
                        suggestions = [
                            "Analyze code for vulnerabilities",
                            "Show remediation options", 
                            "Explain security concepts",
                            "Provide best practices"
                        ]
                        
                        return AIResponse(
                            message=message,
                            confidence=0.85,
                            model_used=f"ollama/{self.ollama_model}",
                            execution_time=0.0,
                            suggestions=suggestions
                        )
                    else:
                        error_text = await response.text()
                        logger.error(f"Ollama API error: {response.status} - {error_text}")
                        return await self._chat_fallback(request)
                        
        except asyncio.TimeoutError:
            logger.warning("Ollama request timed out, using fallback")
            return await self._chat_fallback(request)
        except Exception as e:
            logger.error(f"Ollama chat error: {str(e)}")
            return await self._chat_fallback(request)
    
    async def _chat_fallback(self, request: AIRequest) -> AIResponse:
        """Fallback chat response when APIs are unavailable"""
        message = request.message.lower()
        
        # Quick pattern matching for common security topics
        if any(term in message for term in ["cybersecurity", "security", "vulnerability", "attack"]):
            response_message = "Cybersecurity involves protecting systems, networks, and data from digital attacks. Key areas include network security, data protection, access control, and incident response. Common threats include malware, phishing, and SQL injection."
        elif any(term in message for term in ["sql injection", "sql", "injection"]):
            response_message = "SQL injection is a web security vulnerability that allows attackers to interfere with database queries. Prevention: Use parameterized queries, input validation, and prepared statements. Avoid dynamic SQL construction."
        elif any(term in message for term in ["remediation", "fix", "patch"]):
            response_message = "Security remediation involves identifying and fixing vulnerabilities. Steps: 1) Assess the vulnerability, 2) Prioritize based on risk, 3) Apply appropriate fixes, 4) Verify the fix, 5) Monitor for recurrence."
        else:
            response_message = "I'm your AI Security Assistant. I can help with vulnerability analysis, security best practices, remediation guidance, and threat detection. What specific security topic would you like to explore?"
                
        return AIResponse(
            message=response_message,
            confidence=0.7,
            model_used="fast-fallback",
            execution_time=0.0,
            suggestions=[
                "Analyze my code for vulnerabilities",
                "Show me remediation options", 
                "Explain security best practices",
                "Help with threat detection"
            ]
        )
    
    async def _handle_analysis(self, request: AIRequest, provider: str) -> AIResponse:
        """Handle security analysis requests"""
        analysis_prompt = f"""
        You are a cybersecurity expert performing security analysis. 
        Analyze the following for security vulnerabilities, risks, and compliance issues:
        
        {request.message}
        
        Provide:
        1. Identified vulnerabilities
        2. Risk assessment
        3. Remediation recommendations
        4. Compliance status
        """
        
        modified_request = AIRequest(
            message=analysis_prompt,
            context=request.context,
            model_preference=request.model_preference,
            task_type="chat"
        )
        
        return await self._handle_chat(modified_request, provider)
    
    async def _handle_remediation(self, request: AIRequest, provider: str) -> AIResponse:
        """Handle auto-remediation requests"""
        remediation_prompt = f"""
        You are an auto-remediation expert. For the following security issue, provide:
        1. Step-by-step remediation instructions
        2. Code fixes (if applicable)
        3. Configuration changes needed
        4. Verification steps
        
        Security Issue: {request.message}
        
        Format your response with clear action items that can be automated.
        """
        
        modified_request = AIRequest(
            message=remediation_prompt,
            context=request.context,
            model_preference=request.model_preference,
            task_type="chat"
        )
        
        response = await self._handle_chat(modified_request, provider)
        
        # Add remediation metadata
        response.remediation = {
            "available": True,
            "actions": [
                {
                    "title": "Apply Security Patch",
                    "description": "Automatically apply the recommended security patch",
                    "type": "patch_application"
                },
                {
                    "title": "Update Configuration", 
                    "description": "Update security configuration based on best practices",
                    "type": "configuration_fix"
                }
            ]
        }
        
        return response
    
    async def _handle_ocr(self, request: AIRequest) -> AIResponse:
        """Handle OCR text extraction requests"""
        try:
            if not TESSERACT_AVAILABLE:
                return AIResponse(
                    message="OCR functionality is not available. Please install tesseract-ocr and pytesseract.",
                    confidence=0.0,
                    model_used="ocr-unavailable",
                    execution_time=0.0,
                    suggestions=["Install tesseract-ocr system package", "Install pytesseract Python package"]
                )

            if not request.files:
                return AIResponse(
                    message="Please upload an image or document file for OCR processing.",
                    confidence=0.0,
                    model_used="ocr",
                    execution_time=0.0,
                    suggestions=["Upload an image file", "Upload a PDF document", "Upload a scanned document"]
                )
            
            extracted_texts = []
            
            for file_path in request.files:
                try:
                    # Process image with Tesseract OCR
                    image = Image.open(file_path)
                    text = pytesseract.image_to_string(image, config='--psm 6')
                    extracted_texts.append(f"File: {os.path.basename(file_path)}\nExtracted Text:\n{text}")
                except Exception as e:
                    logger.error(f"OCR processing failed for {file_path}: {e}")
                    extracted_texts.append(f"Failed to process {os.path.basename(file_path)}: {str(e)}")
            
            combined_text = "\n\n".join(extracted_texts)
            
            return AIResponse(
                message=f"OCR processing completed successfully:\n\n{combined_text}",
                confidence=0.9,
                model_used="tesseract-ocr",
                execution_time=0.0,
                metadata={"extracted_files": len(request.files)}
            )
            
        except Exception as e:
            logger.error(f"OCR processing error: {e}")
            return AIResponse(
                message=f"OCR processing failed: {str(e)}",
                confidence=0.0,
                model_used="ocr-error",
                execution_time=0.0
            )
    
    def _build_system_prompt(self, request: AIRequest) -> str:
        """Build system prompt based on request context"""
        base_prompt = """You are an advanced AI Security Assistant specializing in cybersecurity, vulnerability assessment, and automated remediation. You have expertise in:

1. Vulnerability Analysis & Detection
2. Security Code Review
3. Compliance Assessment  
4. Threat Intelligence
5. Auto-Remediation Strategies
6. Security Best Practices

Provide accurate, actionable security advice. When suggesting remediation, be specific and practical."""

        if request.context:
            if request.context.get("tab") == "remediation":
                base_prompt += "\n\nFocus on providing auto-remediation solutions and specific fix instructions."
            elif request.context.get("tab") == "analysis":
                base_prompt += "\n\nFocus on detailed security analysis and threat assessment."
            elif request.context.get("tab") == "ocr":
                base_prompt += "\n\nAssist with document analysis and text extraction tasks."
                
        return base_prompt
    
    def _extract_suggestions(self, message: str) -> List[str]:
        """Extract actionable suggestions from AI response"""
        suggestions = []
        
        # Look for numbered lists or bullet points
        lines = message.split('\n')
        for line in lines:
            line = line.strip()
            if line.startswith(('1.', '2.', '3.', '4.', '5.', '-', '*', '•')):
                clean_suggestion = line[2:].strip() if line[1] == '.' else line[1:].strip()
                if len(clean_suggestion) > 10:  # Filter out very short suggestions
                    suggestions.append(clean_suggestion)
        
        # If no structured suggestions found, create generic ones
        if not suggestions:
            if "vulnerability" in message.lower():
                suggestions = ["Scan for more vulnerabilities", "Review security configuration", "Apply security patches"]
            elif "remediation" in message.lower():
                suggestions = ["Apply recommended fixes", "Test remediation", "Verify security improvement"]
            else:
                suggestions = ["Tell me more", "Explain in detail", "Show examples"]
        
        return suggestions[:4]  # Limit to 4 suggestions
    
    def _extract_remediation(self, message: str) -> Optional[Dict]:
        """Extract remediation actions from AI response"""
        if any(keyword in message.lower() for keyword in ["fix", "patch", "update", "remediate", "resolve"]):
            return {
                "available": True,
                "actions": [
                    {
                        "title": "Apply Recommended Fix",
                        "description": "Implement the suggested security fix",
                        "type": "auto_fix"
                    },
                    {
                        "title": "Generate Security Patch",
                        "description": "Create and apply security patch",
                        "type": "patch_generation"
                    }
                ]
            }
        return None
    
    async def get_status(self) -> Dict[str, Any]:
        """Get current status of all AI providers"""
        await self._test_providers()
        return {
            "providers": self.providers_status,
            "models": {
                "openrouter": self.openrouter_model,
                "ollama": self.ollama_model,
                "embedding": self.embedding_model,
                "vision": self.vision_model
            },
            "capabilities": ["chat", "analysis", "remediation", "ocr"],
            "status": "operational" if any(status == "online" for status in self.providers_status.values()) else "degraded"
        }

# Global instance
ai_service_manager = AIServiceManager()