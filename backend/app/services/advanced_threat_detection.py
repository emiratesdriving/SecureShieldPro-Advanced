"""
Advanced Threat Detection Engine
ML-powered threat analysis with behavioral pattern recognition
"""

import asyncio
import logging
import json
import hashlib
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from enum import Enum
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.cluster import DBSCAN
import joblib
import os

logger = logging.getLogger(__name__)

class ThreatLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class ThreatCategory(Enum):
    MALWARE = "malware"
    INTRUSION = "intrusion"
    DATA_EXFILTRATION = "data_exfiltration"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"
    COMMAND_INJECTION = "command_injection"
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    ANOMALY = "anomaly"
    UNKNOWN = "unknown"

@dataclass
class ThreatIndicator:
    """Individual threat indicator"""
    indicator_type: str
    value: str
    confidence: float
    first_seen: datetime
    last_seen: datetime
    count: int
    metadata: Dict[str, Any]

@dataclass
class ThreatEvent:
    """Security threat event"""
    event_id: str
    timestamp: datetime
    source_ip: str
    target: str
    category: ThreatCategory
    level: ThreatLevel
    confidence: float
    indicators: List[ThreatIndicator]
    description: str
    mitigation: List[str]
    raw_data: Dict[str, Any]

class MLThreatDetector:
    """Machine Learning-based threat detection"""
    
    def __init__(self):
        self.isolation_forest = IsolationForest(contamination=0.1, random_state=42)
        self.tfidf_vectorizer = TfidfVectorizer(max_features=1000, stop_words='english')
        self.clustering_model = DBSCAN(eps=0.5, min_samples=5)
        self.models_trained = False
        self.models_path = "/tmp/secureshield_ml_models"
        self.load_models()
        
    def load_models(self):
        """Load pre-trained models if available"""
        try:
            if os.path.exists(f"{self.models_path}/isolation_forest.joblib"):
                self.isolation_forest = joblib.load(f"{self.models_path}/isolation_forest.joblib")
                self.tfidf_vectorizer = joblib.load(f"{self.models_path}/tfidf_vectorizer.joblib")
                self.models_trained = True
                logger.info("Loaded pre-trained ML models")
        except Exception as e:
            logger.warning(f"Could not load pre-trained models: {e}")
    
    def save_models(self):
        """Save trained models"""
        try:
            os.makedirs(self.models_path, exist_ok=True)
            joblib.dump(self.isolation_forest, f"{self.models_path}/isolation_forest.joblib")
            joblib.dump(self.tfidf_vectorizer, f"{self.models_path}/tfidf_vectorizer.joblib")
            logger.info("Saved ML models")
        except Exception as e:
            logger.error(f"Could not save models: {e}")
    
    def extract_features(self, event_data: Dict[str, Any]) -> np.ndarray:
        """Extract numerical features from event data"""
        features = []
        
        # Network features
        features.append(len(event_data.get('url', '')))
        features.append(len(event_data.get('user_agent', '')))
        features.append(event_data.get('response_code', 200))
        features.append(event_data.get('response_size', 0))
        features.append(event_data.get('request_duration', 0))
        
        # Request pattern features
        url = event_data.get('url', '')
        features.append(url.count('/'))
        features.append(url.count('?'))
        features.append(url.count('&'))
        features.append(url.count('='))
        features.append(1 if any(char in url for char in ['<', '>', '"', "'", 'script']) else 0)
        
        # Payload analysis
        payload = event_data.get('payload', '')
        features.append(len(payload))
        features.append(1 if 'union' in payload.lower() else 0)
        features.append(1 if 'select' in payload.lower() else 0)
        features.append(1 if 'drop' in payload.lower() else 0)
        features.append(1 if any(pattern in payload.lower() for pattern in ['../../../', 'etc/passwd', 'cmd.exe']) else 0)
        
        return np.array(features).reshape(1, -1)
    
    def detect_anomaly(self, event_data: Dict[str, Any]) -> Tuple[bool, float]:
        """Detect anomalies using Isolation Forest"""
        if not self.models_trained:
            return False, 0.0
        
        try:
            features = self.extract_features(event_data)
            anomaly_score = self.isolation_forest.decision_function(features)[0]
            is_anomaly = self.isolation_forest.predict(features)[0] == -1
            
            # Convert score to confidence (0-1)
            confidence = max(0, min(1, (0.5 - anomaly_score) * 2))
            
            return is_anomaly, confidence
        except Exception as e:
            logger.error(f"Anomaly detection error: {e}")
            return False, 0.0
    
    def train_baseline(self, normal_events: List[Dict[str, Any]]):
        """Train on normal/baseline events"""
        try:
            if len(normal_events) < 10:
                logger.warning("Not enough training data for ML models")
                return
            
            features = np.vstack([self.extract_features(event) for event in normal_events])
            self.isolation_forest.fit(features)
            
            # Train text vectorizer on URLs and payloads
            texts = []
            for event in normal_events:
                texts.append(f"{event.get('url', '')} {event.get('payload', '')}")
            
            if texts:
                self.tfidf_vectorizer.fit(texts)
            
            self.models_trained = True
            self.save_models()
            logger.info(f"Trained ML models on {len(normal_events)} normal events")
            
        except Exception as e:
            logger.error(f"Training error: {e}")

class ThreatIntelligence:
    """Threat intelligence and IOC management"""
    
    def __init__(self):
        self.known_bad_ips = set()
        self.known_bad_domains = set()
        self.malware_hashes = set()
        self.suspicious_patterns = []
        self.load_threat_intelligence()
    
    def load_threat_intelligence(self):
        """Load threat intelligence data"""
        # Sample threat indicators (in production, load from threat feeds)
        self.known_bad_ips.update([
            "192.168.1.100",  # Sample malicious IP
            "10.0.0.50",
            "172.16.0.25"
        ])
        
        self.known_bad_domains.update([
            "malicious-site.com",
            "phishing-example.net",
            "malware-c2.org"
        ])
        
        self.malware_hashes.update([
            "5d41402abc4b2a76b9719d911017c592",  # Sample hash
            "098f6bcd4621d373cade4e832627b4f6"
        ])
        
        self.suspicious_patterns = [
            r"(?i)union\s+select",
            r"(?i)drop\s+table",
            r"(?i)<script>",
            r"(?i)javascript:",
            r"\.\.\/\.\.\/",
            r"etc\/passwd",
            r"cmd\.exe",
            r"powershell",
            r"base64"
        ]
        
        logger.info("Loaded threat intelligence data")
    
    def check_ip_reputation(self, ip: str) -> Dict[str, Any]:
        """Check IP reputation"""
        is_malicious = ip in self.known_bad_ips
        return {
            "is_malicious": is_malicious,
            "confidence": 0.9 if is_malicious else 0.0,
            "source": "threat_intelligence"
        }
    
    def check_domain_reputation(self, domain: str) -> Dict[str, Any]:
        """Check domain reputation"""
        is_malicious = domain in self.known_bad_domains
        return {
            "is_malicious": is_malicious,
            "confidence": 0.9 if is_malicious else 0.0,
            "source": "threat_intelligence"
        }
    
    def analyze_payload(self, payload: str) -> Dict[str, Any]:
        """Analyze payload for suspicious patterns"""
        import re
        
        threats = []
        max_confidence = 0.0
        
        for pattern in self.suspicious_patterns:
            if re.search(pattern, payload):
                confidence = 0.8
                threats.append({
                    "pattern": pattern,
                    "confidence": confidence
                })
                max_confidence = max(max_confidence, confidence)
        
        return {
            "threats_found": threats,
            "confidence": max_confidence,
            "is_suspicious": max_confidence > 0.5
        }

class BehavioralAnalyzer:
    """Behavioral analysis for detecting advanced threats"""
    
    def __init__(self):
        self.user_profiles = {}
        self.baseline_metrics = {}
        self.activity_windows = {}
    
    def update_user_profile(self, user_id: str, activity: Dict[str, Any]):
        """Update user behavioral profile"""
        if user_id not in self.user_profiles:
            self.user_profiles[user_id] = {
                "login_times": [],
                "ip_addresses": set(),
                "user_agents": set(),
                "access_patterns": [],
                "failed_logins": 0,
                "first_seen": datetime.now(),
                "last_seen": datetime.now()
            }
        
        profile = self.user_profiles[user_id]
        profile["last_seen"] = datetime.now()
        
        if activity.get("login_time"):
            profile["login_times"].append(activity["login_time"])
        
        if activity.get("ip_address"):
            profile["ip_addresses"].add(activity["ip_address"])
        
        if activity.get("user_agent"):
            profile["user_agents"].add(activity["user_agent"])
        
        if activity.get("failed_login"):
            profile["failed_logins"] += 1
    
    def detect_anomalous_behavior(self, user_id: str, current_activity: Dict[str, Any]) -> Dict[str, Any]:
        """Detect anomalous user behavior"""
        if user_id not in self.user_profiles:
            return {"is_anomalous": False, "confidence": 0.0, "reasons": []}
        
        profile = self.user_profiles[user_id]
        anomalies = []
        confidence = 0.0
        
        # Check for unusual login times
        current_hour = datetime.now().hour
        typical_hours = [dt.hour for dt in profile["login_times"][-50:]]  # Last 50 logins
        if typical_hours and current_hour not in set(typical_hours):
            anomalies.append("Unusual login time")
            confidence = max(confidence, 0.6)
        
        # Check for new IP addresses
        current_ip = current_activity.get("ip_address")
        if current_ip and current_ip not in profile["ip_addresses"]:
            anomalies.append("New IP address")
            confidence = max(confidence, 0.7)
        
        # Check for excessive failed logins
        if profile["failed_logins"] > 10:
            anomalies.append("Excessive failed login attempts")
            confidence = max(confidence, 0.9)
        
        # Check for rapid access pattern changes
        if len(profile["user_agents"]) > 5:  # Multiple user agents
            anomalies.append("Multiple user agents")
            confidence = max(confidence, 0.5)
        
        return {
            "is_anomalous": confidence > 0.5,
            "confidence": confidence,
            "reasons": anomalies
        }

class AdvancedThreatDetectionEngine:
    """Main advanced threat detection engine"""
    
    def __init__(self):
        self.ml_detector = MLThreatDetector()
        self.threat_intel = ThreatIntelligence()
        self.behavioral_analyzer = BehavioralAnalyzer()
        self.detected_threats = []
        self.correlation_rules = self.load_correlation_rules()
        
    def load_correlation_rules(self) -> List[Dict[str, Any]]:
        """Load threat correlation rules"""
        return [
            {
                "name": "Multiple Failed Logins + New IP",
                "conditions": ["failed_login_spike", "new_ip_address"],
                "threat_level": ThreatLevel.HIGH,
                "confidence": 0.8
            },
            {
                "name": "SQL Injection + Admin Access",
                "conditions": ["sql_injection_pattern", "admin_endpoint"],
                "threat_level": ThreatLevel.CRITICAL,
                "confidence": 0.9
            },
            {
                "name": "Anomalous Behavior + Privilege Escalation",
                "conditions": ["behavioral_anomaly", "privilege_change"],
                "threat_level": ThreatLevel.HIGH,
                "confidence": 0.85
            }
        ]
    
    async def analyze_event(self, event_data: Dict[str, Any]) -> Optional[ThreatEvent]:
        """Comprehensive threat analysis of an event"""
        try:
            threat_indicators = []
            max_confidence = 0.0
            threat_category = ThreatCategory.UNKNOWN
            threat_level = ThreatLevel.LOW
            
            # ML-based anomaly detection
            is_anomaly, anomaly_confidence = self.ml_detector.detect_anomaly(event_data)
            if is_anomaly:
                threat_indicators.append(ThreatIndicator(
                    indicator_type="ml_anomaly",
                    value=f"Anomaly score: {anomaly_confidence:.2f}",
                    confidence=anomaly_confidence,
                    first_seen=datetime.now(),
                    last_seen=datetime.now(),
                    count=1,
                    metadata={"detector": "isolation_forest"}
                ))
                max_confidence = max(max_confidence, anomaly_confidence)
                threat_category = ThreatCategory.ANOMALY
            
            # IP reputation check
            source_ip = event_data.get("source_ip", "")
            if source_ip:
                ip_rep = self.threat_intel.check_ip_reputation(source_ip)
                if ip_rep["is_malicious"]:
                    threat_indicators.append(ThreatIndicator(
                        indicator_type="malicious_ip",
                        value=source_ip,
                        confidence=ip_rep["confidence"],
                        first_seen=datetime.now(),
                        last_seen=datetime.now(),
                        count=1,
                        metadata={"source": ip_rep["source"]}
                    ))
                    max_confidence = max(max_confidence, ip_rep["confidence"])
                    threat_category = ThreatCategory.INTRUSION
            
            # Payload analysis
            payload = event_data.get("payload", "")
            if payload:
                payload_analysis = self.threat_intel.analyze_payload(payload)
                if payload_analysis["is_suspicious"]:
                    for threat in payload_analysis["threats_found"]:
                        threat_indicators.append(ThreatIndicator(
                            indicator_type="suspicious_pattern",
                            value=threat["pattern"],
                            confidence=threat["confidence"],
                            first_seen=datetime.now(),
                            last_seen=datetime.now(),
                            count=1,
                            metadata={"pattern_type": "regex"}
                        ))
                        
                        # Categorize based on pattern
                        pattern = threat["pattern"].lower()
                        if "union" in pattern or "select" in pattern:
                            threat_category = ThreatCategory.SQL_INJECTION
                        elif "script" in pattern:
                            threat_category = ThreatCategory.XSS
                        elif "cmd" in pattern or "powershell" in pattern:
                            threat_category = ThreatCategory.COMMAND_INJECTION
                    
                    max_confidence = max(max_confidence, payload_analysis["confidence"])
            
            # Behavioral analysis
            user_id = event_data.get("user_id")
            if user_id:
                behavioral_result = self.behavioral_analyzer.detect_anomalous_behavior(user_id, event_data)
                if behavioral_result["is_anomalous"]:
                    threat_indicators.append(ThreatIndicator(
                        indicator_type="behavioral_anomaly",
                        value=", ".join(behavioral_result["reasons"]),
                        confidence=behavioral_result["confidence"],
                        first_seen=datetime.now(),
                        last_seen=datetime.now(),
                        count=1,
                        metadata={"reasons": behavioral_result["reasons"]}
                    ))
                    max_confidence = max(max_confidence, behavioral_result["confidence"])
                    if threat_category == ThreatCategory.UNKNOWN:
                        threat_category = ThreatCategory.ANOMALY
            
            # Determine threat level
            if max_confidence >= 0.9:
                threat_level = ThreatLevel.CRITICAL
            elif max_confidence >= 0.7:
                threat_level = ThreatLevel.HIGH
            elif max_confidence >= 0.5:
                threat_level = ThreatLevel.MEDIUM
            else:
                threat_level = ThreatLevel.LOW
            
            # Only create threat event if confidence is above threshold
            if max_confidence > 0.5:
                event_id = hashlib.md5(f"{datetime.now().isoformat()}{source_ip}{payload}".encode()).hexdigest()
                
                # Generate mitigation strategies
                mitigation = self.generate_mitigation(threat_category, threat_indicators)
                
                threat_event = ThreatEvent(
                    event_id=event_id,
                    timestamp=datetime.now(),
                    source_ip=source_ip,
                    target=event_data.get("target", ""),
                    category=threat_category,
                    level=threat_level,
                    confidence=max_confidence,
                    indicators=threat_indicators,
                    description=self.generate_description(threat_category, threat_indicators),
                    mitigation=mitigation,
                    raw_data=event_data
                )
                
                self.detected_threats.append(threat_event)
                logger.warning(f"Threat detected: {threat_category.value} with confidence {max_confidence:.2f}")
                
                return threat_event
            
            return None
            
        except Exception as e:
            logger.error(f"Threat analysis error: {e}")
            return None
    
    def generate_description(self, category: ThreatCategory, indicators: List[ThreatIndicator]) -> str:
        """Generate human-readable threat description"""
        descriptions = {
            ThreatCategory.SQL_INJECTION: "SQL injection attack detected in request payload",
            ThreatCategory.XSS: "Cross-site scripting (XSS) attempt identified",
            ThreatCategory.COMMAND_INJECTION: "Command injection pattern detected",
            ThreatCategory.INTRUSION: "Potential intrusion from malicious IP address",
            ThreatCategory.ANOMALY: "Anomalous behavior pattern detected",
            ThreatCategory.MALWARE: "Malware signature or hash detected",
            ThreatCategory.DATA_EXFILTRATION: "Potential data exfiltration activity",
            ThreatCategory.PRIVILEGE_ESCALATION: "Privilege escalation attempt detected"
        }
        
        base_description = descriptions.get(category, "Security threat detected")
        
        if indicators:
            details = [f"{ind.indicator_type}: {ind.value}" for ind in indicators[:3]]
            return f"{base_description}. Indicators: {'; '.join(details)}"
        
        return base_description
    
    def generate_mitigation(self, category: ThreatCategory, indicators: List[ThreatIndicator]) -> List[str]:
        """Generate mitigation recommendations"""
        mitigations = {
            ThreatCategory.SQL_INJECTION: [
                "Implement parameterized queries",
                "Enable SQL injection protection",
                "Validate and sanitize all user inputs",
                "Apply principle of least privilege to database accounts"
            ],
            ThreatCategory.XSS: [
                "Enable Content Security Policy (CSP)",
                "Sanitize and encode user inputs",
                "Use XSS protection headers",
                "Implement input validation"
            ],
            ThreatCategory.COMMAND_INJECTION: [
                "Disable command execution functions",
                "Implement strict input validation",
                "Use command whitelisting",
                "Run applications with minimal privileges"
            ],
            ThreatCategory.INTRUSION: [
                "Block suspicious IP address",
                "Enable rate limiting",
                "Implement IP whitelisting",
                "Monitor for lateral movement"
            ],
            ThreatCategory.ANOMALY: [
                "Review user access permissions",
                "Enable multi-factor authentication",
                "Monitor user behavior patterns",
                "Implement session timeout"
            ]
        }
        
        return mitigations.get(category, ["Monitor activity closely", "Apply security best practices"])
    
    async def get_threat_summary(self, time_window: timedelta = timedelta(hours=24)) -> Dict[str, Any]:
        """Get threat detection summary"""
        cutoff = datetime.now() - time_window
        recent_threats = [t for t in self.detected_threats if t.timestamp > cutoff]
        
        category_counts = {}
        level_counts = {}
        
        for threat in recent_threats:
            category_counts[threat.category.value] = category_counts.get(threat.category.value, 0) + 1
            level_counts[threat.level.value] = level_counts.get(threat.level.value, 0) + 1
        
        return {
            "total_threats": len(recent_threats),
            "threats_by_category": category_counts,
            "threats_by_level": level_counts,
            "avg_confidence": sum(t.confidence for t in recent_threats) / len(recent_threats) if recent_threats else 0,
            "latest_threats": [
                {
                    "event_id": t.event_id,
                    "timestamp": t.timestamp.isoformat(),
                    "category": t.category.value,
                    "level": t.level.value,
                    "confidence": t.confidence,
                    "description": t.description
                }
                for t in sorted(recent_threats, key=lambda x: x.timestamp, reverse=True)[:10]
            ]
        }

# Global instance
advanced_threat_detector = AdvancedThreatDetectionEngine()