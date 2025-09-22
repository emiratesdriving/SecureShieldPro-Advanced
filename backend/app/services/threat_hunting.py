"""
Advanced Threat Hunting Engine
Real-time behavioral analytics, anomaly detection, and automated incident response
"""

import asyncio
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from enum import Enum
import re
import statistics
from dataclasses import dataclass
from collections import defaultdict, deque
import numpy as np

logger = logging.getLogger(__name__)

class ThreatCategory(Enum):
    APT = "advanced_persistent_threat"
    MALWARE = "malware"
    INSIDER_THREAT = "insider_threat"
    DATA_EXFILTRATION = "data_exfiltration"
    LATERAL_MOVEMENT = "lateral_movement"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    COMMAND_CONTROL = "command_control"
    RECONNAISSANCE = "reconnaissance"
    PERSISTENCE = "persistence"
    DEFENSE_EVASION = "defense_evasion"

class AlertSeverity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class HuntingStatus(Enum):
    ACTIVE = "active"
    INVESTIGATING = "investigating"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    RESOLVED = "resolved"

@dataclass
class ThreatIndicator:
    """Threat indicator with context and metadata"""
    id: str
    type: str  # ip, domain, hash, user, process
    value: str
    confidence: float
    severity: AlertSeverity
    category: ThreatCategory
    first_seen: datetime
    last_seen: datetime
    occurrences: int
    context: Dict[str, Any]
    related_indicators: List[str]

@dataclass
class BehavioralAnomaly:
    """Behavioral anomaly detection result"""
    id: str
    entity_type: str  # user, host, network
    entity_id: str
    anomaly_type: str
    confidence: float
    severity: AlertSeverity
    baseline_value: float
    observed_value: float
    deviation_score: float
    detected_at: datetime
    context: Dict[str, Any]

@dataclass
class ThreatHunt:
    """Active threat hunting investigation"""
    id: str
    name: str
    description: str
    category: ThreatCategory
    status: HuntingStatus
    confidence: float
    indicators: List[ThreatIndicator]
    anomalies: List[BehavioralAnomaly]
    timeline: List[Dict[str, Any]]
    artifacts: List[Dict[str, Any]]
    created_at: datetime
    updated_at: datetime
    assigned_analyst: Optional[str]
    priority: int

class AdvancedThreatHunter:
    """Advanced AI-powered threat hunting engine"""
    
    def __init__(self):
        self.active_hunts: Dict[str, ThreatHunt] = {}
        self.threat_indicators: Dict[str, ThreatIndicator] = {}
        self.behavioral_baselines: Dict[str, Dict[str, float]] = {}
        self.detection_rules: List[Dict[str, Any]] = []
        self.ml_models = {}
        self.event_buffer = deque(maxlen=100000)  # Rolling event buffer
        self.correlation_engine = ThreatCorrelationEngine()
        
        # Initialize AI models and detection rules
        asyncio.create_task(self._initialize_hunting_systems())
    
    async def _initialize_hunting_systems(self):
        """Initialize threat hunting AI systems"""
        # Load ML models for different detection scenarios
        self.ml_models = {
            "anomaly_detector": self._load_anomaly_detection_model(),
            "sequence_analyzer": self._load_sequence_analysis_model(),
            "network_behavior": self._load_network_behavior_model(),
            "user_behavior": self._load_user_behavior_model(),
            "lateral_movement": self._load_lateral_movement_model(),
            "command_control": self._load_c2_detection_model()
        }
        
        # Load behavioral baselines
        await self._load_behavioral_baselines()
        
        # Initialize detection rules
        self._initialize_detection_rules()
        
        logger.info("Advanced threat hunting systems initialized")
    
    def _load_anomaly_detection_model(self) -> Dict[str, Any]:
        """Load anomaly detection ML model"""
        return {
            "model_type": "isolation_forest",
            "features": [
                "login_frequency", "data_access_volume", "network_connections",
                "process_execution_rate", "file_modifications", "privilege_escalations"
            ],
            "sensitivity": 0.95,
            "contamination": 0.05
        }
    
    def _load_sequence_analysis_model(self) -> Dict[str, Any]:
        """Load sequence analysis model for attack pattern detection"""
        return {
            "model_type": "lstm_sequence",
            "window_size": 10,
            "features": ["event_type", "source_ip", "destination_ip", "user", "process"],
            "attack_patterns": [
                "mitre_t1078",  # Valid Accounts
                "mitre_t1055",  # Process Injection
                "mitre_t1021",  # Remote Services
                "mitre_t1083",  # File and Directory Discovery
            ]
        }
    
    def _load_network_behavior_model(self) -> Dict[str, Any]:
        """Load network behavior analysis model"""
        return {
            "model_type": "graph_neural_network",
            "features": ["connection_frequency", "data_volume", "protocol_distribution"],
            "detection_capabilities": [
                "dns_tunneling", "beacon_activity", "data_exfiltration",
                "lateral_movement", "c2_communication"
            ]
        }
    
    def _load_user_behavior_model(self) -> Dict[str, Any]:
        """Load user behavior analytics model"""
        return {
            "model_type": "ensemble_classifier",
            "algorithms": ["random_forest", "gradient_boosting", "neural_network"],
            "features": [
                "login_times", "access_patterns", "data_access_volume",
                "geographic_location", "device_fingerprint", "application_usage"
            ]
        }
    
    def _load_lateral_movement_model(self) -> Dict[str, Any]:
        """Load lateral movement detection model"""
        return {
            "model_type": "temporal_convolution",
            "detection_techniques": [
                "pass_the_hash", "pass_the_ticket", "remote_desktop",
                "psexec", "wmi_execution", "ssh_tunneling"
            ]
        }
    
    def _load_c2_detection_model(self) -> Dict[str, Any]:
        """Load command and control detection model"""
        return {
            "model_type": "deep_packet_inspection",
            "detection_methods": [
                "domain_generation_algorithm", "fast_flux", "beacon_analysis",
                "protocol_anomalies", "encrypted_tunneling"
            ]
        }
    
    async def _load_behavioral_baselines(self):
        """Load or calculate behavioral baselines"""
        # Mock baselines - in production, these would be calculated from historical data
        self.behavioral_baselines = {
            "user_login_frequency": {"mean": 8.5, "std": 2.1},
            "data_access_volume": {"mean": 150.0, "std": 45.0},
            "network_connections": {"mean": 25.0, "std": 8.0},
            "process_executions": {"mean": 35.0, "std": 12.0},
            "file_modifications": {"mean": 12.0, "std": 5.0},
            "privilege_escalations": {"mean": 0.1, "std": 0.3}
        }
    
    def _initialize_detection_rules(self):
        """Initialize threat detection rules"""
        self.detection_rules = [
            {
                "id": "rule_001",
                "name": "Suspicious Login Patterns",
                "category": ThreatCategory.INSIDER_THREAT,
                "logic": "multiple_failed_logins AND unusual_time AND unusual_location",
                "threshold": 0.8,
                "enabled": True
            },
            {
                "id": "rule_002", 
                "name": "Data Exfiltration Indicators",
                "category": ThreatCategory.DATA_EXFILTRATION,
                "logic": "large_data_transfer AND unusual_destination AND compression_activity",
                "threshold": 0.7,
                "enabled": True
            },
            {
                "id": "rule_003",
                "name": "Lateral Movement Detection",
                "category": ThreatCategory.LATERAL_MOVEMENT,
                "logic": "credential_access AND remote_execution AND privilege_escalation",
                "threshold": 0.75,
                "enabled": True
            },
            {
                "id": "rule_004",
                "name": "Command and Control Communication",
                "category": ThreatCategory.COMMAND_CONTROL,
                "logic": "beacon_pattern AND encrypted_communication AND unusual_domain",
                "threshold": 0.8,
                "enabled": True
            }
        ]
    
    async def process_security_event(self, event: Dict[str, Any]) -> List[ThreatIndicator]:
        """Process incoming security event for threat detection"""
        try:
            # Add event to buffer
            event_with_timestamp = {**event, "processed_at": datetime.now()}
            self.event_buffer.append(event_with_timestamp)
            
            detected_indicators = []
            
            # Run behavioral analysis
            anomalies = await self._detect_behavioral_anomalies(event)
            
            # Run rule-based detection
            rule_matches = await self._evaluate_detection_rules(event)
            
            # Run ML-based detection
            ml_indicators = await self._ml_threat_detection(event)
            
            # Correlate with existing indicators
            correlated_threats = await self.correlation_engine.correlate_events([event])
            
            # Generate threat indicators
            for anomaly in anomalies:
                indicator = await self._create_threat_indicator_from_anomaly(anomaly)
                if indicator:
                    detected_indicators.append(indicator)
                    self.threat_indicators[indicator.id] = indicator
            
            for rule_match in rule_matches:
                indicator = await self._create_threat_indicator_from_rule(rule_match, event)
                if indicator:
                    detected_indicators.append(indicator)
                    self.threat_indicators[indicator.id] = indicator
            
            # Update or create threat hunts
            await self._update_threat_hunts(detected_indicators, event)
            
            return detected_indicators
            
        except Exception as e:
            logger.error(f"Error processing security event: {str(e)}")
            return []
    
    async def _detect_behavioral_anomalies(self, event: Dict[str, Any]) -> List[BehavioralAnomaly]:
        """Detect behavioral anomalies using ML models"""
        anomalies = []
        
        try:
            # Extract behavioral features from event
            features = self._extract_behavioral_features(event)
            
            # Check each feature against baseline
            for feature_name, value in features.items():
                if feature_name in self.behavioral_baselines:
                    baseline = self.behavioral_baselines[feature_name]
                    
                    # Calculate z-score
                    z_score = abs((value - baseline["mean"]) / baseline["std"])
                    
                    # Detect anomaly if z-score exceeds threshold
                    if z_score > 3.0:  # 3 standard deviations
                        anomaly = BehavioralAnomaly(
                            id=f"anomaly_{datetime.now().timestamp()}",
                            entity_type=event.get("entity_type", "unknown"),
                            entity_id=event.get("entity_id", "unknown"),
                            anomaly_type=feature_name,
                            confidence=min(z_score / 5.0, 1.0),
                            severity=self._calculate_anomaly_severity(z_score),
                            baseline_value=baseline["mean"],
                            observed_value=value,
                            deviation_score=z_score,
                            detected_at=datetime.now(),
                            context={"event": event, "baseline": baseline}
                        )
                        anomalies.append(anomaly)
            
            return anomalies
            
        except Exception as e:
            logger.error(f"Behavioral anomaly detection failed: {str(e)}")
            return []
    
    def _extract_behavioral_features(self, event: Dict[str, Any]) -> Dict[str, float]:
        """Extract behavioral features from security event"""
        features = {}
        
        # Extract relevant metrics based on event type
        event_type = event.get("type", "").lower()
        
        if "login" in event_type:
            features["user_login_frequency"] = event.get("login_count", 1.0)
            
        if "data_access" in event_type:
            features["data_access_volume"] = event.get("bytes_accessed", 0.0)
            
        if "network" in event_type:
            features["network_connections"] = event.get("connection_count", 1.0)
            
        if "process" in event_type:
            features["process_executions"] = event.get("process_count", 1.0)
            
        if "file" in event_type:
            features["file_modifications"] = event.get("file_count", 1.0)
            
        if "privilege" in event_type:
            features["privilege_escalations"] = event.get("escalation_count", 1.0)
        
        return features
    
    def _calculate_anomaly_severity(self, z_score: float) -> AlertSeverity:
        """Calculate anomaly severity based on deviation score"""
        if z_score > 5.0:
            return AlertSeverity.CRITICAL
        elif z_score > 4.0:
            return AlertSeverity.HIGH
        elif z_score > 3.5:
            return AlertSeverity.MEDIUM
        else:
            return AlertSeverity.LOW
    
    async def _evaluate_detection_rules(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Evaluate detection rules against event"""
        rule_matches = []
        
        for rule in self.detection_rules:
            if not rule["enabled"]:
                continue
                
            try:
                # Simplified rule evaluation (in production, use proper rule engine)
                confidence = await self._evaluate_rule_logic(rule, event)
                
                if confidence >= rule["threshold"]:
                    rule_matches.append({
                        "rule": rule,
                        "confidence": confidence,
                        "event": event,
                        "matched_at": datetime.now()
                    })
                    
            except Exception as e:
                logger.error(f"Rule evaluation failed for {rule['id']}: {str(e)}")
        
        return rule_matches
    
    async def _evaluate_rule_logic(self, rule: Dict[str, Any], event: Dict[str, Any]) -> float:
        """Evaluate rule logic against event (simplified implementation)"""
        logic = rule["logic"].lower()
        event_type = event.get("type", "").lower()
        
        # Mock rule evaluation based on event characteristics
        confidence = 0.0
        
        if "login" in logic and "login" in event_type:
            confidence += 0.3
            
        if "failed" in logic and event.get("status") == "failed":
            confidence += 0.4
            
        if "unusual_time" in logic:
            hour = datetime.now().hour
            if hour < 6 or hour > 22:  # Outside business hours
                confidence += 0.3
                
        if "data_transfer" in logic and "network" in event_type:
            confidence += 0.4
            
        if "large" in logic and event.get("size", 0) > 1000000:  # > 1MB
            confidence += 0.3
        
        return min(confidence, 1.0)
    
    async def _ml_threat_detection(self, event: Dict[str, Any]) -> List[ThreatIndicator]:
        """ML-based threat detection"""
        indicators = []
        
        try:
            # Simulate ML model predictions
            for model_name, model_config in self.ml_models.items():
                prediction = await self._run_ml_model(model_name, model_config, event)
                
                if prediction["confidence"] > 0.7:
                    indicator = ThreatIndicator(
                        id=f"ml_{model_name}_{datetime.now().timestamp()}",
                        type="ml_detection",
                        value=prediction["threat_type"],
                        confidence=prediction["confidence"],
                        severity=self._ml_confidence_to_severity(prediction["confidence"]),
                        category=ThreatCategory(prediction.get("category", "reconnaissance")),
                        first_seen=datetime.now(),
                        last_seen=datetime.now(),
                        occurrences=1,
                        context={"model": model_name, "event": event, "prediction": prediction},
                        related_indicators=[]
                    )
                    indicators.append(indicator)
            
            return indicators
            
        except Exception as e:
            logger.error(f"ML threat detection failed: {str(e)}")
            return []
    
    async def _run_ml_model(self, model_name: str, model_config: Dict[str, Any], event: Dict[str, Any]) -> Dict[str, Any]:
        """Run ML model for threat detection"""
        # Simulate ML model execution
        await asyncio.sleep(0.1)  # Simulate processing time
        
        # Mock predictions based on model type
        if model_name == "anomaly_detector":
            return {
                "threat_type": "behavioral_anomaly",
                "confidence": 0.85,
                "category": "insider_threat"
            }
        elif model_name == "sequence_analyzer":
            return {
                "threat_type": "attack_sequence",
                "confidence": 0.78,
                "category": "lateral_movement"
            }
        elif model_name == "network_behavior":
            return {
                "threat_type": "suspicious_network_activity",
                "confidence": 0.72,
                "category": "command_control"
            }
        else:
            return {
                "threat_type": "unknown_pattern",
                "confidence": 0.6,
                "category": "reconnaissance"
            }
    
    def _ml_confidence_to_severity(self, confidence: float) -> AlertSeverity:
        """Convert ML confidence to alert severity"""
        if confidence > 0.9:
            return AlertSeverity.CRITICAL
        elif confidence > 0.8:
            return AlertSeverity.HIGH
        elif confidence > 0.7:
            return AlertSeverity.MEDIUM
        else:
            return AlertSeverity.LOW
    
    async def _create_threat_indicator_from_anomaly(self, anomaly: BehavioralAnomaly) -> Optional[ThreatIndicator]:
        """Create threat indicator from behavioral anomaly"""
        try:
            return ThreatIndicator(
                id=f"threat_{anomaly.id}",
                type="behavioral_anomaly",
                value=f"{anomaly.entity_type}:{anomaly.entity_id}",
                confidence=anomaly.confidence,
                severity=anomaly.severity,
                category=ThreatCategory.INSIDER_THREAT,
                first_seen=anomaly.detected_at,
                last_seen=anomaly.detected_at,
                occurrences=1,
                context={"anomaly": anomaly.__dict__},
                related_indicators=[]
            )
        except Exception as e:
            logger.error(f"Failed to create indicator from anomaly: {str(e)}")
            return None
    
    async def _create_threat_indicator_from_rule(self, rule_match: Dict[str, Any], event: Dict[str, Any]) -> Optional[ThreatIndicator]:
        """Create threat indicator from rule match"""
        try:
            rule = rule_match["rule"]
            
            return ThreatIndicator(
                id=f"threat_rule_{rule['id']}_{datetime.now().timestamp()}",
                type="rule_match",
                value=rule["name"],
                confidence=rule_match["confidence"],
                severity=self._rule_confidence_to_severity(rule_match["confidence"]),
                category=rule["category"],
                first_seen=rule_match["matched_at"],
                last_seen=rule_match["matched_at"],
                occurrences=1,
                context={"rule": rule, "event": event},
                related_indicators=[]
            )
        except Exception as e:
            logger.error(f"Failed to create indicator from rule: {str(e)}")
            return None
    
    def _rule_confidence_to_severity(self, confidence: float) -> AlertSeverity:
        """Convert rule confidence to alert severity"""
        if confidence > 0.9:
            return AlertSeverity.CRITICAL
        elif confidence > 0.8:
            return AlertSeverity.HIGH
        elif confidence > 0.7:
            return AlertSeverity.MEDIUM
        else:
            return AlertSeverity.LOW
    
    async def _update_threat_hunts(self, indicators: List[ThreatIndicator], event: Dict[str, Any]):
        """Update or create threat hunts based on indicators"""
        try:
            for indicator in indicators:
                # Find existing hunt or create new one
                hunt = await self._find_or_create_hunt(indicator)
                
                # Update hunt with new indicator
                hunt.indicators.append(indicator)
                hunt.timeline.append({
                    "timestamp": datetime.now(),
                    "event_type": "indicator_added",
                    "indicator_id": indicator.id,
                    "event": event
                })
                hunt.updated_at = datetime.now()
                
                # Update hunt confidence and priority
                hunt.confidence = await self._calculate_hunt_confidence(hunt)
                hunt.priority = await self._calculate_hunt_priority(hunt)
                
                self.active_hunts[hunt.id] = hunt
                
        except Exception as e:
            logger.error(f"Failed to update threat hunts: {str(e)}")
    
    async def _find_or_create_hunt(self, indicator: ThreatIndicator) -> ThreatHunt:
        """Find existing hunt or create new one for indicator"""
        # Look for existing hunt with same category
        for hunt in self.active_hunts.values():
            if (hunt.category == indicator.category and 
                hunt.status in [HuntingStatus.ACTIVE, HuntingStatus.INVESTIGATING]):
                return hunt
        
        # Create new hunt
        hunt_id = f"hunt_{datetime.now().timestamp()}"
        return ThreatHunt(
            id=hunt_id,
            name=f"Hunt: {indicator.category.value.replace('_', ' ').title()}",
            description=f"Automated threat hunt for {indicator.category.value}",
            category=indicator.category,
            status=HuntingStatus.ACTIVE,
            confidence=indicator.confidence,
            indicators=[],
            anomalies=[],
            timeline=[],
            artifacts=[],
            created_at=datetime.now(),
            updated_at=datetime.now(),
            assigned_analyst=None,
            priority=1
        )
    
    async def _calculate_hunt_confidence(self, hunt: ThreatHunt) -> float:
        """Calculate overall hunt confidence"""
        if not hunt.indicators:
            return 0.0
        
        # Weight recent indicators more heavily
        total_confidence = 0.0
        total_weight = 0.0
        
        for indicator in hunt.indicators:
            age_hours = (datetime.now() - indicator.first_seen).total_seconds() / 3600
            weight = max(1.0 - (age_hours / 24), 0.1)  # Decay over 24 hours
            
            total_confidence += indicator.confidence * weight
            total_weight += weight
        
        return total_confidence / total_weight if total_weight > 0 else 0.0
    
    async def _calculate_hunt_priority(self, hunt: ThreatHunt) -> int:
        """Calculate hunt priority (1-5, 5 being highest)"""
        priority = 1
        
        # High confidence increases priority
        if hunt.confidence > 0.8:
            priority += 2
        elif hunt.confidence > 0.6:
            priority += 1
        
        # Critical severity increases priority
        critical_indicators = sum(1 for i in hunt.indicators if i.severity == AlertSeverity.CRITICAL)
        if critical_indicators > 0:
            priority += 2
        
        # Multiple indicators increase priority
        if len(hunt.indicators) > 3:
            priority += 1
        
        return min(priority, 5)
    
    async def get_active_hunts(self) -> List[ThreatHunt]:
        """Get all active threat hunts"""
        return list(self.active_hunts.values())
    
    async def get_hunt_by_id(self, hunt_id: str) -> Optional[ThreatHunt]:
        """Get specific threat hunt by ID"""
        return self.active_hunts.get(hunt_id)
    
    async def update_hunt_status(self, hunt_id: str, status: HuntingStatus, analyst: Optional[str] = None) -> bool:
        """Update threat hunt status"""
        try:
            if hunt_id in self.active_hunts:
                hunt = self.active_hunts[hunt_id]
                hunt.status = status
                hunt.updated_at = datetime.now()
                if analyst:
                    hunt.assigned_analyst = analyst
                
                hunt.timeline.append({
                    "timestamp": datetime.now(),
                    "event_type": "status_changed",
                    "old_status": hunt.status.value,
                    "new_status": status.value,
                    "analyst": analyst
                })
                
                return True
            return False
        except Exception as e:
            logger.error(f"Failed to update hunt status: {str(e)}")
            return False
    
    async def get_threat_hunting_metrics(self) -> Dict[str, Any]:
        """Get threat hunting performance metrics"""
        try:
            hunts = list(self.active_hunts.values())
            
            # Calculate metrics
            total_hunts = len(hunts)
            active_hunts = len([h for h in hunts if h.status == HuntingStatus.ACTIVE])
            investigating_hunts = len([h for h in hunts if h.status == HuntingStatus.INVESTIGATING])
            resolved_hunts = len([h for h in hunts if h.status == HuntingStatus.RESOLVED])
            
            avg_confidence = statistics.mean([h.confidence for h in hunts]) if hunts else 0.0
            
            # Category distribution
            category_counts = defaultdict(int)
            for hunt in hunts:
                category_counts[hunt.category.value] += 1
            
            # Severity distribution
            severity_counts = defaultdict(int)
            for hunt in hunts:
                for indicator in hunt.indicators:
                    severity_counts[indicator.severity.value] += 1
            
            return {
                "total_hunts": total_hunts,
                "active_hunts": active_hunts,
                "investigating_hunts": investigating_hunts,
                "resolved_hunts": resolved_hunts,
                "average_confidence": round(avg_confidence, 2),
                "category_distribution": dict(category_counts),
                "severity_distribution": dict(severity_counts),
                "total_indicators": len(self.threat_indicators),
                "detection_rules": len([r for r in self.detection_rules if r["enabled"]]),
                "ml_models_active": len(self.ml_models)
            }
            
        except Exception as e:
            logger.error(f"Failed to get metrics: {str(e)}")
            return {}


class ThreatCorrelationEngine:
    """Advanced threat correlation and attribution engine"""
    
    def __init__(self):
        self.correlation_rules = []
        self.attack_patterns = {}
        self.attribution_models = {}
        
    async def correlate_events(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Correlate events to identify attack patterns"""
        correlations = []
        
        try:
            # Time-based correlation
            time_correlations = await self._correlate_by_time(events)
            correlations.extend(time_correlations)
            
            # Entity-based correlation
            entity_correlations = await self._correlate_by_entity(events)
            correlations.extend(entity_correlations)
            
            # Pattern-based correlation
            pattern_correlations = await self._correlate_by_pattern(events)
            correlations.extend(pattern_correlations)
            
            return correlations
            
        except Exception as e:
            logger.error(f"Event correlation failed: {str(e)}")
            return []
    
    async def _correlate_by_time(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Correlate events within time windows"""
        correlations = []
        
        # Group events by time windows (e.g., 5-minute windows)
        time_windows = defaultdict(list)
        for event in events:
            timestamp = event.get("timestamp", datetime.now())
            window_key = int(timestamp.timestamp() // 300)  # 5-minute windows
            time_windows[window_key].append(event)
        
        # Look for correlated events within each window
        for window_events in time_windows.values():
            if len(window_events) > 1:
                correlations.append({
                    "type": "temporal_correlation",
                    "events": window_events,
                    "confidence": min(len(window_events) / 10.0, 1.0)
                })
        
        return correlations
    
    async def _correlate_by_entity(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Correlate events by entities (users, hosts, IPs)"""
        correlations = []
        
        # Group events by entity
        entity_events = defaultdict(list)
        for event in events:
            entities = [
                event.get("user_id"),
                event.get("source_ip"),
                event.get("host_id")
            ]
            
            for entity in entities:
                if entity:
                    entity_events[entity].append(event)
        
        # Look for suspicious entity activity
        for entity, entity_event_list in entity_events.items():
            if len(entity_event_list) > 3:  # Multiple events from same entity
                correlations.append({
                    "type": "entity_correlation",
                    "entity": entity,
                    "events": entity_event_list,
                    "confidence": min(len(entity_event_list) / 5.0, 1.0)
                })
        
        return correlations
    
    async def _correlate_by_pattern(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Correlate events by attack patterns"""
        correlations = []
        
        # Look for known attack patterns (simplified)
        attack_sequences = [
            ["reconnaissance", "initial_access", "persistence"],
            ["credential_access", "lateral_movement", "data_exfiltration"],
            ["defense_evasion", "privilege_escalation", "impact"]
        ]
        
        for sequence in attack_sequences:
            matching_events = []
            for stage in sequence:
                for event in events:
                    if stage.lower() in event.get("type", "").lower():
                        matching_events.append(event)
                        break
            
            if len(matching_events) >= 2:
                correlations.append({
                    "type": "attack_pattern",
                    "pattern": sequence,
                    "events": matching_events,
                    "confidence": len(matching_events) / len(sequence)
                })
        
        return correlations