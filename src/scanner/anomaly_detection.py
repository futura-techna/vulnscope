"""
VulnScope - Anomaly Detection Module
Behavioral analysis, risk scoring, and pattern detection for Zero Trust
"""

import re
import math
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import statistics


class AnomalyType(str, Enum):
    """Types of anomalies detected"""
    UNUSUAL_VOLUME = "UNUSUAL_VOLUME"
    UNUSUAL_TIMING = "UNUSUAL_TIMING"
    UNUSUAL_LOCATION = "UNUSUAL_LOCATION"
    UNUSUAL_PATTERN = "UNUSUAL_PATTERN"
    BEHAVIORAL_DEVIATION = "BEHAVIORAL_DEVIATION"
    CREDENTIAL_MISUSE = "CREDENTIAL_MISUSE"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    LATERAL_MOVEMENT = "LATERAL_MOVEMENT"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"


class RiskLevel(str, Enum):
    """Risk levels for anomalies"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class RequestProfile:
    """Profile of a request"""
    timestamp: datetime = field(default_factory=datetime.utcnow)
    user_id: Optional[str] = None
    ip_address: str = ""
    user_agent: str = ""
    method: str = "GET"
    path: str = ""
    resource_type: str = ""
    data_size: int = 0
    response_code: int = 0
    response_time: float = 0.0
    is_authenticated: bool = False
    privileges: List[str] = field(default_factory=list)
    accessed_resources: List[str] = field(default_factory=list)


@dataclass
class AnomalyDetectionResult:
    """Result of anomaly detection"""
    anomaly_type: AnomalyType
    risk_level: RiskLevel
    score: float  # 0-100
    description: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    indicators: List[str] = field(default_factory=list)


class BehavioralAnalyzer:
    """Analyze user/system behavior for anomalies"""
    
    def __init__(self):
        self.baseline_profiles: Dict[str, List[RequestProfile]] = {}
        self.anomalies: List[AnomalyDetectionResult] = []
        self.statistical_baseline: Dict[str, Any] = {}
    
    def analyze_request(self, profile: RequestProfile) -> List[AnomalyDetectionResult]:
        """Analyze a request for anomalies"""
        anomalies = []
        
        # Get user baseline
        user_key = profile.user_id or profile.ip_address
        if user_key not in self.baseline_profiles:
            self.baseline_profiles[user_key] = []
        
        user_profiles = self.baseline_profiles[user_key]
        
        # Volume anomaly detection
        if len(user_profiles) > 10:
            volume_anomaly = self._detect_volume_anomaly(profile, user_profiles)
            if volume_anomaly:
                anomalies.append(volume_anomaly)
        
        # Timing anomaly detection
        timing_anomaly = self._detect_timing_anomaly(profile, user_profiles)
        if timing_anomaly:
            anomalies.append(timing_anomaly)
        
        # Location anomaly detection
        location_anomaly = self._detect_location_anomaly(profile, user_profiles)
        if location_anomaly:
            anomalies.append(location_anomaly)
        
        # Behavioral deviation detection
        behavior_anomaly = self._detect_behavioral_deviation(profile, user_profiles)
        if behavior_anomaly:
            anomalies.append(behavior_anomaly)
        
        # Privilege escalation detection
        priv_anomaly = self._detect_privilege_escalation(profile, user_profiles)
        if priv_anomaly:
            anomalies.append(priv_anomaly)
        
        # Data exfiltration detection
        exfil_anomaly = self._detect_data_exfiltration(profile, user_profiles)
        if exfil_anomaly:
            anomalies.append(exfil_anomaly)
        
        # Add current profile to baseline
        user_profiles.append(profile)
        
        return anomalies
    
    def _detect_volume_anomaly(self, profile: RequestProfile, 
                              baseline: List[RequestProfile]) -> Optional[AnomalyDetectionResult]:
        """Detect unusual request volume"""
        
        recent_profiles = [p for p in baseline if 
                          (datetime.utcnow() - p.timestamp).total_seconds() < 3600]
        
        if len(recent_profiles) < 5:
            return None
        
        # Calculate average requests per minute
        avg_requests = len(recent_profiles) / 60
        
        # Check if current burst of requests is unusual
        current_hour_requests = len([p for p in recent_profiles if 
                                    (datetime.utcnow() - p.timestamp).total_seconds() < 60])
        
        if current_hour_requests > avg_requests * 3:
            return AnomalyDetectionResult(
                anomaly_type=AnomalyType.UNUSUAL_VOLUME,
                risk_level=RiskLevel.MEDIUM,
                score=min(100, (current_hour_requests / avg_requests) * 30),
                description=f"Unusual request volume detected: {current_hour_requests} requests/min (baseline: {avg_requests:.1f})",
                indicators=['High request frequency', 'Possible DoS or brute-force attack'],
            )
        
        return None
    
    def _detect_timing_anomaly(self, profile: RequestProfile,
                              baseline: List[RequestProfile]) -> Optional[AnomalyDetectionResult]:
        """Detect unusual request timing"""
        
        if len(baseline) < 5:
            return None
        
        # Get historical timestamps
        timestamps = [p.timestamp for p in baseline[-10:]]
        
        # Check if request is outside normal hours
        current_hour = datetime.utcnow().hour
        baseline_hours = [t.hour for t in timestamps]
        
        if baseline_hours:
            avg_hour = statistics.mean(baseline_hours)
            std_dev = statistics.stdev(baseline_hours) if len(baseline_hours) > 1 else 0
            
            # Unusual if 3+ standard deviations away
            if std_dev > 0 and abs(current_hour - avg_hour) > 3 * std_dev:
                return AnomalyDetectionResult(
                    anomaly_type=AnomalyType.UNUSUAL_TIMING,
                    risk_level=RiskLevel.LOW,
                    score=min(100, abs(current_hour - avg_hour) * 5),
                    description=f"Request at unusual time: {current_hour}:00 (baseline avg: {avg_hour:.1f})",
                    indicators=['Off-hours access', 'Atypical usage pattern'],
                )
        
        return None
    
    def _detect_location_anomaly(self, profile: RequestProfile,
                                baseline: List[RequestProfile]) -> Optional[AnomalyDetectionResult]:
        """Detect unusual access locations"""
        
        if len(baseline) < 3:
            return None
        
        # Get historical IPs
        baseline_ips = [p.ip_address for p in baseline[-10:]]
        
        if profile.ip_address not in baseline_ips[-5:]:
            return AnomalyDetectionResult(
                anomaly_type=AnomalyType.UNUSUAL_LOCATION,
                risk_level=RiskLevel.HIGH,
                score=75,
                description=f"Access from new IP address: {profile.ip_address}",
                indicators=['New location', 'Possible account compromise', 'VPN/Proxy usage change'],
            )
        
        return None
    
    def _detect_behavioral_deviation(self, profile: RequestProfile,
                                    baseline: List[RequestProfile]) -> Optional[AnomalyDetectionResult]:
        """Detect behavioral deviations"""
        
        if len(baseline) < 5:
            return None
        
        # Get typical resource types accessed
        baseline_resources = [p.resource_type for p in baseline[-20:]]
        
        if baseline_resources and profile.resource_type not in baseline_resources:
            return AnomalyDetectionResult(
                anomaly_type=AnomalyType.BEHAVIORAL_DEVIATION,
                risk_level=RiskLevel.MEDIUM,
                score=50,
                description=f"Access to new resource type: {profile.resource_type}",
                indicators=['Unusual resource access', 'Deviation from baseline behavior'],
            )
        
        return None
    
    def _detect_privilege_escalation(self, profile: RequestProfile,
                                    baseline: List[RequestProfile]) -> Optional[AnomalyDetectionResult]:
        """Detect privilege escalation attempts"""
        
        if len(baseline) < 3:
            return None
        
        # Get typical privilege levels
        baseline_privileges = [p.privileges for p in baseline[-10:]]
        current_privileges = set(profile.privileges)
        
        if baseline_privileges:
            baseline_privilege_set = set()
            for priv_list in baseline_privileges:
                baseline_privilege_set.update(priv_list)
            
            new_privileges = current_privileges - baseline_privilege_set
            if new_privileges:
                return AnomalyDetectionResult(
                    anomaly_type=AnomalyType.PRIVILEGE_ESCALATION,
                    risk_level=RiskLevel.CRITICAL,
                    score=90,
                    description=f"New privileges detected: {', '.join(new_privileges)}",
                    indicators=['Privilege escalation', 'Unauthorized permission grant'],
                )
        
        return None
    
    def _detect_data_exfiltration(self, profile: RequestProfile,
                                 baseline: List[RequestProfile]) -> Optional[AnomalyDetectionResult]:
        """Detect potential data exfiltration"""
        
        if len(baseline) < 5:
            return None
        
        # Calculate average data transfer
        baseline_sizes = [p.data_size for p in baseline[-20:]]
        avg_size = statistics.mean(baseline_sizes) if baseline_sizes else 0
        std_dev = statistics.stdev(baseline_sizes) if len(baseline_sizes) > 1 else 0
        
        # Detect unusually large data transfers
        if std_dev > 0 and profile.data_size > avg_size + (3 * std_dev):
            return AnomalyDetectionResult(
                anomaly_type=AnomalyType.DATA_EXFILTRATION,
                risk_level=RiskLevel.HIGH,
                score=80,
                description=f"Unusual data transfer size: {profile.data_size} bytes (baseline avg: {avg_size:.0f})",
                indicators=['Large data transfer', 'Possible exfiltration', 'Unusual download pattern'],
            )
        
        return None


class RiskScorer:
    """Calculate risk scores for requests and users"""
    
    def __init__(self):
        self.weights = {
            'authentication': 0.20,
            'authorization': 0.20,
            'encryption': 0.15,
            'logging': 0.10,
            'anomaly': 0.25,
            'compliance': 0.10,
        }
    
    def calculate_request_risk(self, profile: RequestProfile,
                              anomalies: List[AnomalyDetectionResult]) -> float:
        """Calculate risk score for a request (0-100)"""
        
        score = 0.0
        
        # Authentication risk
        auth_risk = 0 if profile.is_authenticated else 50
        score += auth_risk * self.weights['authentication']
        
        # Authorization risk (privileges)
        if 'admin' in profile.privileges:
            score += 30 * self.weights['authorization']
        elif 'root' in profile.privileges:
            score += 50 * self.weights['authorization']
        
        # Encryption risk (HTTPS)
        if not profile.user_agent.startswith('https'):
            score += 40 * self.weights['encryption']
        
        # Anomaly risk
        if anomalies:
            anomaly_scores = [a.score for a in anomalies]
            avg_anomaly = sum(anomaly_scores) / len(anomaly_scores)
            score += avg_anomaly * self.weights['anomaly']
        
        return min(100, score)
    
    def calculate_user_risk(self, user_id: str,
                           profiles: List[RequestProfile],
                           analyzer: BehavioralAnalyzer) -> float:
        """Calculate overall risk score for a user (0-100)"""
        
        if not profiles:
            return 0.0
        
        total_risk = 0.0
        
        for profile in profiles[-10:]:
            anomalies = analyzer.analyze_request(profile)
            request_risk = self.calculate_request_risk(profile, anomalies)
            total_risk += request_risk
        
        return total_risk / min(10, len(profiles))


class ContinuousThreatAssessment:
    """Continuous threat assessment for Zero Trust"""
    
    def __init__(self):
        self.analyzer = BehavioralAnalyzer()
        self.risk_scorer = RiskScorer()
        self.threat_events: List[Dict[str, Any]] = []
    
    def assess_request(self, profile: RequestProfile) -> Dict[str, Any]:
        """Assess a request for threats"""
        
        # Detect anomalies
        anomalies = self.analyzer.analyze_request(profile)
        
        # Calculate risk
        request_risk = self.risk_scorer.calculate_request_risk(profile, anomalies)
        
        # Determine threat level
        if request_risk >= 80:
            threat_level = RiskLevel.CRITICAL
        elif request_risk >= 60:
            threat_level = RiskLevel.HIGH
        elif request_risk >= 40:
            threat_level = RiskLevel.MEDIUM
        else:
            threat_level = RiskLevel.LOW
        
        assessment = {
            'timestamp': datetime.utcnow().isoformat(),
            'user_id': profile.user_id,
            'risk_score': request_risk,
            'threat_level': threat_level.value,
            'anomalies': [
                {
                    'type': a.anomaly_type.value,
                    'score': a.score,
                    'description': a.description,
                } for a in anomalies
            ],
            'recommendation': self._get_recommendation(request_risk, anomalies),
        }
        
        # Store if threat
        if request_risk >= 60:
            self.threat_events.append(assessment)
        
        return assessment
    
    def _get_recommendation(self, risk_score: float,
                           anomalies: List[AnomalyDetectionResult]) -> str:
        """Get recommendation based on risk"""
        
        if risk_score >= 80:
            return "BLOCK: Critical threat detected. Immediate isolation recommended."
        elif risk_score >= 60:
            return "CHALLENGE: MFA required. Monitor user activity closely."
        elif risk_score >= 40:
            return "MONITOR: Enhanced logging recommended."
        else:
            return "ALLOW: Request appears legitimate."
