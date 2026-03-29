"""
VulnScope - Advanced Zero Trust Architecture Detectors
Comprehensive Zero Trust implementation verification and context-aware security
"""

import re
import json
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional, Set
from enum import Enum
from datetime import datetime, timedelta

from ..core.models import Endpoint, Finding, Severity, VulnerabilityType, Status


class TrustLevel(str, Enum):
    """Zero Trust Trust Levels"""
    NEVER = "NEVER"
    CONDITIONAL = "CONDITIONAL"
    ALWAYS = "ALWAYS"


class ContextFactor(str, Enum):
    """Context Factors for Zero Trust Assessment"""
    USER_IDENTITY = "USER_IDENTITY"
    DEVICE_POSTURE = "DEVICE_POSTURE"
    LOCATION = "LOCATION"
    TIME_OF_DAY = "TIME_OF_DAY"
    RISK_SCORE = "RISK_SCORE"
    NETWORK_SEGMENT = "NETWORK_SEGMENT"
    APPLICATION_CONTEXT = "APPLICATION_CONTEXT"
    DATA_CLASSIFICATION = "DATA_CLASSIFICATION"


class Detector(ABC):
    """Base class for vulnerability detectors"""
    
    @property
    @abstractmethod
    def vulnerability_type(self) -> VulnerabilityType:
        pass
    
    @property
    @abstractmethod
    def severity(self) -> Severity:
        pass
    
    @abstractmethod
    def detect(self, endpoint: Endpoint, session) -> List[Finding]:
        pass


class ContextAwareAccessDetector(Detector):
    """Detect missing context-aware access controls (Zero Trust Pillar 1)"""
    
    @property
    def vulnerability_type(self) -> VulnerabilityType:
        return VulnerabilityType.MISSING_ZERO_TRUST
    
    @property
    def severity(self) -> Severity:
        return Severity.HIGH
    
    # Required context factors for sensitive endpoints
    SENSITIVE_ENDPOINTS_CONTEXT_REQUIREMENTS = {
        r'/admin': [
            ContextFactor.USER_IDENTITY,
            ContextFactor.DEVICE_POSTURE,
            ContextFactor.RISK_SCORE,
        ],
        r'/api/users': [
            ContextFactor.USER_IDENTITY,
            ContextFactor.DEVICE_POSTURE,
        ],
        r'/api/payments': [
            ContextFactor.USER_IDENTITY,
            ContextFactor.DEVICE_POSTURE,
            ContextFactor.LOCATION,
            ContextFactor.RISK_SCORE,
        ],
        r'/api/data': [
            ContextFactor.USER_IDENTITY,
            ContextFactor.DATA_CLASSIFICATION,
        ],
        r'/.*/delete': [
            ContextFactor.USER_IDENTITY,
            ContextFactor.DEVICE_POSTURE,
            ContextFactor.RISK_SCORE,
        ],
    }
    
    def detect(self, endpoint: Endpoint, session) -> List[Finding]:
        """Detect missing context-aware access controls"""
        findings = []
        
        url = endpoint.url.lower()
        path = endpoint.path.lower()
        
        for pattern, required_factors in self.SENSITIVE_ENDPOINTS_CONTEXT_REQUIREMENTS.items():
            if re.search(pattern, path):
                # Check if endpoint implements context requirements
                if not self._has_context_controls(endpoint, session):
                    factors_str = ', '.join([f.value for f in required_factors])
                    finding = self._create_finding(
                        endpoint=endpoint,
                        title="Missing Context-Aware Access Control",
                        description=f"Endpoint '{path}' requires context-aware access controls but none detected. "
                                   f"Zero Trust requires verification of: {factors_str}",
                        evidence={
                            'url': endpoint.url,
                            'path': path,
                            'required_context_factors': [f.value for f in required_factors],
                            'detected_factors': self._extract_context_factors(endpoint, session),
                        }
                    )
                    findings.append(finding)
                    break
        
        return findings
    
    def _has_context_controls(self, endpoint: Endpoint, session) -> bool:
        """Check if endpoint implements context controls"""
        try:
            response = session.get(endpoint.url, timeout=10)
            headers = response.headers
            
            # Check for context validation headers
            context_headers = [
                'X-Device-Trust',
                'X-Risk-Score',
                'X-User-Context',
                'X-Location-Verified',
                'X-Device-Compliance',
            ]
            
            return any(h in headers for h in context_headers)
        except Exception:
            return False
    
    def _extract_context_factors(self, endpoint: Endpoint, session) -> List[str]:
        """Extract detected context factors from endpoint"""
        factors = []
        try:
            response = session.get(endpoint.url, timeout=10)
            headers = response.headers.keys()
            
            # Map headers to context factors
            header_factor_map = {
                'authorization': ContextFactor.USER_IDENTITY.value,
                'x-device-trust': ContextFactor.DEVICE_POSTURE.value,
                'x-location': ContextFactor.LOCATION.value,
                'x-risk-score': ContextFactor.RISK_SCORE.value,
                'x-device-compliance': ContextFactor.DEVICE_POSTURE.value,
            }
            
            for header, factor in header_factor_map.items():
                if header.lower() in [h.lower() for h in headers]:
                    factors.append(factor)
        except Exception:
            pass
        
        return factors
    
    def _create_finding(self, endpoint: Endpoint, title: str,
                       description: str, evidence: Dict[str, Any]) -> Finding:
        """Create a standardized finding"""
        return Finding(
            scan_id="",
            target_id=endpoint.target_id,
            endpoint_id=str(endpoint.id),
            vulnerability_type=self.vulnerability_type,
            severity=self.severity,
            title=title,
            description=description,
            evidence=evidence,
            status=Status.PENDING,
        )


class DevicePostureDetector(Detector):
    """Detect missing device compliance verification (Zero Trust Pillar 2)"""
    
    @property
    def vulnerability_type(self) -> VulnerabilityType:
        return VulnerabilityType.MISSING_ZERO_TRUST
    
    @property
    def severity(self) -> Severity:
        return Severity.HIGH
    
    # Device posture requirements
    REQUIRED_POSTURE_CHECKS = [
        'antivirus_enabled',
        'firewall_enabled',
        'disk_encryption',
        'os_patched',
        'mfa_enabled',
        'password_manager_used',
    ]
    
    def detect(self, endpoint: Endpoint, session) -> List[Finding]:
        """Detect missing device posture verification"""
        findings = []
        
        # Check for device posture validation
        if not self._has_device_posture_validation(endpoint, session):
            finding = self._create_finding(
                endpoint=endpoint,
                title="Missing Device Posture Verification",
                description="Endpoint does not verify device compliance. Zero Trust requires validating: "
                          f"{', '.join(self.REQUIRED_POSTURE_CHECKS)}",
                evidence={
                    'url': endpoint.url,
                    'required_checks': self.REQUIRED_POSTURE_CHECKS,
                    'detected_headers': self._get_posture_headers(endpoint, session),
                }
            )
            findings.append(finding)
        
        return findings
    
    def _has_device_posture_validation(self, endpoint: Endpoint, session) -> bool:
        """Check if endpoint validates device posture"""
        try:
            response = session.get(endpoint.url, timeout=10)
            headers = response.headers
            
            posture_headers = [
                'X-Device-Compliance',
                'X-Device-Trust',
                'X-Device-Health',
                'X-Endpoint-Security',
            ]
            
            return any(h in headers for h in posture_headers)
        except Exception:
            return False
    
    def _get_posture_headers(self, endpoint: Endpoint, session) -> List[str]:
        """Get device posture headers from endpoint"""
        headers = []
        try:
            response = session.get(endpoint.url, timeout=10)
            posture_headers = [
                'X-Device-Compliance',
                'X-Device-Trust',
                'X-Device-Health',
                'X-Endpoint-Security',
                'X-Antivirus-Status',
                'X-Firewall-Status',
            ]
            headers = [h for h in posture_headers if h in response.headers]
        except Exception:
            pass
        
        return headers
    
    def _create_finding(self, endpoint: Endpoint, title: str,
                       description: str, evidence: Dict[str, Any]) -> Finding:
        """Create a standardized finding"""
        return Finding(
            scan_id="",
            target_id=endpoint.target_id,
            endpoint_id=str(endpoint.id),
            vulnerability_type=self.vulnerability_type,
            severity=self.severity,
            title=title,
            description=description,
            evidence=evidence,
            status=Status.PENDING,
        )


class MicroSegmentationDetector(Detector):
    """Detect missing network micro-segmentation (Zero Trust Pillar 3)"""
    
    @property
    def vulnerability_type(self) -> VulnerabilityType:
        return VulnerabilityType.MISSING_ZERO_TRUST
    
    @property
    def severity(self) -> Severity:
        return Severity.HIGH
    
    def detect(self, endpoint: Endpoint, session) -> List[Finding]:
        """Detect missing micro-segmentation"""
        findings = []
        
        # Check for network segmentation indicators
        findings.extend(self._check_network_boundaries(endpoint, session))
        findings.extend(self._check_east_west_traffic_controls(endpoint, session))
        
        return findings
    
    def _check_network_boundaries(self, endpoint: Endpoint, session) -> List[Finding]:
        """Check for network boundary enforcement"""
        findings = []
        
        try:
            response = session.get(endpoint.url, timeout=10)
            
            # Check for network boundary indicators
            boundary_headers = [
                'X-Network-Zone',
                'X-VLAN-ID',
                'X-Security-Zone',
                'X-Network-Segment',
            ]
            
            has_boundary_info = any(h in response.headers for h in boundary_headers)
            
            if not has_boundary_info:
                finding = self._create_finding(
                    endpoint=endpoint,
                    title="Missing Network Boundary Information",
                    description="Endpoint does not expose network boundary information. "
                              "Zero Trust requires explicit network segmentation.",
                    evidence={
                        'url': endpoint.url,
                        'missing_headers': boundary_headers,
                    }
                )
                findings.append(finding)
        except Exception:
            pass
        
        return findings
    
    def _check_east_west_traffic_controls(self, endpoint: Endpoint, session) -> List[Finding]:
        """Check for east-west traffic controls"""
        findings = []
        
        try:
            response = session.get(endpoint.url, timeout=10)
            
            # Check for service-to-service communication controls
            service_controls = [
                'X-Require-mTLS',
                'X-Service-Identity',
                'X-Service-Mesh',
                'X-Network-Policy',
            ]
            
            has_service_controls = any(h in response.headers for h in service_controls)
            
            if not has_service_controls:
                finding = self._create_finding(
                    endpoint=endpoint,
                    title="Missing East-West Traffic Controls",
                    description="Service-to-service communication does not enforce mutual TLS or policies. "
                              "Zero Trust requires mutual authentication between services.",
                    evidence={
                        'url': endpoint.url,
                        'missing_controls': service_controls,
                    }
                )
                findings.append(finding)
        except Exception:
            pass
        
        return findings
    
    def _create_finding(self, endpoint: Endpoint, title: str,
                       description: str, evidence: Dict[str, Any]) -> Finding:
        """Create a standardized finding"""
        return Finding(
            scan_id="",
            target_id=endpoint.target_id,
            endpoint_id=str(endpoint.id),
            vulnerability_type=self.vulnerability_type,
            severity=self.severity,
            title=title,
            description=description,
            evidence=evidence,
            status=Status.PENDING,
        )


class AnomalyDetectionDetector(Detector):
    """Detect missing behavioral/anomaly detection (Zero Trust Pillar 4)"""
    
    @property
    def vulnerability_type(self) -> VulnerabilityType:
        return VulnerabilityType.MISSING_ZERO_TRUST
    
    @property
    def severity(self) -> Severity:
        return Severity.MEDIUM
    
    ANOMALY_DETECTION_HEADERS = [
        'X-Behavioral-Analysis',
        'X-Anomaly-Detection',
        'X-User-Behavior-Profile',
        'X-Risk-Adaptive-Auth',
    ]
    
    def detect(self, endpoint: Endpoint, session) -> List[Finding]:
        """Detect missing anomaly detection"""
        findings = []
        
        if not self._has_anomaly_detection(endpoint, session):
            finding = self._create_finding(
                endpoint=endpoint,
                title="Missing Behavioral Anomaly Detection",
                description="Endpoint does not implement behavioral analysis or anomaly detection. "
                          "Zero Trust requires continuous monitoring of suspicious activity patterns.",
                evidence={
                    'url': endpoint.url,
                    'required_capability': 'Anomaly Detection / User Behavior Analytics (UBA)',
                }
            )
            findings.append(finding)
        
        return findings
    
    def _has_anomaly_detection(self, endpoint: Endpoint, session) -> bool:
        """Check if endpoint has anomaly detection"""
        try:
            response = session.get(endpoint.url, timeout=10)
            headers = response.headers
            
            return any(h in headers for h in self.ANOMALY_DETECTION_HEADERS)
        except Exception:
            return False
    
    def _create_finding(self, endpoint: Endpoint, title: str,
                       description: str, evidence: Dict[str, Any]) -> Finding:
        """Create a standardized finding"""
        return Finding(
            scan_id="",
            target_id=endpoint.target_id,
            endpoint_id=str(endpoint.id),
            vulnerability_type=self.vulnerability_type,
            severity=self.severity,
            title=title,
            description=description,
            evidence=evidence,
            status=Status.PENDING,
        )


class EncryptionVerificationDetector(Detector):
    """Detect missing encryption in transit and at rest (Zero Trust Pillar 5)"""
    
    @property
    def vulnerability_type(self) -> VulnerabilityType:
        return VulnerabilityType.WEAK_CRYPTOGRAPHY
    
    @property
    def severity(self) -> Severity:
        return Severity.HIGH
    
    def detect(self, endpoint: Endpoint, session) -> List[Finding]:
        """Detect missing encryption verification"""
        findings = []
        
        # Check encryption in transit
        transit_findings = self._check_encryption_in_transit(endpoint, session)
        findings.extend(transit_findings)
        
        # Check encryption at rest indicators
        rest_findings = self._check_encryption_at_rest_indicators(endpoint, session)
        findings.extend(rest_findings)
        
        return findings
    
    def _check_encryption_in_transit(self, endpoint: Endpoint, session) -> List[Finding]:
        """Check encryption in transit"""
        findings = []
        
        try:
            response = session.get(endpoint.url, timeout=10)
            
            # Check for encryption in transit indicators
            if not response.url.startswith('https://'):
                finding = self._create_finding(
                    endpoint=endpoint,
                    title="Unencrypted Communication Channel",
                    description="Data in transit is not encrypted. Use HTTPS/TLS for all communications.",
                    evidence={'url': response.url},
                )
                findings.append(finding)
            
            # Check TLS version
            if hasattr(response, 'raw'):
                ssl_version = getattr(response.raw, '_original_response', None)
                if ssl_version:
                    # TLS 1.2+ required for Zero Trust
                    pass
        
        except Exception:
            pass
        
        return findings
    
    def _check_encryption_at_rest_indicators(self, endpoint: Endpoint, session) -> List[Finding]:
        """Check encryption at rest indicators"""
        findings = []
        
        try:
            response = session.get(endpoint.url, timeout=10)
            
            # Check for encryption at rest headers
            encryption_headers = [
                'X-Data-Encrypted',
                'X-Encryption-Algorithm',
                'X-Key-Management-Service',
            ]
            
            has_encryption_headers = any(h in response.headers for h in encryption_headers)
            
            if not has_encryption_headers:
                finding = self._create_finding(
                    endpoint=endpoint,
                    title="Missing Data-at-Rest Encryption Verification",
                    description="No indication that data at rest is encrypted. "
                              "Zero Trust requires encryption of all sensitive data.",
                    evidence={
                        'url': endpoint.url,
                        'missing_headers': encryption_headers,
                    }
                )
                findings.append(finding)
        except Exception:
            pass
        
        return findings
    
    def _create_finding(self, endpoint: Endpoint, title: str,
                       description: str, evidence: Dict[str, Any]) -> Finding:
        """Create a standardized finding"""
        return Finding(
            scan_id="",
            target_id=endpoint.target_id,
            endpoint_id=str(endpoint.id),
            vulnerability_type=self.vulnerability_type,
            severity=self.severity,
            title=title,
            description=description,
            evidence=evidence,
            status=Status.PENDING,
        )


class VisibilitySensitivityDetector(Detector):
    """Detect missing visibility and analytics (Zero Trust Pillar 6)"""
    
    @property
    def vulnerability_type(self) -> VulnerabilityType:
        return VulnerabilityType.MISSING_ZERO_TRUST
    
    @property
    def severity(self) -> Severity:
        return Severity.MEDIUM
    
    VISIBILITY_HEADERS = [
        'X-Request-ID',
        'X-Correlation-ID',
        'X-Trace-ID',
        'X-Span-ID',
        'X-Cloud-Trace-Context',
    ]
    
    def detect(self, endpoint: Endpoint, session) -> List[Finding]:
        """Detect missing visibility and logging"""
        findings = []
        
        if not self._has_visibility_headers(endpoint, session):
            finding = self._create_finding(
                endpoint=endpoint,
                title="Missing Request Tracing and Visibility",
                description="Endpoint lacks request/transaction tracing headers. "
                          "Zero Trust requires complete visibility of all requests for threat detection.",
                evidence={
                    'url': endpoint.url,
                    'required_headers': self.VISIBILITY_HEADERS,
                }
            )
            findings.append(finding)
        
        return findings
    
    def _has_visibility_headers(self, endpoint: Endpoint, session) -> bool:
        """Check if endpoint has visibility headers"""
        try:
            response = session.get(endpoint.url, timeout=10)
            headers = response.headers
            
            return any(h in headers for h in self.VISIBILITY_HEADERS)
        except Exception:
            return False
    
    def _create_finding(self, endpoint: Endpoint, title: str,
                       description: str, evidence: Dict[str, Any]) -> Finding:
        """Create a standardized finding"""
        return Finding(
            scan_id="",
            target_id=endpoint.target_id,
            endpoint_id=str(endpoint.id),
            vulnerability_type=self.vulnerability_type,
            severity=self.severity,
            title=title,
            description=description,
            evidence=evidence,
            status=Status.PENDING,
        )
