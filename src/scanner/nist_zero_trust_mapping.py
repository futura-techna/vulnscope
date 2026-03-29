"""
VulnScope - NIST Zero Trust Architecture Mapping & Compliance
Maps vulnerabilities to NIST SP 800-207 Six Pillars and provides Zero Trust assessment
"""

from enum import Enum
from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime

from ..core.models import VulnerabilityType, Severity


class NISTZeroTrustPillar(str, Enum):
    """NIST SP 800-207 Zero Trust Six Pillars"""
    IDENTITY = "Identity_Verification"
    DEVICES = "Device_Health_Verification"
    NETWORKS = "Network_Segmentation"
    APPS_AND_WORKLOADS = "Application_and_Workload_Security"
    DATA = "Data_Security"
    VISIBILITY_ANALYTICS = "Visibility_and_Analytics"


class ZeroTrustControl(str, Enum):
    """Zero Trust Control Categories"""
    PREVENT = "Prevent"
    DETECT = "Detect"
    RESPOND = "Respond"
    GOVERN = "Govern"


@dataclass
class NISTMapping:
    """NIST Zero Trust mapping for a vulnerability"""
    vulnerability_type: VulnerabilityType
    pillar: NISTZeroTrustPillar
    control: ZeroTrustControl
    cwe_ids: List[str] = field(default_factory=list)
    nist_control: str = ""  # e.g., AC-2, AC-3, etc.
    mitigation: str = ""
    priority: int = 0  # 1-5, higher = more important


class ZeroTrustMappingService:
    """Service to map vulnerabilities to NIST Zero Trust framework"""
    
    def __init__(self):
        self.mappings = self._initialize_mappings()
    
    def _initialize_mappings(self) -> Dict[VulnerabilityType, List[NISTMapping]]:
        """Initialize vulnerability to NIST Zero Trust mappings"""
        return {
            # Identity & Access Management (Pillar 1)
            VulnerabilityType.BROKEN_AUTH: [
                NISTMapping(
                    vulnerability_type=VulnerabilityType.BROKEN_AUTH,
                    pillar=NISTZeroTrustPillar.IDENTITY,
                    control=ZeroTrustControl.PREVENT,
                    cwe_ids=["CWE-287", "CWE-521"],
                    nist_control="AC-2, AC-3, IA-2, IA-4, IA-5",
                    mitigation="Implement MFA, OAuth 2.0, and OAuth2/OpenID Connect. Use strong password policies.",
                    priority=5,
                ),
            ],
            VulnerabilityType.AUTH_BYPASS: [
                NISTMapping(
                    vulnerability_type=VulnerabilityType.AUTH_BYPASS,
                    pillar=NISTZeroTrustPillar.IDENTITY,
                    control=ZeroTrustControl.PREVENT,
                    cwe_ids=["CWE-284", "CWE-862"],
                    nist_control="AC-2, AC-3, IA-7",
                    mitigation="Enforce proper authentication validation. Implement access control checks on all resources.",
                    priority=5,
                ),
            ],
            VulnerabilityType.OVERLY_PERMISSIVE_IAM: [
                NISTMapping(
                    vulnerability_type=VulnerabilityType.OVERLY_PERMISSIVE_IAM,
                    pillar=NISTZeroTrustPillar.IDENTITY,
                    control=ZeroTrustControl.GOVERN,
                    cwe_ids=["CWE-266", "CWE-269"],
                    nist_control="AC-2, AC-3, AC-6, IA-4",
                    mitigation="Apply principle of least privilege (PoLP). Regularly audit IAM permissions.",
                    priority=4,
                ),
            ],
            VulnerabilityType.IDOR: [
                NISTMapping(
                    vulnerability_type=VulnerabilityType.IDOR,
                    pillar=NISTZeroTrustPillar.IDENTITY,
                    control=ZeroTrustControl.PREVENT,
                    cwe_ids=["CWE-639", "CWE-276"],
                    nist_control="AC-3, AC-4, IA-4",
                    mitigation="Implement authorization checks for all object references. Use indirect references.",
                    priority=5,
                ),
            ],
            
            # Device Health (Pillar 2)
            VulnerabilityType.VULNERABLE_DEPENDENCY: [
                NISTMapping(
                    vulnerability_type=VulnerabilityType.VULNERABLE_DEPENDENCY,
                    pillar=NISTZeroTrustPillar.DEVICES,
                    control=ZeroTrustControl.DETECT,
                    cwe_ids=["CWE-1104", "CWE-1105"],
                    nist_control="SI-2, SI-4, SI-5",
                    mitigation="Implement SCA (Software Composition Analysis). Use SBOM. Keep dependencies updated.",
                    priority=4,
                ),
            ],
            VulnerabilityType.WEAK_SSL_TLS: [
                NISTMapping(
                    vulnerability_type=VulnerabilityType.WEAK_SSL_TLS,
                    pillar=NISTZeroTrustPillar.DEVICES,
                    control=ZeroTrustControl.PREVENT,
                    cwe_ids=["CWE-295", "CWE-327"],
                    nist_control="SC-7, SC-8, SC-13",
                    mitigation="Use TLS 1.2+. Disable weak ciphers. Enforce HTTPS.",
                    priority=5,
                ),
            ],
            
            # Network Segmentation (Pillar 3)
            VulnerabilityType.MISSING_ZERO_TRUST: [
                NISTMapping(
                    vulnerability_type=VulnerabilityType.MISSING_ZERO_TRUST,
                    pillar=NISTZeroTrustPillar.NETWORKS,
                    control=ZeroTrustControl.GOVERN,
                    cwe_ids=["CWE-284", "CWE-692"],
                    nist_control="AC-3, AC-4, SC-7",
                    mitigation="Implement Zero Trust architecture. Use micro-segmentation. Enforce mTLS.",
                    priority=5,
                ),
            ],
            VulnerabilityType.INSECURE_NETWORK_CONFIG: [
                NISTMapping(
                    vulnerability_type=VulnerabilityType.INSECURE_NETWORK_CONFIG,
                    pillar=NISTZeroTrustPillar.NETWORKS,
                    control=ZeroTrustControl.PREVENT,
                    cwe_ids=["CWE-318", "CWE-934"],
                    nist_control="AC-4, SC-7, SC-15",
                    mitigation="Implement network segmentation. Use firewalls. Enforce security groups/NACLs.",
                    priority=4,
                ),
            ],
            VulnerabilityType.OPEN_PORT: [
                NISTMapping(
                    vulnerability_type=VulnerabilityType.OPEN_PORT,
                    pillar=NISTZeroTrustPillar.NETWORKS,
                    control=ZeroTrustControl.PREVENT,
                    cwe_ids=["CWE-1333", "CWE-200"],
                    nist_control="AC-3, AC-4, SC-7",
                    mitigation="Close unnecessary ports. Implement network access controls. Use WAF.",
                    priority=4,
                ),
            ],
            
            # Application Security (Pillar 4)
            VulnerabilityType.XSS: [
                NISTMapping(
                    vulnerability_type=VulnerabilityType.XSS,
                    pillar=NISTZeroTrustPillar.APPS_AND_WORKLOADS,
                    control=ZeroTrustControl.PREVENT,
                    cwe_ids=["CWE-79", "CWE-80"],
                    nist_control="SI-10, AC-3, SC-5",
                    mitigation="Implement input validation, output encoding, CSP headers, WAF rules.",
                    priority=5,
                ),
            ],
            VulnerabilityType.SQL_INJECTION: [
                NISTMapping(
                    vulnerability_type=VulnerabilityType.SQL_INJECTION,
                    pillar=NISTZeroTrustPillar.APPS_AND_WORKLOADS,
                    control=ZeroTrustControl.PREVENT,
                    cwe_ids=["CWE-89", "CWE-90"],
                    nist_control="SI-10, AC-3, SC-5",
                    mitigation="Use parameterized queries, ORM, SAST scanning, WAF rules.",
                    priority=5,
                ),
            ],
            VulnerabilityType.SSRF: [
                NISTMapping(
                    vulnerability_type=VulnerabilityType.SSRF,
                    pillar=NISTZeroTrustPillar.APPS_AND_WORKLOADS,
                    control=ZeroTrustControl.PREVENT,
                    cwe_ids=["CWE-918", "CWE-611"],
                    nist_control="SI-10, AC-3, SC-7",
                    mitigation="Validate URLs, implement URL scheme whitelisting, block internal IPs.",
                    priority=4,
                ),
            ],
            
            # Data Security (Pillar 5)
            VulnerabilityType.SENSITIVE_DATA_EXPOSURE: [
                NISTMapping(
                    vulnerability_type=VulnerabilityType.SENSITIVE_DATA_EXPOSURE,
                    pillar=NISTZeroTrustPillar.DATA,
                    control=ZeroTrustControl.PREVENT,
                    cwe_ids=["CWE-200", "CWE-311"],
                    nist_control="SC-7, SC-13, SC-28",
                    mitigation="Encrypt data in transit and at rest. Mask sensitive data. Use DLP.",
                    priority=5,
                ),
            ],
            VulnerabilityType.INSECURE_STORAGE: [
                NISTMapping(
                    vulnerability_type=VulnerabilityType.INSECURE_STORAGE,
                    pillar=NISTZeroTrustPillar.DATA,
                    control=ZeroTrustControl.PREVENT,
                    cwe_ids=["CWE-377", "CWE-378"],
                    nist_control="AC-4, SC-28, SI-12",
                    mitigation="Encrypt storage. Implement access controls. Use secure storage APIs.",
                    priority=4,
                ),
            ],
            VulnerabilityType.WEAK_CRYPTOGRAPHY: [
                NISTMapping(
                    vulnerability_type=VulnerabilityType.WEAK_CRYPTOGRAPHY,
                    pillar=NISTZeroTrustPillar.DATA,
                    control=ZeroTrustControl.PREVENT,
                    cwe_ids=["CWE-327", "CWE-328"],
                    nist_control="SC-13, AC-2, SC-7",
                    mitigation="Use strong cryptography (AES-256, RSA-2048+). Implement key rotation.",
                    priority=5,
                ),
            ],
            VulnerabilityType.CLOUD_MISCONFIGURATION: [
                NISTMapping(
                    vulnerability_type=VulnerabilityType.CLOUD_MISCONFIGURATION,
                    pillar=NISTZeroTrustPillar.DATA,
                    control=ZeroTrustControl.GOVERN,
                    cwe_ids=["CWE-1393", "CWE-693"],
                    nist_control="AC-3, AC-4, SC-28",
                    mitigation="Implement IaC governance, CSPM, config auditing, enforce encryption.",
                    priority=4,
                ),
            ],
            
            # Visibility & Analytics (Pillar 6)
            VulnerabilityType.INFO_LEAK: [
                NISTMapping(
                    vulnerability_type=VulnerabilityType.INFO_LEAK,
                    pillar=NISTZeroTrustPillar.VISIBILITY_ANALYTICS,
                    control=ZeroTrustControl.DETECT,
                    cwe_ids=["CWE-200", "CWE-497"],
                    nist_control="AU-2, AU-6, SI-4",
                    mitigation="Implement monitoring, SIEM, DLP. Sanitize error messages.",
                    priority=3,
                ),
            ],
            VulnerabilityType.SUPPLY_CHAIN_COMPROMISE: [
                NISTMapping(
                    vulnerability_type=VulnerabilityType.SUPPLY_CHAIN_COMPROMISE,
                    pillar=NISTZeroTrustPillar.VISIBILITY_ANALYTICS,
                    control=ZeroTrustControl.DETECT,
                    cwe_ids=["CWE-1357", "CWE-1104"],
                    nist_control="SA-3, SA-4, SI-4",
                    mitigation="Implement supply chain security, SBOM, code signing, threat intelligence.",
                    priority=4,
                ),
            ],
        }
    
    def get_mappings_for_vulnerability(self, vuln_type: VulnerabilityType) -> List[NISTMapping]:
        """Get NIST mappings for a vulnerability"""
        return self.mappings.get(vuln_type, [])
    
    def get_mappings_for_pillar(self, pillar: NISTZeroTrustPillar) -> List[NISTMapping]:
        """Get all vulnerabilities mapped to a specific pillar"""
        mappings = []
        for vuln_mappings in self.mappings.values():
            for mapping in vuln_mappings:
                if mapping.pillar == pillar:
                    mappings.append(mapping)
        return mappings
    
    def get_pillar_assessment(self, pillar: NISTZeroTrustPillar, 
                             findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Assess a pillar based on findings"""
        pillar_mappings = self.get_mappings_for_pillar(pillar)
        
        # Count vulnerabilities by pillar
        pillar_findings = []
        for finding in findings:
            vuln_type = finding.get('vulnerability_type')
            mappings = self.get_mappings_for_vulnerability(vuln_type)
            for mapping in mappings:
                if mapping.pillar == pillar:
                    pillar_findings.append(finding)
        
        # Calculate compliance score
        total_possible = len(pillar_mappings) * 100
        deductions = sum(10 * f.get('severity', 1) for f in pillar_findings)
        compliance_score = max(0, 100 - (deductions / len(pillar_mappings) if pillar_mappings else 0))
        
        return {
            'pillar': pillar.value,
            'findings_count': len(pillar_findings),
            'compliance_score': round(compliance_score),
            'status': 'COMPLIANT' if compliance_score >= 80 else 'NON_COMPLIANT',
            'mappings': pillar_mappings,
        }
    
    def get_zero_trust_assessment(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate comprehensive Zero Trust assessment"""
        assessments = []
        total_score = 0
        
        for pillar in NISTZeroTrustPillar:
            assessment = self.get_pillar_assessment(pillar, findings)
            assessments.append(assessment)
            total_score += assessment['compliance_score']
        
        overall_score = round(total_score / len(NISTZeroTrustPillar))
        
        return {
            'assessment_date': datetime.utcnow().isoformat(),
            'overall_score': overall_score,
            'compliance_status': 'COMPLIANT' if overall_score >= 80 else 'NON_COMPLIANT',
            'pillar_assessments': assessments,
            'total_findings': len(findings),
            'critical_findings': sum(1 for f in findings if f.get('severity') == Severity.CRITICAL),
            'high_findings': sum(1 for f in findings if f.get('severity') == Severity.HIGH),
            'recommendations': self._generate_recommendations(assessments),
        }
    
    def _generate_recommendations(self, assessments: List[Dict[str, Any]]) -> List[str]:
        """Generate recommendations based on assessment"""
        recommendations = []
        
        for assessment in assessments:
            if assessment['compliance_score'] < 80:
                pillar_name = assessment['pillar'].replace('_', ' ')
                recommendations.append(
                    f"Improve {pillar_name} - Current compliance: {assessment['compliance_score']}%"
                )
        
        return recommendations


# Mapping service instance
zero_trust_service = ZeroTrustMappingService()
