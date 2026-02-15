"""
VulnScope - Compliance Checkers
PCI-DSS, NIS2, SOC2 compliance checking
"""

from typing import Dict, Any, List
from abc import ABC, abstractmethod
from dataclasses import dataclass

from ..core.models import Finding, Severity


@dataclass
class ComplianceRequirement:
    """Compliance requirement"""
    id: str
    name: str
    description: str
    severity: Severity
    mandatory: bool = True


class ComplianceChecker(ABC):
    """Base class for compliance checkers"""
    
    @property
    @abstractmethod
    def standard(self) -> str:
        """Return compliance standard name"""
        pass
    
    @property
    @abstractmethod
    def requirements(self) -> List[ComplianceRequirement]:
        """Return list of requirements"""
        pass
    
    @abstractmethod
    def check(self, findings: List[Finding]) -> Dict[str, Any]:
        """Check compliance status"""
        pass
    
    def _calculate_score(self, critical: int, high: int, 
                        medium: int, low: int) -> float:
        """Calculate compliance score"""
        total = critical + high + medium + low
        
        if total == 0:
            return 100.0
        
        # Weighted score
        score = 100.0 - (critical * 20.0) - (high * 10.0) - (medium * 5.0) - (low * 2.0)
        
        return max(0.0, min(100.0, score))


class PCICompliance(ComplianceChecker):
    """PCI-DSS compliance checker"""
    
    @property
    def standard(self) -> str:
        return "PCI-DSS"
    
    @property
    def requirements(self) -> List[ComplianceRequirement]:
        return [
            ComplianceRequirement(
                id="PCI-6.5.1",
                name="Injection Flaws",
                description="All injection flaws in SQL, OS and LDAP queries",
                severity=Severity.HIGH,
            ),
            ComplianceRequirement(
                id="PCI-6.5.7",
                name="Cross-Site Scripting (XSS)",
                description="Cross-site scripting (XSS)",
                severity=Severity.HIGH,
            ),
            ComplianceRequirement(
                id="PCI-6.5.8",
                name="Broken Authentication",
                description="Broken authentication and session management",
                severity=Severity.HIGH,
            ),
            ComplianceRequirement(
                id="PCI-6.5.9",
                name="Sensitive Data Exposure",
                description="Insecure cryptographic storage",
                severity=Severity.CRITICAL,
            ),
        ]
    
    def check(self, findings: List[Finding]) -> Dict[str, Any]:
        """Check PCI-DSS compliance"""
        violations = []
        
        for finding in findings:
            # Check for critical/high findings
            if finding.severity in [Severity.CRITICAL, Severity.HIGH]:
                violations.append({
                    'requirement_id': self._map_vulnerability_to_requirement(finding),
                    'finding': finding.title,
                    'severity': finding.severity.value,
                })
        
        # Count by severity
        critical = len([f for f in findings if f.severity == Severity.CRITICAL])
        high = len([f for f in findings if f.severity == Severity.HIGH])
        medium = len([f for f in findings if f.severity == Severity.MEDIUM])
        low = len([f for f in findings if f.severity == Severity.LOW])
        
        compliant = critical == 0 and high == 0
        
        return {
            'standard': self.standard,
            'compliant': compliant,
            'score': self._calculate_score(critical, high, medium, low),
            'violations': violations,
            'summary': {
                'critical': critical,
                'high': high,
                'medium': medium,
                'low': low,
            },
            'requirements': [
                {
                    'id': req.id,
                    'name': req.name,
                    'met': not any(v['requirement_id'] == req.id for v in violations),
                }
                for req in self.requirements
            ],
        }
    
    def _map_vulnerability_to_requirement(self, finding: Finding) -> str:
        """Map vulnerability type to PCI requirement"""
        from ..core.models import VulnerabilityType
        
        mapping = {
            VulnerabilityType.SQL_INJECTION: "PCI-6.5.1",
            VulnerabilityType.XSS: "PCI-6.5.7",
            VulnerabilityType.BROKEN_AUTH: "PCI-6.5.8",
            VulnerabilityType.AUTH_BYPASS: "PCI-6.5.8",
            VulnerabilityType.SENSITIVE_DATA_EXPOSURE: "PCI-6.5.9",
        }
        
        return mapping.get(finding.vulnerability_type, "")


class NIS2Compliance(ComplianceChecker):
    """NIS2 compliance checker"""
    
    @property
    def standard(self) -> str:
        return "NIS2"
    
    @property
    def requirements(self) -> List[ComplianceRequirement]:
        return [
            ComplianceRequirement(
                id="NIS2-21.a",
                name="Risk Management",
                description="Take appropriate technical and operational measures to manage risks",
                severity=Severity.HIGH,
            ),
            ComplianceRequirement(
                id="NIS2-21.b",
                name="Incident Handling",
                description="Take measures to prevent and handle incidents",
                severity=Severity.HIGH,
            ),
            ComplianceRequirement(
                id="NIS2-21.c",
                name="Business Continuity",
                description="Ensure business continuity and crisis management",
                severity=Severity.MEDIUM,
            ),
            ComplianceRequirement(
                id="NIS2-21.d",
                name="Supply Chain",
                description="Supply chain security",
                severity=Severity.HIGH,
            ),
        ]
    
    def check(self, findings: List[Finding]) -> Dict[str, Any]:
        """Check NIS2 compliance"""
        violations = []
        
        # NIS2 considers medium severity as well
        for finding in findings:
            if finding.severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM]:
                violations.append({
                    'requirement_id': self._map_vulnerability_to_requirement(finding),
                    'finding': finding.title,
                    'severity': finding.severity.value,
                })
        
        critical = len([f for f in findings if f.severity == Severity.CRITICAL])
        high = len([f for f in findings if f.severity == Severity.HIGH])
        medium = len([f for f in findings if f.severity == Severity.MEDIUM])
        low = len([f for f in findings if f.severity == Severity.LOW])
        
        compliant = critical == 0 and high == 0
        
        return {
            'standard': self.standard,
            'compliant': compliant,
            'score': self._calculate_score(critical, high, medium, low),
            'violations': violations,
            'summary': {
                'critical': critical,
                'high': high,
                'medium': medium,
                'low': low,
            },
            'requirements': [
                {
                    'id': req.id,
                    'name': req.name,
                    'met': not any(v['requirement_id'] == req.id for v in violations),
                }
                for req in self.requirements
            ],
        }
    
    def _map_vulnerability_to_requirement(self, finding: Finding) -> str:
        """Map vulnerability type to NIS2 requirement"""
        from ..core.models import VulnerabilityType
        
        # NIS2 is more broad - any vulnerability could be a risk
        return "NIS2-21.a"


class SOC2Compliance(ComplianceChecker):
    """SOC 2 compliance checker"""
    
    @property
    def standard(self) -> str:
        return "SOC2"
    
    @property
    def requirements(self) -> List[ComplianceRequirement]:
        return [
            ComplianceRequirement(
                id="CC6.1",
                name="Logical Access",
                description="Logical and physical access controls",
                severity=Severity.HIGH,
            ),
            ComplianceRequirement(
                id="CC6.6",
                name="Change Management",
                description="Change management processes",
                severity=Severity.MEDIUM,
            ),
            ComplianceRequirement(
                id="CC7.2",
                name="Vulnerability Management",
                description="System vulnerabilities are identified and addressed",
                severity=Severity.HIGH,
            ),
        ]
    
    def check(self, findings: List[Finding]) -> Dict[str, Any]:
        """Check SOC2 compliance"""
        violations = []
        
        for finding in findings:
            if finding.severity in [Severity.CRITICAL, Severity.HIGH]:
                violations.append({
                    'requirement_id': self._map_vulnerability_to_requirement(finding),
                    'finding': finding.title,
                    'severity': finding.severity.value,
                })
        
        critical = len([f for f in findings if f.severity == Severity.CRITICAL])
        high = len([f for f in findings if f.severity == Severity.HIGH])
        medium = len([f for f in findings if f.severity == Severity.MEDIUM])
        low = len([f for f in findings if f.severity == Severity.LOW])
        
        compliant = critical == 0 and high == 0
        
        return {
            'standard': self.standard,
            'compliant': compliant,
            'score': self._calculate_score(critical, high, medium, low),
            'violations': violations,
            'summary': {
                'critical': critical,
                'high': high,
                'medium': medium,
                'low': low,
            },
            'requirements': [
                {
                    'id': req.id,
                    'name': req.name,
                    'met': not any(v['requirement_id'] == req.id for v in violations),
                }
                for req in self.requirements
            ],
        }
    
    def _map_vulnerability_to_requirement(self, finding: Finding) -> str:
        """Map vulnerability type to SOC2 requirement"""
        from ..core.models import VulnerabilityType
        
        mapping = {
            VulnerabilityType.BROKEN_AUTH: "CC6.1",
            VulnerabilityType.AUTH_BYPASS: "CC6.1",
            VulnerabilityType.SQL_INJECTION: "CC7.2",
            VulnerabilityType.XSS: "CC7.2",
            VulnerabilityType.SENSITIVE_DATA_EXPOSURE: "CC6.1",
        }
        
        return mapping.get(finding.vulnerability_type, "CC7.2")


class HIPAACompliance(ComplianceChecker):
    """HIPAA compliance checker"""
    
    @property
    def standard(self) -> str:
        return "HIPAA"
    
    @property
    def requirements(self) -> List[ComplianceRequirement]:
        return [
            ComplianceRequirement(
                id="HIPAA-164.312(a)",
                name="Access Control",
                description="Implement technical policies for electronic access",
                severity=Severity.HIGH,
            ),
            ComplianceRequirement(
                id="HIPAA-164.312(b)",
                name="Audit Controls",
                description="Implement hardware, software, procedures for audit trails",
                severity=Severity.HIGH,
            ),
            ComplianceRequirement(
                id="HIPAA-164.312(d)",
                name="Person or Entity Authentication",
                description="Implement procedures to verify identity",
                severity=Severity.HIGH,
            ),
            ComplianceRequirement(
                id="HIPAA-164.312(e)",
                name="Transmission Security",
                description="Implement technical security measures for ePHI",
                severity=Severity.HIGH,
            ),
        ]
    
    def check(self, findings: List[Finding]) -> Dict[str, Any]:
        """Check HIPAA compliance"""
        violations = []
        
        for finding in findings:
            if finding.severity in [Severity.CRITICAL, Severity.HIGH]:
                violations.append({
                    'requirement_id': self._map_vulnerability_to_requirement(finding),
                    'finding': finding.title,
                    'severity': finding.severity.value,
                })
        
        critical = len([f for f in findings if f.severity == Severity.CRITICAL])
        high = len([f for f in findings if f.severity == Severity.HIGH])
        medium = len([f for f in findings if f.severity == Severity.MEDIUM])
        low = len([f for f in findings if f.severity == Severity.LOW])
        
        compliant = critical == 0 and high == 0
        
        return {
            'standard': self.standard,
            'compliant': compliant,
            'score': self._calculate_score(critical, high, medium, low),
            'violations': violations,
            'summary': {'critical': critical, 'high': high, 'medium': medium, 'low': low},
            'requirements': [{'id': req.id, 'name': req.name, 'met': not any(v['requirement_id'] == req.id for v in violations)} for req in self.requirements],
        }
    
    def _map_vulnerability_to_requirement(self, finding: Finding) -> str:
        from ..core.models import VulnerabilityType
        mapping = {
            VulnerabilityType.BROKEN_AUTH: "HIPAA-164.312(a)",
            VulnerabilityType.AUTH_BYPASS: "HIPAA-164.312(a)",
            VulnerabilityType.SENSITIVE_DATA_EXPOSURE: "HIPAA-164.312(e)",
        }
        return mapping.get(finding.vulnerability_type, "HIPAA-164.312(a)")


class ISO27001Compliance(ComplianceChecker):
    """ISO 27001 compliance checker"""
    
    @property
    def standard(self) -> str:
        return "ISO27001"
    
    @property
    def requirements(self) -> List[ComplianceRequirement]:
        return [
            ComplianceRequirement(
                id="A.9.1",
                name="Business Requirements of Access Control",
                description="Limit access to information and information processing facilities",
                severity=Severity.HIGH,
            ),
            ComplianceRequirement(
                id="A.9.2",
                name="User Access Management",
                description="Ensure authorized user access and prevent unauthorized access",
                severity=Severity.HIGH,
            ),
            ComplianceRequirement(
                id="A.9.4",
                name="System and Application Access Control",
                description="Prevent unauthorized access to systems and applications",
                severity=Severity.HIGH,
            ),
            ComplianceRequirement(
                id="A.12.3",
                name="Information Backup",
                description="Maintain backup copies of information",
                severity=Severity.MEDIUM,
            ),
            ComplianceRequirement(
                id="A.14.2",
                name="Security in Development and Support Processes",
                description="Integrate security into development lifecycle",
                severity=Severity.HIGH,
            ),
        ]
    
    def check(self, findings: List[Finding]) -> Dict[str, Any]:
        """Check ISO 27001 compliance"""
        violations = []
        
        for finding in findings:
            if finding.severity in [Severity.CRITICAL, Severity.HIGH]:
                violations.append({
                    'requirement_id': self._map_vulnerability_to_requirement(finding),
                    'finding': finding.title,
                    'severity': finding.severity.value,
                })
        
        critical = len([f for f in findings if f.severity == Severity.CRITICAL])
        high = len([f for f in findings if f.severity == Severity.HIGH])
        medium = len([f for f in findings if f.severity == Severity.MEDIUM])
        low = len([f for f in findings if f.severity == Severity.LOW])
        
        compliant = critical == 0 and high == 0
        
        return {
            'standard': self.standard,
            'compliant': compliant,
            'score': self._calculate_score(critical, high, medium, low),
            'violations': violations,
            'summary': {'critical': critical, 'high': high, 'medium': medium, 'low': low},
            'requirements': [{'id': req.id, 'name': req.name, 'met': not any(v['requirement_id'] == req.id for v in violations)} for req in self.requirements],
        }
    
    def _map_vulnerability_to_requirement(self, finding: Finding) -> str:
        from ..core.models import VulnerabilityType
        mapping = {
            VulnerabilityType.BROKEN_AUTH: "A.9.1",
            VulnerabilityType.AUTH_BYPASS: "A.9.2",
            VulnerabilityType.SQL_INJECTION: "A.14.2",
            VulnerabilityType.XSS: "A.14.2",
        }
        return mapping.get(finding.vulnerability_type, "A.9.1")


class ComplianceReport:
    """Generate compliance reports"""
    
    def __init__(self):
        self.checkers = {
            "PCI-DSS": PCICompliance(),
            "NIS2": NIS2Compliance(),
            "SOC2": SOC2Compliance(),
            "HIPAA": HIPAACompliance(),
            "ISO27001": ISO27001Compliance(),
        }
    
    def check_all(self, findings: List[Finding], 
                  standards: List[str]) -> Dict[str, Any]:
        """Check compliance against multiple standards"""
        results = {}
        
        for standard in standards:
            checker = self.checkers.get(standard)
            if checker:
                results[standard] = checker.check(findings)
        
        return results
    
    def get_supported_standards(self) -> List[str]:
        """Get list of supported standards"""
        return list(self.checkers.keys())
