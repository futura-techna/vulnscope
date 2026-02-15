"""
VulnScope - Policy Engine
Policy-as-Code implementation for security policies
"""

import yaml
from typing import List, Dict, Any, Optional
from enum import Enum
from dataclasses import dataclass, field
from datetime import datetime
from uuid import UUID, uuid4

from ..core.models import Finding, Severity, VulnerabilityType


class PolicyAction(str, Enum):
    """Actions to take when policy is violated"""
    FAIL = "fail"
    WARN = "warn"
    NOTIFY = "notify"
    BLOCK = "block"


class PolicyScope(str, Enum):
    """Scope of policy application"""
    SCAN = "scan"
    TARGET = "target"
    FINDING = "finding"
    ENDPOINT = "endpoint"


@dataclass
class PolicyRule:
    """Individual rule within a policy"""
    id: UUID = field(default_factory=uuid4)
    name: str = ""
    description: str = ""
    
    # Rule conditions
    vulnerability_types: List[VulnerabilityType] = field(default_factory=list)
    severities: List[Severity] = field(default_factory=list)
    cwe_ids: List[str] = field(default_factory=list)
    cve_ids: List[str] = field(default_factory=list)
    
    # Rule action
    action: PolicyAction = PolicyAction.FAIL
    message: str = ""


@dataclass
class Policy:
    """Security policy"""
    id: UUID = field(default_factory=uuid4)
    name: str = ""
    description: str = ""
    version: str = "1.0"
    enabled: bool = True
    
    # Policy scope
    scope: PolicyScope = PolicyScope.FINDING
    
    # Rules
    rules: List[PolicyRule] = field(default_factory=list)
    
    # Metadata
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    author: str = ""
    tags: List[str] = field(default_factory=list)
    
    # Compliance standards
    compliance_standards: List[str] = field(default_factory=list)


class PolicyEngine:
    """
    Policy-as-Code engine for security governance
    
    Features:
    - YAML-based policy definition
    - Multiple compliance standards (PCI-DSS, NIS2, SOC2)
    - Rule-based evaluation
    - Automatic enforcement
    - Policy versioning
    """
    
    def __init__(self):
        self.policies: Dict[str, Policy] = {}
        self.default_policies = self._create_default_policies()
    
    def _create_default_policies(self) -> Dict[str, Policy]:
        """Create default security policies"""
        policies = {}
        
        # Critical vulnerabilities policy
        critical_policy = Policy(
            name="Critical Vulnerabilities",
            description="Fail on critical or high severity vulnerabilities",
            scope=PolicyScope.FINDING,
            compliance_standards=["PCI-DSS", "NIS2"],
            rules=[
                PolicyRule(
                    name="No Critical Vulnerabilities",
                    description="Critical vulnerabilities must be fixed immediately",
                    severities=[Severity.CRITICAL],
                    action=PolicyAction.FAIL,
                    message="Critical vulnerability found"
                ),
                PolicyRule(
                    name="No High Vulnerabilities",
                    description="High severity vulnerabilities must be addressed",
                    severities=[Severity.HIGH],
                    action=PolicyAction.FAIL,
                    message="High severity vulnerability found"
                ),
            ]
        )
        policies["critical_vulns"] = critical_policy
        
        # SQL Injection policy
        sqli_policy = Policy(
            name="No SQL Injection",
            description="SQL injection vulnerabilities are not tolerated",
            scope=PolicyScope.FINDING,
            compliance_standards=["PCI-DSS", "OWASP"],
            rules=[
                PolicyRule(
                    name="No SQL Injection",
                    description="SQL injection must be prevented",
                    vulnerability_types=[VulnerabilityType.SQL_INJECTION],
                    cwe_ids=["CWE-89"],
                    action=PolicyAction.FAIL,
                    message="SQL injection vulnerability detected"
                ),
            ]
        )
        policies["no_sqli"] = sqli_policy
        
        # Authentication policy
        auth_policy = Policy(
            name="Authentication Security",
            description="Ensure strong authentication mechanisms",
            scope=PolicyScope.FINDING,
            compliance_standards=["PCI-DSS", "NIST"],
            rules=[
                PolicyRule(
                    name="No Broken Authentication",
                    description="Broken authentication vulnerabilities must be fixed",
                    vulnerability_types=[VulnerabilityType.BROKEN_AUTH, VulnerabilityType.AUTH_BYPASS],
                    cwe_ids=["CWE-287", "CWE-306"],
                    action=PolicyAction.FAIL,
                    message="Authentication vulnerability detected"
                ),
            ]
        )
        policies["auth_security"] = auth_policy
        
        return policies
    
    def load_policy_from_yaml(self, yaml_path: str) -> Policy:
        """Load policy from YAML file"""
        with open(yaml_path, 'r') as f:
            policy_data = yaml.safe_load(f)
        
        return self._parse_policy(policy_data)
    
    def load_policy_from_dict(self, policy_data: Dict[str, Any]) -> Policy:
        """Load policy from dictionary"""
        return self._parse_policy(policy_data)
    
    def _parse_policy(self, data: Dict[str, Any]) -> Policy:
        """Parse policy data"""
        policy = Policy(
            name=data.get('name', ''),
            description=data.get('description', ''),
            version=data.get('version', '1.0'),
            enabled=data.get('enabled', True),
            scope=PolicyScope(data.get('scope', 'finding')),
            author=data.get('author', ''),
            tags=data.get('tags', []),
            compliance_standards=data.get('compliance_standards', []),
        )
        
        # Parse rules
        for rule_data in data.get('rules', []):
            rule = PolicyRule(
                name=rule_data.get('name', ''),
                description=rule_data.get('description', ''),
                action=PolicyAction(rule_data.get('action', 'fail')),
                message=rule_data.get('message', ''),
            )
            
            # Parse conditions
            for vuln_type in rule_data.get('vulnerability_types', []):
                try:
                    rule.vulnerability_types.append(VulnerabilityType(vuln_type))
                except ValueError:
                    pass
            
            for severity in rule_data.get('severities', []):
                try:
                    rule.severities.append(Severity(severity))
                except ValueError:
                    pass
            
            rule.cwe_ids = rule_data.get('cwe_ids', [])
            rule.cve_ids = rule_data.get('cve_ids', [])
            
            policy.rules.append(rule)
        
        return policy
    
    def add_policy(self, policy: Policy):
        """Add policy to engine"""
        self.policies[policy.name.lower().replace(' ', '_')] = policy
    
    def get_policy(self, name: str) -> Optional[Policy]:
        """Get policy by name"""
        return self.policies.get(name.lower().replace(' ', '_'))
    
    def evaluate_finding(self, finding: Finding, 
                        policy: Policy) -> tuple[bool, List[str]]:
        """
        Evaluate a finding against a policy
        
        Returns:
            Tuple of (passed, violation_messages)
        """
        if not policy.enabled:
            return True, []
        
        violations = []
        
        for rule in policy.rules:
            # Check if finding matches rule conditions
            matches = self._check_rule(finding, rule)
            
            if matches:
                if rule.action == PolicyAction.FAIL:
                    violations.append(rule.message or f"Policy violation: {rule.name}")
                elif rule.action == PolicyAction.WARN:
                    violations.append(f"Warning: {rule.message or rule.name}")
                elif rule.action == PolicyAction.NOTIFY:
                    # Notification would be handled by caller
                    violations.append(f"Notification: {rule.message or rule.name}")
        
        return len(violations) == 0, violations
    
    def _check_rule(self, finding: Finding, rule: PolicyRule) -> bool:
        """Check if finding matches rule conditions"""
        # Check vulnerability type
        if rule.vulnerability_types:
            if finding.vulnerability_type not in rule.vulnerability_types:
                return False
        
        # Check severity
        if rule.severities:
            if finding.severity not in rule.severities:
                return False
        
        # Check CWE
        if rule.cwe_ids:
            if not finding.cwe_id or finding.cwe_id not in rule.cwe_ids:
                return False
        
        # Check CVE
        if rule.cve_ids:
            if not finding.cve_id or finding.cve_id not in rule.cve_ids:
                return False
        
        return True
    
    def evaluate_scan(self, findings: List[Finding], 
                     policy: Policy) -> tuple[bool, Dict[str, Any]]:
        """
        Evaluate scan results against a policy
        
        Returns:
            Tuple of (passed, evaluation_result)
        """
        all_violations = []
        findings_by_severity = {s: 0 for s in Severity}
        
        for finding in findings:
            passed, violations = self.evaluate_finding(finding, policy)
            all_violations.extend(violations)
            findings_by_severity[finding.severity] += 1
        
        result = {
            'policy_name': policy.name,
            'passed': len(all_violations) == 0,
            'total_findings': len(findings),
            'violations': all_violations,
            'findings_by_severity': findings_by_severity,
            'compliance_standards': policy.compliance_standards,
        }
        
        return len(all_violations) == 0, result
    
    def export_policy_yaml(self, policy: Policy) -> str:
        """Export policy to YAML"""
        data = {
            'name': policy.name,
            'description': policy.description,
            'version': policy.version,
            'enabled': policy.enabled,
            'scope': policy.scope.value,
            'author': policy.author,
            'tags': policy.tags,
            'compliance_standards': policy.compliance_standards,
            'rules': [],
        }
        
        for rule in policy.rules:
            rule_data = {
                'name': rule.name,
                'description': rule.description,
                'action': rule.action.value,
                'message': rule.message,
                'vulnerability_types': [v.value for v in rule.vulnerability_types],
                'severities': [s.value for s in rule.severities],
                'cwe_ids': rule.cwe_ids,
                'cve_ids': rule.cve_ids,
            }
            data['rules'].append(rule_data)
        
        return yaml.dump(data, default_flow_style=False)
    
    def get_compliance_status(self, findings: List[Finding], 
                              standard: str) -> Dict[str, Any]:
        """Get compliance status for a standard"""
        status = {
            'standard': standard,
            'compliant': True,
            'violations': [],
            'critical_issues': 0,
            'high_issues': 0,
        }
        
        for finding in findings:
            # Check if finding is relevant to standard
            relevant = False
            
            if standard == "PCI-DSS":
                relevant = finding.severity in [Severity.CRITICAL, Severity.HIGH]
            elif standard == "NIS2":
                relevant = finding.severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM]
            
            if relevant:
                status['compliant'] = False
                status['violations'].append({
                    'title': finding.title,
                    'severity': finding.severity.value,
                    'cwe_id': finding.cwe_id,
                })
                
                if finding.severity == Severity.CRITICAL:
                    status['critical_issues'] += 1
                elif finding.severity == Severity.HIGH:
                    status['high_issues'] += 1
        
        return status
