"""
VulnScope - Policy Engine Unit Tests
Tests for security policy management
"""

import pytest
from uuid import uuid4
from unittest.mock import Mock, patch
from datetime import datetime

from src.evidence.policy import (
    PolicyEngine, Policy, PolicyRule,
    PolicyAction, PolicyScope
)
from src.core.models import Finding, Severity, VulnerabilityType


class TestPolicyRule:
    """Test PolicyRule class"""
    
    def test_create_rule(self):
        rule = PolicyRule(
            name="No Critical Vulnerabilities",
            description="Block critical vulns",
            action=PolicyAction.FAIL,
            message="Critical vulnerability found"
        )
        
        assert rule.name == "No Critical Vulnerabilities"
        assert rule.action == PolicyAction.FAIL
    
    def test_rule_with_severities(self):
        rule = PolicyRule(
            name="Block Critical and High",
            severities=[Severity.CRITICAL, Severity.HIGH],
            action=PolicyAction.FAIL
        )
        
        assert Severity.CRITICAL in rule.severities
        assert Severity.HIGH in rule.severities
    
    def test_rule_with_vulnerability_types(self):
        rule = PolicyRule(
            name="Block SQL Injection",
            vulnerability_types=[VulnerabilityType.SQL_INJECTION],
            action=PolicyAction.FAIL
        )
        
        assert VulnerabilityType.SQL_INJECTION in rule.vulnerability_types
    
    def test_rule_with_cwe_ids(self):
        rule = PolicyRule(
            name="Block CWE-89",
            cwe_ids=["CWE-89"],
            action=PolicyAction.FAIL
        )
        
        assert "CWE-89" in rule.cwe_ids
    
    def test_rule_default_action(self):
        rule = PolicyRule(name="Test Rule")
        assert rule.action == PolicyAction.FAIL
    
    def test_rule_actions(self):
        actions = [
            PolicyAction.FAIL,
            PolicyAction.WARN,
            PolicyAction.NOTIFY,
            PolicyAction.BLOCK,
        ]
        
        for action in actions:
            assert action is not None


class TestPolicy:
    """Test Policy class"""
    
    def test_create_policy(self):
        policy = Policy(
            name="Security Policy",
            description="Default security policy"
        )
        
        assert policy.name == "Security Policy"
        assert len(policy.rules) == 0
    
    def test_policy_with_rules(self):
        rule = PolicyRule(
            name="Block SQL Injection",
            vulnerability_types=[VulnerabilityType.SQL_INJECTION],
            action=PolicyAction.FAIL
        )
        
        policy = Policy(
            name="Test Policy",
            rules=[rule]
        )
        
        assert len(policy.rules) == 1
    
    def test_policy_enabled_default(self):
        policy = Policy(name="Test")
        assert policy.enabled == True
    
    def test_policy_version_default(self):
        policy = Policy(name="Test")
        assert policy.version == "1.0"
    
    def test_policy_scope_default(self):
        policy = Policy(name="Test")
        assert policy.scope == PolicyScope.FINDING
    
    def test_policy_compliance_standards(self):
        policy = Policy(
            name="PCI Policy",
            compliance_standards=["PCI-DSS", "NIS2"]
        )
        
        assert "PCI-DSS" in policy.compliance_standards
        assert "NIS2" in policy.compliance_standards
    
    def test_policy_metadata(self):
        policy = Policy(
            name="Test",
            author="Security Team",
            tags=["security", "compliance"]
        )
        
        assert policy.author == "Security Team"
        assert "security" in policy.tags


class TestPolicyScope:
    """Test PolicyScope enum"""
    
    def test_scopes(self):
        assert PolicyScope.SCAN == "scan"
        assert PolicyScope.TARGET == "target"
        assert PolicyScope.FINDING == "finding"
        assert PolicyScope.ENDPOINT == "endpoint"


class TestPolicyEngine:
    """Test PolicyEngine class"""
    
    def test_initialization(self):
        engine = PolicyEngine()
        assert engine is not None
        assert engine.default_policies is not None
    
    def test_default_policies_created(self):
        engine = PolicyEngine()
        
        # Should have default policies
        assert "critical_vulns" in engine.default_policies
        assert "no_sqli" in engine.default_policies
        assert "auth_security" in engine.default_policies
    
    def test_add_policy(self):
        engine = PolicyEngine()
        
        policy = Policy(name="Test Policy")
        engine.add_policy(policy)
        
        retrieved = engine.get_policy("test_policy")
        assert retrieved is not None
    
    def test_get_policy(self):
        engine = PolicyEngine()
        
        policy = Policy(name="My Custom Policy")
        engine.add_policy(policy)
        
        retrieved = engine.get_policy("my_custom_policy")
        assert retrieved is not None
        assert retrieved.name == "My Custom Policy"
    
    def test_get_nonexistent_policy(self):
        engine = PolicyEngine()
        
        retrieved = engine.get_policy("nonexistent")
        assert retrieved is None


class TestPolicyEvaluation:
    """Test policy evaluation"""
    
    def test_evaluate_finding_empty_rules(self):
        engine = PolicyEngine()
        
        policy = Policy(name="Empty Policy", rules=[])
        finding = Finding(
            scan_id=uuid4(),
            target_id=uuid4(),
            title="Test Finding",
            description="Test",
            severity=Severity.HIGH,
            vulnerability_type=VulnerabilityType.XSS
        )
        
        passed, violations = engine.evaluate_finding(finding, policy)
        
        assert passed == True
        assert len(violations) == 0
    
    def test_evaluate_finding_with_severity_match(self):
        engine = PolicyEngine()
        
        policy = Policy(
            name="Block Critical",
            rules=[
                PolicyRule(
                    name="No Critical",
                    severities=[Severity.CRITICAL],
                    action=PolicyAction.FAIL,
                    message="Critical found"
                )
            ]
        )
        
        finding = Finding(
            scan_id=uuid4(),
            target_id=uuid4(),
            title="Critical Issue",
            description="Test",
            severity=Severity.CRITICAL,
            vulnerability_type=VulnerabilityType.SQL_INJECTION
        )
        
        passed, violations = engine.evaluate_finding(finding, policy)
        
        assert passed == False
        assert len(violations) == 1
    
    def test_evaluate_finding_with_vuln_type_match(self):
        engine = PolicyEngine()
        
        policy = Policy(
            name="Block SQLi",
            rules=[
                PolicyRule(
                    name="No SQLi",
                    vulnerability_types=[VulnerabilityType.SQL_INJECTION],
                    action=PolicyAction.FAIL,
                    message="SQLi found"
                )
            ]
        )
        
        finding = Finding(
            scan_id=uuid4(),
            target_id=uuid4(),
            title="SQL Injection",
            description="Test",
            severity=Severity.HIGH,
            vulnerability_type=VulnerabilityType.SQL_INJECTION
        )
        
        passed, violations = engine.evaluate_finding(finding, policy)
        
        assert passed == False
    
    def test_evaluate_finding_warn_action(self):
        engine = PolicyEngine()
        
        policy = Policy(
            name="Warn on Medium",
            rules=[
                PolicyRule(
                    name="Medium Warning",
                    severities=[Severity.MEDIUM],
                    action=PolicyAction.WARN,
                    message="Medium severity issue"
                )
            ]
        )
        
        finding = Finding(
            scan_id=uuid4(),
            target_id=uuid4(),
            title="Medium Issue",
            description="Test",
            severity=Severity.MEDIUM,
            vulnerability_type=VulnerabilityType.XSS
        )
        
        passed, violations = engine.evaluate_finding(finding, policy)
        
        # WARN doesn't fail, just adds warning
        assert passed == False  # violations exist but are warnings
        assert "Warning" in violations[0]
    
    def test_evaluate_scan_empty_findings(self):
        engine = PolicyEngine()
        
        policy = Policy(name="Test")
        passed, result = engine.evaluate_scan([], policy)
        
        assert passed == True
        assert result['total_findings'] == 0
    
    def test_evaluate_scan_with_findings(self):
        engine = PolicyEngine()
        
        policy = Policy(
            name="Block Critical",
            rules=[
                PolicyRule(
                    name="No Critical",
                    severities=[Severity.CRITICAL],
                    action=PolicyAction.FAIL
                )
            ]
        )
        
        scan_id = uuid4()
        target_id = uuid4()
        
        findings = [
            Finding(
                scan_id=scan_id,
                target_id=target_id,
                title="Critical Issue",
                description="Test",
                severity=Severity.CRITICAL,
                vulnerability_type=VulnerabilityType.SQL_INJECTION
            )
        ]
        
        passed, result = engine.evaluate_scan(findings, policy)
        
        assert passed == False
        assert result['total_findings'] == 1
    
    def test_disabled_policy_passes(self):
        engine = PolicyEngine()
        
        policy = Policy(
            name="Disabled Policy",
            enabled=False,
            rules=[
                PolicyRule(
                    name="Block All",
                    severities=[Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM],
                    action=PolicyAction.FAIL
                )
            ]
        )
        
        finding = Finding(
            scan_id=uuid4(),
            target_id=uuid4(),
            title="Critical Issue",
            description="Test",
            severity=Severity.CRITICAL,
            vulnerability_type=VulnerabilityType.SQL_INJECTION
        )
        
        passed, violations = engine.evaluate_finding(finding, policy)
        
        assert passed == True
        assert len(violations) == 0


class TestComplianceStatus:
    """Test compliance status functionality"""
    
    def test_pci_dss_compliance(self):
        engine = PolicyEngine()
        
        findings = [
            Finding(
                scan_id=uuid4(),
                target_id=uuid4(),
                title="Critical Issue",
                description="Test",
                severity=Severity.CRITICAL,
                vulnerability_type=VulnerabilityType.SQL_INJECTION
            )
        ]
        
        status = engine.get_compliance_status(findings, "PCI-DSS")
        
        assert status['standard'] == "PCI-DSS"
        assert status['compliant'] == False
        assert status['critical_issues'] == 1
    
    def test_nis2_compliance(self):
        engine = PolicyEngine()
        
        findings = [
            Finding(
                scan_id=uuid4(),
                target_id=uuid4(),
                title="Medium Issue",
                description="Test",
                severity=Severity.MEDIUM,
                vulnerability_type=VulnerabilityType.XSS
            )
        ]
        
        status = engine.get_compliance_status(findings, "NIS2")
        
        assert status['compliant'] == False
        assert len(status['violations']) == 1
    
    def test_compliance_no_findings(self):
        engine = PolicyEngine()
        
        status = engine.get_compliance_status([], "PCI-DSS")
        
        assert status['compliant'] == True
        assert status['critical_issues'] == 0


class TestPolicyYAML:
    """Test YAML import/export"""
    
    def test_export_policy_yaml(self):
        engine = PolicyEngine()
        
        policy = Policy(
            name="Test Policy",
            description="Test Description",
            rules=[
                PolicyRule(
                    name="Block SQLi",
                    vulnerability_types=[VulnerabilityType.SQL_INJECTION],
                    action=PolicyAction.FAIL
                )
            ]
        )
        
        yaml_str = engine.export_policy_yaml(policy)
        
        assert "Test Policy" in yaml_str
        assert "Block SQLi" in yaml_str
    
    def test_load_policy_from_dict(self):
        engine = PolicyEngine()
        
        policy_data = {
            'name': 'Custom Policy',
            'description': 'Custom policy from dict',
            'version': '2.0',
            'enabled': True,
            'scope': 'finding',
            'rules': [
                {
                    'name': 'Block XSS',
                    'action': 'fail',
                    'vulnerability_types': ['xss'],
                    'severities': ['high']
                }
            ]
        }
        
        policy = engine.load_policy_from_dict(policy_data)
        
        assert policy.name == "Custom Policy"
        assert policy.version == "2.0"
        assert len(policy.rules) == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])