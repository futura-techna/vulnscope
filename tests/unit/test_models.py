"""
VulnScope - Models Unit Tests
Tests for core data models
"""

import pytest
from datetime import datetime
from uuid import uuid4

from src.core.models import (
    Target, Endpoint, Finding, Scan, ScanResult, Report,
    Severity, Status, VulnerabilityType
)


class TestSeverity:
    """Test Severity enum"""
    
    def test_severity_values(self):
        assert Severity.CRITICAL.value == "CRITICAL"
        assert Severity.HIGH.value == "HIGH"
        assert Severity.MEDIUM.value == "MEDIUM"
        assert Severity.LOW.value == "LOW"
        assert Severity.INFO.value == "INFO"
    
    def test_severity_ordering(self):
        # Critical should be most severe
        severities = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        assert len(severities) == 5


class TestStatus:
    """Test Status enum"""
    
    def test_status_values(self):
        assert Status.PENDING.value == "PENDING"
        assert Status.RUNNING.value == "RUNNING"
        assert Status.COMPLETED.value == "COMPLETED"
        assert Status.FAILED.value == "FAILED"
        assert Status.CANCELLED.value == "CANCELLED"


class TestVulnerabilityType:
    """Test VulnerabilityType enum"""
    
    def test_vulnerability_types_exist(self):
        assert VulnerabilityType.SQL_INJECTION is not None
        assert VulnerabilityType.XSS is not None
        assert VulnerabilityType.SSRF is not None
        assert VulnerabilityType.IDOR is not None
        assert VulnerabilityType.CSRF is not None
    
    def test_vulnerability_type_values(self):
        assert VulnerabilityType.SQL_INJECTION.value == "SQL_INJECTION"
        assert VulnerabilityType.XSS.value == "XSS"


class TestTarget:
    """Test Target model"""
    
    def test_create_target(self):
        target = Target(
            name="Test Target",
            url="http://example.com"
        )
        
        assert target.name == "Test Target"
        assert str(target.url) == "http://example.com/"
    
    def test_target_default_values(self):
        target = Target(
            name="Test",
            url="http://example.com"
        )
        
        assert target.id is not None
        assert len(target.tags) == 0
        assert target.auth_type is None
        assert target.auth_config == {}
    
    def test_target_with_auth(self):
        target = Target(
            name="Test",
            url="http://example.com",
            auth_type="bearer",
            auth_config={"token": "test-token"}
        )
        
        assert target.auth_type == "bearer"
        assert target.auth_config["token"] == "test-token"
    
    def test_target_timestamps(self):
        before = datetime.utcnow()
        target = Target(name="Test", url="http://example.com")
        after = datetime.utcnow()
        
        assert before <= target.created_at <= after
        assert before <= target.updated_at <= after


class TestEndpoint:
    """Test Endpoint model"""
    
    def test_create_endpoint(self):
        target_id = uuid4()
        
        endpoint = Endpoint(
            target_id=target_id,
            url="http://example.com/api/users",
            method="GET",
            path="/api/users"
        )
        
        assert endpoint.target_id == target_id
        assert endpoint.url == "http://example.com/api/users"
        assert endpoint.method == "GET"
        assert endpoint.path == "/api/users"
    
    def test_endpoint_default_values(self):
        target_id = uuid4()
        
        endpoint = Endpoint(
            target_id=target_id,
            url="http://example.com",
            method="GET",
            path="/"
        )
        
        assert endpoint.parameters == []
        assert endpoint.headers == {}
        assert endpoint.body is None
        assert endpoint.source == "crawler"
    
    def test_endpoint_with_parameters(self):
        target_id = uuid4()
        
        endpoint = Endpoint(
            target_id=target_id,
            url="http://example.com/search",
            method="GET",
            path="/search",
            parameters=[
                {"name": "q", "type": "string"},
                {"name": "page", "type": "integer"}
            ]
        )
        
        assert len(endpoint.parameters) == 2
    
    def test_endpoint_is_api_detection(self):
        target_id = uuid4()
        
        api_endpoint = Endpoint(
            target_id=target_id,
            url="http://example.com/api/users",
            method="GET",
            path="/api/users"
        )
        api_endpoint.is_api = True
        
        assert api_endpoint.is_api == True


class TestFinding:
    """Test Finding model"""
    
    def test_create_finding(self):
        scan_id = uuid4()
        target_id = uuid4()
        
        finding = Finding(
            scan_id=scan_id,
            target_id=target_id,
            title="SQL Injection",
            description="SQL injection vulnerability",
            severity=Severity.CRITICAL,
            vulnerability_type=VulnerabilityType.SQL_INJECTION
        )
        
        assert finding.title == "SQL Injection"
        assert finding.severity == Severity.CRITICAL
        assert finding.vulnerability_type == VulnerabilityType.SQL_INJECTION
    
    def test_finding_default_status(self):
        scan_id = uuid4()
        target_id = uuid4()
        
        finding = Finding(
            scan_id=scan_id,
            target_id=target_id,
            title="Test",
            description="Test",
            severity=Severity.HIGH,
            vulnerability_type=VulnerabilityType.XSS
        )
        
        assert finding.status == Status.PENDING
        assert finding.false_positive == False
        assert finding.verified == False
    
    def test_finding_with_evidence(self):
        scan_id = uuid4()
        target_id = uuid4()
        
        finding = Finding(
            scan_id=scan_id,
            target_id=target_id,
            title="XSS",
            description="XSS vulnerability",
            severity=Severity.HIGH,
            vulnerability_type=VulnerabilityType.XSS,
            evidence={
                "payload": "<script>alert(1)</script>",
                "response": "..."
            }
        )
        
        assert finding.evidence["payload"] == "<script>alert(1)</script>"
    
    def test_finding_with_cwe(self):
        scan_id = uuid4()
        target_id = uuid4()
        
        finding = Finding(
            scan_id=scan_id,
            target_id=target_id,
            title="SQLi",
            description="SQL injection",
            severity=Severity.CRITICAL,
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
            cwe_id="CWE-89"
        )
        
        assert finding.cwe_id == "CWE-89"


class TestScan:
    """Test Scan model"""
    
    def test_create_scan(self):
        target_id = uuid4()
        
        scan = Scan(
            target_id=target_id,
            name="Test Scan"
        )
        
        assert scan.target_id == target_id
        assert scan.name == "Test Scan"
    
    def test_scan_default_values(self):
        target_id = uuid4()
        
        scan = Scan(target_id=target_id, name="Test")
        
        assert scan.scan_type == "full"
        assert scan.status == Status.PENDING
        assert scan.enable_crawler == True
        assert scan.enable_dast == True
    
    def test_scan_configuration(self):
        target_id = uuid4()
        
        scan = Scan(
            target_id=target_id,
            name="Quick Scan",
            scan_type="quick",
            enable_fuzzer=False,
            max_requests_per_second=50
        )
        
        assert scan.scan_type == "quick"
        assert scan.enable_fuzzer == False
        assert scan.max_requests_per_second == 50


class TestScanResult:
    """Test ScanResult model"""
    
    def test_empty_result(self):
        scan = Scan(target_id=uuid4(), name="Test")
        target = Target(name="Test", url="http://example.com")
        
        result = ScanResult(scan=scan, target=target)
        
        assert len(result.findings) == 0
        assert len(result.endpoints) == 0
        assert len(result.errors) == 0
    
    def test_result_with_findings(self):
        scan_id = uuid4()
        target_id = uuid4()
        
        scan = Scan(id=scan_id, target_id=target_id, name="Test")
        target = Target(id=target_id, name="Test", url="http://example.com")
        
        findings = [
            Finding(
                scan_id=scan_id,
                target_id=target_id,
                title="XSS",
                description="XSS",
                severity=Severity.HIGH,
                vulnerability_type=VulnerabilityType.XSS
            )
        ]
        
        result = ScanResult(scan=scan, target=target, findings=findings)
        
        assert len(result.findings) == 1


class TestReport:
    """Test Report model"""
    
    def test_create_report(self):
        scan_id = uuid4()
        target_id = uuid4()
        
        report = Report(
            scan_id=scan_id,
            target_id=target_id,
            title="Security Report"
        )
        
        assert report.scan_id == scan_id
        assert report.title == "Security Report"
    
    def test_report_default_values(self):
        scan_id = uuid4()
        target_id = uuid4()
        
        report = Report(scan_id=scan_id, target_id=target_id, title="Test")
        
        assert report.format == "json"
        assert len(report.findings) == 0
        assert len(report.recommendations) == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])