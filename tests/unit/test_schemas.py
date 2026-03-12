"""
VulnScope - API Schemas Unit Tests
Tests for Pydantic validation models
"""

import pytest
from pydantic import ValidationError
from datetime import datetime
from uuid import uuid4, UUID

from src.api.schemas import (
    ScanStatus, Severity,
    TargetCreate, TargetUpdate, TargetResponse,
    ScanCreate, ScanResponse, ScanStatusResponse,
    FindingResponse, FindingListResponse,
    ReportGenerateRequest, ReportResponse,
    PolicyRuleInput, PolicyCreate, PolicyResponse,
    ComplianceRequest, ComplianceResponse,
    IntegrationConfig, GitHubCheckRequest, JiraTicketRequest, SIEMEventRequest
)


class TestEnums:
    """Test enum values"""
    
    def test_scan_status_values(self):
        """Test ScanStatus enum values"""
        assert ScanStatus.PENDING == "pending"
        assert ScanStatus.RUNNING == "running"
        assert ScanStatus.COMPLETED == "completed"
        assert ScanStatus.FAILED == "failed"
        assert ScanStatus.CANCELLED == "cancelled"
    
    def test_severity_values(self):
        """Test Severity enum values"""
        assert Severity.CRITICAL == "Critical"
        assert Severity.HIGH == "High"
        assert Severity.MEDIUM == "Medium"
        assert Severity.LOW == "Low"
        assert Severity.INFO == "Info"


class TestTargetSchemas:
    """Test Target-related schemas"""
    
    def test_target_create_minimal(self):
        """Test TargetCreate with minimal fields"""
        target = TargetCreate(name="Test Target", url="http://example.com")
        
        assert target.name == "Test Target"
        assert target.url == "http://example.com"
        assert target.description is None
        assert target.tags is None
    
    def test_target_create_full(self):
        """Test TargetCreate with all fields"""
        target = TargetCreate(
            name="Full Target",
            url="https://example.com",
            description="Test description",
            tags=["api", "production"],
            auth_type="bearer",
            auth_config={"token": "secret"}
        )
        
        assert target.name == "Full Target"
        assert target.url == "https://example.com"
        assert target.description == "Test description"
        assert target.tags == ["api", "production"]
        assert target.auth_type == "bearer"
    
    def test_target_create_missing_required(self):
        """Test TargetCreate missing required fields"""
        with pytest.raises(ValidationError):
            TargetCreate(name="Test")  # Missing url
        
        with pytest.raises(ValidationError):
            TargetCreate(url="http://example.com")  # Missing name
    
    def test_target_update_partial(self):
        """Test TargetUpdate with partial fields"""
        update = TargetUpdate(name="New Name")
        
        assert update.name == "New Name"
        assert update.url is None
        assert update.description is None
    
    def test_target_update_empty(self):
        """Test TargetUpdate with no fields"""
        update = TargetUpdate()
        
        assert update.name is None
        assert update.url is None
    
    def test_target_response(self):
        """Test TargetResponse schema"""
        target_id = uuid4()
        
        target = TargetResponse(
            id=target_id,
            name="Test Target",
            url="http://example.com",
            description="Description",
            tags=["test"],
            created_at=datetime.utcnow()
        )
        
        assert target.id == target_id
        assert target.name == "Test Target"
        assert target.tags == ["test"]


class TestScanSchemas:
    """Test Scan-related schemas"""
    
    def test_scan_create_minimal(self):
        """Test ScanCreate with minimal fields"""
        scan = ScanCreate(target_id="target-123", name="Test Scan")
        
        assert scan.target_id == "target-123"
        assert scan.name == "Test Scan"
        assert scan.scan_type == "full"  # Default value
        assert scan.enable_crawler is True  # Default value
        assert scan.enable_dast is True  # Default value
    
    def test_scan_create_full(self):
        """Test ScanCreate with all fields"""
        scan = ScanCreate(
            target_id="target-123",
            name="Full Scan",
            description="Complete scan",
            scan_type="stealth",
            enable_crawler=True,
            enable_openapi_import=True,
            enable_graphql_import=True,
            enable_dast=True,
            enable_fuzzer=True,
            max_concurrent=20,
            timeout=60,
            recursive_depth=5
        )
        
        assert scan.scan_type == "stealth"
        assert scan.enable_fuzzer is True
        assert scan.max_concurrent == 20
        assert scan.recursive_depth == 5
    
    def test_scan_create_missing_required(self):
        """Test ScanCreate missing required fields"""
        with pytest.raises(ValidationError):
            ScanCreate(target_id="123")  # Missing name
        
        with pytest.raises(ValidationError):
            ScanCreate(name="Test")  # Missing target_id
    
    def test_scan_response(self):
        """Test ScanResponse schema"""
        scan_id = uuid4()
        target_id = uuid4()
        
        scan = ScanResponse(
            id=scan_id,
            target_id=target_id,
            name="Test Scan",
            status="completed",
            progress=100,
            endpoints_discovered=50,
            findings_count=10,
            created_at=datetime.utcnow()
        )
        
        assert scan.id == scan_id
        assert scan.status == "completed"
        assert scan.progress == 100
    
    def test_scan_status_response(self):
        """Test ScanStatusResponse schema"""
        scan_id = uuid4()
        
        status = ScanStatusResponse(
            scan_id=scan_id,
            status="running",
            progress=50,
            endpoints_discovered=25,
            findings_count=5
        )
        
        assert status.progress == 50
        assert status.endpoints_discovered == 25
    
    def test_scan_status_progress_validation(self):
        """Test progress field validation (0-100)"""
        scan_id = uuid4()
        
        # Valid progress
        status = ScanStatusResponse(scan_id=scan_id, status="running", progress=50)
        assert status.progress == 50
        
        # Progress at boundaries
        status_0 = ScanStatusResponse(scan_id=scan_id, status="pending", progress=0)
        assert status_0.progress == 0
        
        status_100 = ScanStatusResponse(scan_id=scan_id, status="completed", progress=100)
        assert status_100.progress == 100


class TestFindingSchemas:
    """Test Finding-related schemas"""
    
    def test_finding_response_minimal(self):
        """Test FindingResponse with minimal fields"""
        finding_id = uuid4()
        scan_id = uuid4()
        target_id = uuid4()
        
        finding = FindingResponse(
            id=finding_id,
            scan_id=scan_id,
            target_id=target_id,
            title="XSS Vulnerability",
            severity="High",
            created_at=datetime.utcnow()
        )
        
        assert finding.title == "XSS Vulnerability"
        assert finding.severity == "High"
        assert finding.status == "Open"  # Default value
    
    def test_finding_response_full(self):
        """Test FindingResponse with all fields"""
        finding_id = uuid4()
        scan_id = uuid4()
        target_id = uuid4()
        
        finding = FindingResponse(
            id=finding_id,
            scan_id=scan_id,
            target_id=target_id,
            title="SQL Injection",
            description="SQL injection in login form",
            severity="Critical",
            vuln_type="SQL_INJECTION",
            url="http://example.com/login",
            method="POST",
            parameter="username",
            payload="' OR '1'='1",
            evidence="Database error message",
            status="Open",
            cvss_score=9.8,
            cwe_id="CWE-89",
            owasp_category="A03:2021",
            created_at=datetime.utcnow()
        )
        
        assert finding.title == "SQL Injection"
        assert finding.cvss_score == 9.8
        assert finding.cwe_id == "CWE-89"
    
    def test_finding_list_response(self):
        """Test FindingListResponse schema"""
        finding_id = uuid4()
        scan_id = uuid4()
        target_id = uuid4()
        
        findings = [
            FindingResponse(
                id=finding_id,
                scan_id=scan_id,
                target_id=target_id,
                title="Finding 1",
                severity="High",
                created_at=datetime.utcnow()
            )
        ]
        
        response = FindingListResponse(total=1, findings=findings)
        
        assert response.total == 1
        assert len(response.findings) == 1


class TestReportSchemas:
    """Test Report-related schemas"""
    
    def test_report_generate_request_minimal(self):
        """Test ReportGenerateRequest with minimal fields"""
        request = ReportGenerateRequest(scan_id="scan-123")
        
        assert request.scan_id == "scan-123"
        assert request.format == "json"  # Default
        assert request.include_evidence is True  # Default
    
    def test_report_generate_request_full(self):
        """Test ReportGenerateRequest with all fields"""
        request = ReportGenerateRequest(
            scan_id="scan-123",
            name="Security Report",
            format="html",
            include_evidence=True,
            compliance_standards=["PCI-DSS", "SOC2"]
        )
        
        assert request.format == "html"
        assert request.compliance_standards == ["PCI-DSS", "SOC2"]
    
    def test_report_response(self):
        """Test ReportResponse schema"""
        report_id = uuid4()
        scan_id = uuid4()
        
        report = ReportResponse(
            id=report_id,
            scan_id=scan_id,
            name="Test Report",
            format="json",
            download_url="/reports/123/download",
            created_at=datetime.utcnow()
        )
        
        assert report.format == "json"
        assert report.download_url == "/reports/123/download"


class TestPolicySchemas:
    """Test Policy-related schemas"""
    
    def test_policy_rule_input(self):
        """Test PolicyRuleInput schema"""
        rule = PolicyRuleInput(
            name="No Critical Vulnerabilities",
            description="Fail on critical vulnerabilities",
            vulnerability_types=["SQL_INJECTION", "XSS"],
            severities=["Critical"],
            action="fail"
        )
        
        assert rule.name == "No Critical Vulnerabilities"
        assert "SQL_INJECTION" in rule.vulnerability_types
        assert rule.action == "fail"
    
    def test_policy_create_minimal(self):
        """Test PolicyCreate with minimal fields"""
        policy = PolicyCreate(
            name="Security Policy",
            description="Default security policy"
        )
        
        assert policy.name == "Security Policy"
        assert policy.version == "1.0"  # Default
        assert policy.scope == "finding"  # Default
    
    def test_policy_create_with_rules(self):
        """Test PolicyCreate with rules"""
        rule = PolicyRuleInput(
            name="Rule 1",
            description="Test rule",
            severities=["Critical"],
            action="fail"
        )
        
        policy = PolicyCreate(
            name="Policy with Rules",
            description="Policy with custom rules",
            rules=[rule]
        )
        
        assert len(policy.rules) == 1
    
    def test_policy_response(self):
        """Test PolicyResponse schema"""
        policy_id = uuid4()
        
        policy = PolicyResponse(
            id=policy_id,
            name="Test Policy",
            description="Test description",
            rules_count=5,
            version="1.0"
        )
        
        assert policy.rules_count == 5


class TestComplianceSchemas:
    """Test Compliance-related schemas"""
    
    def test_compliance_request(self):
        """Test ComplianceRequest schema"""
        request = ComplianceRequest(
            scan_id="scan-123",
            standard="PCI-DSS"
        )
        
        assert request.standard == "PCI-DSS"
        assert request.scan_id == "scan-123"
    
    def test_compliance_request_standard_required(self):
        """Test that standard is required"""
        with pytest.raises(ValidationError):
            ComplianceRequest(scan_id="scan-123")
    
    def test_compliance_response(self):
        """Test ComplianceResponse schema"""
        response = ComplianceResponse(
            standard="PCI-DSS",
            compliant=True,
            score=95.5,
            violations=[],
            requirements=[{"id": "1.1", "name": "Requirement 1"}]
        )
        
        assert response.standard == "PCI-DSS"
        assert response.compliant is True
        assert response.score == 95.5


class TestIntegrationSchemas:
    """Test Integration-related schemas"""
    
    def test_integration_config(self):
        """Test IntegrationConfig schema"""
        config = IntegrationConfig(
            type="github",
            config={"token": "ghp_xxx", "repo": "owner/repo"}
        )
        
        assert config.type == "github"
        assert "token" in config.config
    
    def test_github_check_request(self):
        """Test GitHubCheckRequest schema"""
        scan_id = uuid4()
        
        request = GitHubCheckRequest(
            scan_id=scan_id,
            owner="owner",
            repo="repo",
            branch="develop"
        )
        
        assert request.owner == "owner"
        assert request.repo == "repo"
        assert request.branch == "develop"
    
    def test_github_check_request_default_branch(self):
        """Test GitHubCheckRequest default branch"""
        scan_id = uuid4()
        
        request = GitHubCheckRequest(
            scan_id=scan_id,
            owner="owner",
            repo="repo"
        )
        
        assert request.branch == "main"  # Default
    
    def test_jira_ticket_request(self):
        """Test JiraTicketRequest schema"""
        scan_id = uuid4()
        
        request = JiraTicketRequest(
            scan_id=scan_id,
            project_key="SEC",
            create_individual_tickets=True
        )
        
        assert request.project_key == "SEC"
        assert request.create_individual_tickets is True
    
    def test_siem_event_request(self):
        """Test SIEMEventRequest schema"""
        scan_id = uuid4()
        
        request = SIEMEventRequest(
            scan_id=scan_id,
            system="splunk",
            send_findings=True
        )
        
        assert request.system == "splunk"
        assert request.send_findings is True


class TestSchemaValidation:
    """Test schema validation edge cases"""
    
    def test_empty_required_string_validation(self):
        """Test that empty strings are handled"""
        # Pydantic may allow empty strings by default
        target = TargetCreate(name="", url="http://example.com")
        assert target.name == ""
    
    def test_invalid_uuid_format(self):
        """Test handling of invalid UUID format in response models"""
        # Pydantic will coerce string UUIDs
        target = TargetResponse(
            id="12345678-1234-5678-1234-567812345678",
            name="Test",
            url="http://example.com",
            created_at=datetime.utcnow()
        )
        
        assert isinstance(target.id, UUID)
    
    def test_datetime_coercion(self):
        """Test datetime field coercion"""
        # ISO format string should be coerced to datetime
        target = TargetResponse(
            id=uuid4(),
            name="Test",
            url="http://example.com",
            created_at="2024-01-01T00:00:00"
        )
        
        assert isinstance(target.created_at, datetime)


class TestSchemaSerialization:
    """Test schema serialization"""
    
    def test_target_create_dict(self):
        """Test TargetCreate to dict"""
        target = TargetCreate(
            name="Test",
            url="http://example.com",
            tags=["api"]
        )
        
        data = target.model_dump()
        
        assert data["name"] == "Test"
        assert data["url"] == "http://example.com"
        assert data["tags"] == ["api"]
    
    def test_finding_response_json(self):
        """Test FindingResponse JSON serialization"""
        finding_id = uuid4()
        scan_id = uuid4()
        target_id = uuid4()
        
        finding = FindingResponse(
            id=finding_id,
            scan_id=scan_id,
            target_id=target_id,
            title="Test Finding",
            severity="High",
            created_at=datetime.utcnow()
        )
        
        json_str = finding.model_dump_json()
        
        assert "Test Finding" in json_str
        assert "High" in json_str


if __name__ == "__main__":
    pytest.main([__file__, "-v"])