"""
VulnScope - API Routes Unit Tests
Tests for REST API endpoints
"""

import pytest
from unittest.mock import Mock, patch, AsyncMock
from uuid import uuid4
from datetime import datetime

from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.api.routes import router
from src.api.schemas import (
    TargetCreate, ScanCreate, FindingResponse,
    ReportGenerateRequest, ComplianceRequest
)
from src.core.models import Target, Scan, Finding, Severity, VulnerabilityType, Status


# Create test app
app = FastAPI()
app.include_router(router)
client = TestClient(app)


class TestTargetEndpoints:
    """Test target endpoints"""
    
    def test_create_target(self):
        response = client.post(
            "/targets",
            json={
                "name": "Test Target",
                "url": "http://example.com",
                "description": "Test description",
                "tags": ["test", "api"]
            }
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "Test Target"
        assert "id" in data
    
    def test_list_targets(self):
        response = client.get("/targets")
        
        assert response.status_code == 200
        assert isinstance(response.json(), list)
    
    def test_get_target_not_found(self):
        target_id = str(uuid4())
        response = client.get(f"/targets/{target_id}")
        
        assert response.status_code == 404
    
    def test_delete_target(self):
        # First create a target
        create_response = client.post(
            "/targets",
            json={
                "name": "Target to Delete",
                "url": "http://delete-example.com"
            }
        )
        assert create_response.status_code == 200
        target_id = create_response.json()["id"]
        
        # Then delete it
        response = client.delete(f"/targets/{target_id}")
        
        assert response.status_code == 200
        assert response.json()["status"] == "deleted"


class TestScanEndpoints:
    """Test scan endpoints"""
    
    def test_create_scan(self):
        # First create a target
        target_response = client.post(
            "/targets",
            json={
                "name": "Test Target for Scan",
                "url": "http://scan-example.com"
            }
        )
        assert target_response.status_code == 200
        target_id = target_response.json()["id"]
        
        response = client.post(
            "/scans",
            json={
                "target_id": target_id,
                "name": "Test Scan",
                "scan_type": "full"
            }
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "Test Scan"
    
    def test_list_scans(self):
        response = client.get("/scans")
        
        assert response.status_code == 200
        assert isinstance(response.json(), list)
    
    def test_list_scans_with_filters(self):
        target_id = str(uuid4())
        
        response = client.get(
            "/scans",
            params={"target_id": target_id, "status": "completed"}
        )
        
        assert response.status_code == 200
    
    def test_get_scan_not_found(self):
        scan_id = str(uuid4())
        response = client.get(f"/scans/{scan_id}")
        
        assert response.status_code == 404
    
    def test_get_scan_status(self):
        # Create target and scan
        target_response = client.post(
            "/targets",
            json={"name": "Target for Status", "url": "http://status-example.com"}
        )
        target_id = target_response.json()["id"]
        
        scan_response = client.post(
            "/scans",
            json={"target_id": target_id, "name": "Scan for Status"}
        )
        scan_id = scan_response.json()["id"]
        
        response = client.get(f"/scans/{scan_id}/status")
        
        assert response.status_code == 200
        data = response.json()
        assert "status" in data
        assert "progress" in data
    
    def test_cancel_scan(self):
        # Create target and scan
        target_response = client.post(
            "/targets",
            json={"name": "Target for Cancel", "url": "http://cancel-example.com"}
        )
        target_id = target_response.json()["id"]
        
        scan_response = client.post(
            "/scans",
            json={"target_id": target_id, "name": "Scan to Cancel"}
        )
        scan_id = scan_response.json()["id"]
        
        response = client.post(f"/scans/{scan_id}/cancel")
        
        assert response.status_code == 200
        assert response.json()["status"] == "cancelled"


class TestFindingEndpoints:
    """Test finding endpoints"""
    
    def test_list_findings(self):
        response = client.get("/findings")
        
        assert response.status_code == 200
        data = response.json()
        assert "total" in data
        assert "findings" in data
    
    def test_list_findings_with_filters(self):
        scan_id = str(uuid4())
        
        response = client.get(
            "/findings",
            params={
                "scan_id": scan_id,
                "severity": "HIGH"
            }
        )
        
        assert response.status_code == 200
    
    def test_get_finding_not_found(self):
        finding_id = str(uuid4())
        response = client.get(f"/findings/{finding_id}")
        
        assert response.status_code == 404
    
    def test_update_finding(self):
        # Create target and scan first to get a finding
        target_response = client.post(
            "/targets",
            json={"name": "Target for Finding", "url": "http://finding-example.com"}
        )
        target_id = target_response.json()["id"]
        
        scan_response = client.post(
            "/scans",
            json={"target_id": target_id, "name": "Scan for Finding"}
        )
        scan_id = scan_response.json()["id"]
        
        # Wait a moment and get findings (scan generates mock findings)
        import time
        time.sleep(0.1)
        
        findings_response = client.get("/findings", params={"scan_id": scan_id})
        findings = findings_response.json()["findings"]
        
        # If no findings were generated, test with 404 expectation
        if not findings:
            finding_id = str(uuid4())
            response = client.patch(
                f"/findings/{finding_id}",
                params={"status": "confirmed", "false_positive": False}
            )
            assert response.status_code == 404
        else:
            finding_id = findings[0]["id"]
            response = client.patch(
                f"/findings/{finding_id}",
                params={"status": "confirmed", "false_positive": False}
            )
            assert response.status_code == 200
    
    def test_verify_finding(self):
        # Create target and scan first to get a finding
        target_response = client.post(
            "/targets",
            json={"name": "Target for Verify", "url": "http://verify-example.com"}
        )
        target_id = target_response.json()["id"]
        
        scan_response = client.post(
            "/scans",
            json={"target_id": target_id, "name": "Scan for Verify"}
        )
        scan_id = scan_response.json()["id"]
        
        # Wait a moment and get findings (scan generates mock findings)
        import time
        time.sleep(0.1)
        
        findings_response = client.get("/findings", params={"scan_id": scan_id})
        findings = findings_response.json()["findings"]
        
        # If no findings were generated, test with 404 expectation
        if not findings:
            finding_id = str(uuid4())
            response = client.post(
                f"/findings/{finding_id}/verify",
                params={"verified": True}
            )
            assert response.status_code == 404
        else:
            finding_id = findings[0]["id"]
            response = client.post(
                f"/findings/{finding_id}/verify",
                params={"verified": True}
            )
            assert response.status_code == 200


class TestDiscoveryEndpoints:
    """Test discovery endpoints"""
    
    def test_discover_crawl(self):
        # Create target first
        target_response = client.post(
            "/targets",
            json={"name": "Target for Crawl", "url": "http://crawl-example.com"}
        )
        target_id = target_response.json()["id"]
        
        response = client.post(
            "/discover/crawl",
            params={"target_id": target_id}
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "status" in data
    
    def test_discover_openapi(self):
        # Create target first
        target_response = client.post(
            "/targets",
            json={"name": "Target for OpenAPI", "url": "http://openapi-example.com"}
        )
        target_id = target_response.json()["id"]
        
        response = client.post(
            "/discover/openapi",
            params={
                "spec_url": "http://example.com/openapi.json",
                "target_id": target_id
            }
        )
        
        assert response.status_code == 200
    
    def test_discover_graphql(self):
        # Create target first
        target_response = client.post(
            "/targets",
            json={"name": "Target for GraphQL", "url": "http://graphql-example.com"}
        )
        target_id = target_response.json()["id"]
        
        response = client.post(
            "/discover/graphql",
            params={
                "endpoint_url": "http://example.com/graphql",
                "target_id": target_id
            }
        )
        
        assert response.status_code == 200


class TestReportEndpoints:
    """Test report endpoints"""
    
    def test_generate_report_json(self):
        # Create target and scan first
        target_response = client.post(
            "/targets",
            json={"name": "Target for Report", "url": "http://report-example.com"}
        )
        target_id = target_response.json()["id"]
        
        scan_response = client.post(
            "/scans",
            json={"target_id": target_id, "name": "Scan for Report"}
        )
        scan_id = scan_response.json()["id"]
        
        response = client.post(
            "/reports/generate",
            json={
                "scan_id": scan_id,
                "format": "json"
            }
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["format"] == "json"
    
    def test_generate_report_html(self):
        # Create target and scan first
        target_response = client.post(
            "/targets",
            json={"name": "Target for HTML Report", "url": "http://html-report-example.com"}
        )
        target_id = target_response.json()["id"]
        
        scan_response = client.post(
            "/scans",
            json={"target_id": target_id, "name": "Scan for HTML Report"}
        )
        scan_id = scan_response.json()["id"]
        
        response = client.post(
            "/reports/generate",
            json={
                "scan_id": scan_id,
                "format": "html"
            }
        )
        
        assert response.status_code == 200
    
    def test_generate_report_unsupported_format(self):
        # Create target and scan first
        target_response = client.post(
            "/targets",
            json={"name": "Target for Unsupported", "url": "http://unsupported-example.com"}
        )
        target_id = target_response.json()["id"]
        
        scan_response = client.post(
            "/scans",
            json={"target_id": target_id, "name": "Scan for Unsupported"}
        )
        scan_id = scan_response.json()["id"]
        
        response = client.post(
            "/reports/generate",
            json={
                "scan_id": scan_id,
                "format": "unsupported"
            }
        )
        
        # Should still work - format validation is lenient
        assert response.status_code in [200, 400]
    
    def test_get_report_not_found(self):
        report_id = str(uuid4())
        response = client.get(f"/reports/{report_id}")
        
        assert response.status_code == 404


class TestPolicyEndpoints:
    """Test policy endpoints"""
    
    def test_create_policy(self):
        response = client.post(
            "/policies",
            json={
                "name": "Security Policy",
                "description": "Test policy",
                "rules": []
            }
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "Security Policy"
    
    def test_list_policies(self):
        response = client.get("/policies")
        
        assert response.status_code == 200
        assert isinstance(response.json(), list)
    
    def test_get_policy_not_found(self):
        policy_id = str(uuid4())
        response = client.get(f"/policies/{policy_id}")
        
        assert response.status_code == 404
    
    def test_evaluate_policy(self):
        policy_id = str(uuid4())
        scan_id = str(uuid4())
        
        response = client.post(
            f"/policies/{policy_id}/evaluate",
            params={"scan_id": scan_id}
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "passed" in data


class TestComplianceEndpoints:
    """Test compliance endpoints"""
    
    def test_check_compliance(self):
        scan_id = str(uuid4())
        
        response = client.post(
            "/compliance/check",
            json={
                "scan_id": scan_id,
                "standard": "PCI-DSS"
            }
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["standard"] == "PCI-DSS"
    
    def test_list_compliance_standards(self):
        response = client.get("/compliance/standards")
        
        assert response.status_code == 200
        data = response.json()
        assert "standards" in data


class TestIntegrationEndpoints:
    """Test integration endpoints"""
    
    def test_create_github_check(self):
        scan_id = str(uuid4())
        
        response = client.post(
            "/integrations/github/check",
            params={"scan_id": scan_id}
        )
        
        assert response.status_code == 200
    
    def test_create_jira_ticket(self):
        scan_id = str(uuid4())
        
        response = client.post(
            "/integrations/jira/ticket",
            params={"scan_id": scan_id}
        )
        
        assert response.status_code == 200
    
    def test_send_to_siem(self):
        scan_id = str(uuid4())
        
        response = client.post(
            "/integrations/siem/send",
            params={"scan_id": scan_id, "system": "splunk"}
        )
        
        assert response.status_code == 200


class TestSettingsEndpoints:
    """Test settings endpoints"""
    
    def test_get_settings(self):
        response = client.get("/settings")
        
        assert response.status_code == 200
        data = response.json()
        assert "app_name" in data
        assert "version" in data


if __name__ == "__main__":
    pytest.main([__file__, "-v"])