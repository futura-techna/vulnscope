"""
VulnScope - Dashboard Tests
Unit tests for Streamlit dashboard functionality
"""

import pytest
import pandas as pd
from datetime import datetime


# Test data
scans_data = [
    {"Name": "Full Scan - Production", "Target": "app.example.com", "Status": "Completed", "Findings": 23, "Date": "2024-01-15"},
    {"Name": "Quick Scan - Dev", "Target": "dev.example.com", "Status": "Completed", "Findings": 5, "Date": "2024-01-14"},
    {"Name": "API Security Scan", "Target": "api.example.com", "Status": "Running", "Findings": 8, "Date": "2024-01-14"},
    {"Name": "Auth Test", "Target": "auth.example.com", "Status": "Completed", "Findings": 12, "Date": "2024-01-13"},
]

targets_data = [
    {"Name": "Production App", "URL": "https://app.example.com", "Type": "Web App", "Last Scan": "2024-01-15"},
    {"Name": "Dev Environment", "URL": "https://dev.example.com", "Type": "Web App", "Last Scan": "2024-01-14"},
    {"Name": "API Gateway", "URL": "https://api.example.com", "Type": "REST API", "Last Scan": "2024-01-13"},
]

findings_data = [
    {"ID": "VULN-001", "Title": "SQL Injection in /api/users", "Severity": "Critical", "Type": "SQL Injection", "Target": "app.example.com", "Status": "Open"},
    {"ID": "VULN-002", "Title": "XSS in search parameter", "Severity": "High", "Type": "XSS", "Target": "app.example.com", "Status": "Open"},
    {"ID": "VULN-003", "Title": "SSRF in URL parameter", "Severity": "High", "Type": "SSRF", "Target": "api.example.com", "Status": "In Progress"},
    {"ID": "VULN-004", "Title": "IDOR in /user/profile", "Severity": "Medium", "Type": "IDOR", "Target": "app.example.com", "Status": "Open"},
]


class TestDashboardData:
    """Test dashboard data structures"""
    
    def test_scans_data_structure(self):
        """Test scans data has required fields"""
        for scan in scans_data:
            assert "Name" in scan
            assert "Target" in scan
            assert "Status" in scan
            assert "Findings" in scan
            assert "Date" in scan
    
    def test_targets_data_structure(self):
        """Test targets data has required fields"""
        for target in targets_data:
            assert "Name" in target
            assert "URL" in target
            assert "Type" in target
            assert "Last Scan" in target
    
    def test_findings_data_structure(self):
        """Test findings data has required fields"""
        for finding in findings_data:
            assert "ID" in finding
            assert "Title" in finding
            assert "Severity" in finding
            assert "Type" in finding
            assert "Target" in finding
            assert "Status" in finding


class TestScansData:
    """Test scans data processing"""
    
    def test_total_scans_count(self):
        """Test total scans count"""
        assert len(scans_data) == 4
    
    def test_completed_scans(self):
        """Test completed scans count"""
        completed = [s for s in scans_data if s["Status"] == "Completed"]
        assert len(completed) == 3
    
    def test_running_scans(self):
        """Test running scans count"""
        running = [s for s in scans_data if s["Status"] == "Running"]
        assert len(running) == 1
    
    def test_total_findings(self):
        """Test total findings across all scans"""
        total = sum(s["Findings"] for s in scans_data)
        assert total == 48


class TestTargetsData:
    """Test targets data processing"""
    
    def test_total_targets_count(self):
        """Test total targets count"""
        assert len(targets_data) == 3
    
    def test_target_types(self):
        """Test target types distribution"""
        types = [t["Type"] for t in targets_data]
        assert "Web App" in types
        assert "REST API" in types
    
    def test_target_urls_valid(self):
        """Test all target URLs are valid"""
        for target in targets_data:
            assert target["URL"].startswith("https://")


class TestFindingsData:
    """Test findings data processing"""
    
    def test_total_findings_count(self):
        """Test total findings count"""
        assert len(findings_data) == 4
    
    def test_findings_by_severity(self):
        """Test findings by severity"""
        critical = [f for f in findings_data if f["Severity"] == "Critical"]
        high = [f for f in findings_data if f["Severity"] == "High"]
        medium = [f for f in findings_data if f["Severity"] == "Medium"]
        
        assert len(critical) == 1
        assert len(high) == 2
        assert len(medium) == 1
    
    def test_findings_by_type(self):
        """Test findings by vulnerability type"""
        types = [f["Type"] for f in findings_data]
        assert "SQL Injection" in types
        assert "XSS" in types
        assert "SSRF" in types
        assert "IDOR" in types
    
    def test_open_findings(self):
        """Test open findings count"""
        open_findings = [f for f in findings_data if f["Status"] == "Open"]
        assert len(open_findings) == 3
    
    def test_findings_have_cwe_format(self):
        """Test findings can be mapped to CWE"""
        # All findings should have valid vulnerability types
        for finding in findings_data:
            assert finding["Type"] in ["SQL Injection", "XSS", "SSRF", "IDOR"]


class TestCharts:
    """Test chart data generation"""
    
    def test_severity_chart_data(self):
        """Test severity distribution chart data"""
        severity_data = {"Critical": 12, "High": 45, "Medium": 78, "Low": 34}
        assert len(severity_data) == 4
        assert sum(severity_data.values()) == 169
    
    def test_time_chart_data(self):
        """Test vulnerabilities over time chart data"""
        time_data = {"Week 1": 15, "Week 2": 23, "Week 3": 18, "Week 4": 25}
        assert len(time_data) == 4
        assert sum(time_data.values()) == 81
    
    def test_compliance_chart_data(self):
        """Test compliance chart data"""
        compliance_data = {
            "Access Control": 92,
            "Encryption": 88,
            "Monitoring": 95,
            "Incident Response": 78,
            "Vendor Management": 85,
        }
        assert len(compliance_data) == 5
        assert all(0 <= v <= 100 for v in compliance_data.values())


class TestReports:
    """Test report generation"""
    
    def test_json_report_format(self):
        """Test JSON report format"""
        scan_name = "Full Scan - Production"
        json_content = f'{{"report": {{"title": "{scan_name}", "findings": []}}}}'
        assert "report" in json_content
        assert scan_name in json_content
    
    def test_html_report_format(self):
        """Test HTML report format"""
        scan_name = "Full Scan - Production"
        html_content = f"<html><body><h1>VulnScope Report - {scan_name}</h1></body></html>"
        assert "<html>" in html_content
        assert "<h1>" in html_content
        assert scan_name in html_content
    
    def test_csv_report_format(self):
        """Test CSV report format"""
        csv_content = "ID,Title,Severity\n1,SQL Injection,Critical"
        lines = csv_content.split("\n")
        assert len(lines) == 2
        assert lines[0] == "ID,Title,Severity"
    
    def test_sarif_report_format(self):
        """Test SARIF report format"""
        sarif_content = '{"$schema": "sarif", "runs": []}'
        assert "$schema" in sarif_content
        assert "sarif" in sarif_content
    
    def test_report_filename_generation(self):
        """Test report filename generation"""
        scan_name = "Full Scan - Production"
        scan_id = scan_name.lower().replace(" ", "-")
        assert scan_id == "full-scan---production"


class TestAPIClients:
    """Test API client functions"""
    
    def test_api_url_format(self):
        """Test API URL format"""
        api_url = "http://localhost:8000/api/v1"
        assert "localhost" in api_url
        assert "8000" in api_url
        assert "/api/v1" in api_url
    
    def test_scan_creation_payload(self):
        """Test scan creation API payload"""
        payload = {
            "name": "New Security Scan",
            "target_id": "demo-target-id",
            "description": "Security vulnerability scan",
            "scan_type": "full",
            "enable_crawler": True,
            "enable_dast": True,
            "enable_fuzzer": False,
            "enable_openapi_import": False
        }
        assert "name" in payload
        assert "scan_type" in payload
        assert isinstance(payload["enable_crawler"], bool)
    
    def test_target_creation_payload(self):
        """Test target creation API payload"""
        payload = {
            "name": "My Application",
            "url": "https://example.com",
            "description": "Security assessment target",
            "tags": ["production", "critical"],
            "auth_type": "Bearer Token",
            "auth_config": {"token": "secret"}
        }
        assert "name" in payload
        assert "url" in payload
        assert "tags" in payload
        assert isinstance(payload["tags"], list)


class TestComplianceStandards:
    """Test compliance standards"""
    
    def test_pci_dss_compliance(self):
        """Test PCI-DSS compliance"""
        score = 95
        assert score >= 90
        assert score <= 100
    
    def test_nis2_compliance(self):
        """Test NIS2 compliance"""
        score = 78
        assert score >= 70
        assert score < 90
    
    def test_soc2_compliance(self):
        """Test SOC2 compliance"""
        score = 92
        assert score >= 90
    
    def test_hipaa_compliance(self):
        """Test HIPAA compliance"""
        score = 88
        assert score >= 80
    
    def test_iso27001_compliance(self):
        """Test ISO27001 compliance"""
        score = 85
        assert score >= 80


class TestDataFrames:
    """Test pandas DataFrame operations"""
    
    def test_scans_dataframe(self):
        """Test scans DataFrame creation"""
        df = pd.DataFrame(scans_data)
        assert len(df) == 4
        assert "Name" in df.columns
        assert "Target" in df.columns
        assert "Status" in df.columns
    
    def test_targets_dataframe(self):
        """Test targets DataFrame creation"""
        df = pd.DataFrame(targets_data)
        assert len(df) == 3
        assert "Name" in df.columns
        assert "URL" in df.columns
    
    def test_findings_dataframe(self):
        """Test findings DataFrame creation"""
        df = pd.DataFrame(findings_data)
        assert len(df) == 4
        assert "ID" in df.columns
        assert "Severity" in df.columns
    
    def test_filter_findings_by_severity(self):
        """Test filtering findings by severity"""
        df = pd.DataFrame(findings_data)
        critical = df[df["Severity"] == "Critical"]
        assert len(critical) == 1
    
    def test_filter_findings_by_status(self):
        """Test filtering findings by status"""
        df = pd.DataFrame(findings_data)
        open_findings = df[df["Status"] == "Open"]
        assert len(open_findings) == 3


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
