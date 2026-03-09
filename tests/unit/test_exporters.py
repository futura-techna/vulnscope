"""
VulnScope - Exporters Unit Tests
Tests for report exporters (JSON, XML, HTML, SARIF, CSV)
"""

import pytest
import json
from datetime import datetime
from uuid import uuid4
from unittest.mock import Mock, patch

from src.evidence.exporters import (
    Exporter, JSONExporter, XMLExporter, HTMLExporter,
    SARIFExporter, CSVExporter, ExporterFactory
)
from src.core.models import Finding, Scan, Target, Severity, VulnerabilityType, Status


class TestExporterFactory:
    """Test exporter factory"""
    
    def test_get_json_exporter(self):
        exporter = ExporterFactory.get_exporter("json")
        assert isinstance(exporter, JSONExporter)
    
    def test_get_xml_exporter(self):
        exporter = ExporterFactory.get_exporter("xml")
        assert isinstance(exporter, XMLExporter)
    
    def test_get_html_exporter(self):
        exporter = ExporterFactory.get_exporter("html")
        assert isinstance(exporter, HTMLExporter)
    
    def test_get_sarif_exporter(self):
        exporter = ExporterFactory.get_exporter("sarif")
        assert isinstance(exporter, SARIFExporter)
    
    def test_get_csv_exporter(self):
        exporter = ExporterFactory.get_exporter("csv")
        assert isinstance(exporter, CSVExporter)
    
    def test_get_unsupported_format(self):
        exporter = ExporterFactory.get_exporter("unsupported")
        assert exporter is None
    
    def test_get_supported_formats(self):
        formats = ExporterFactory.get_supported_formats()
        assert "json" in formats
        assert "xml" in formats
        assert "html" in formats
        assert "sarif" in formats
        assert "csv" in formats


class TestJSONExporter:
    """Test JSON exporter"""
    
    def test_format_property(self):
        exporter = JSONExporter()
        assert exporter.format == "json"
    
    def test_export_empty_findings(self):
        exporter = JSONExporter()
        
        scan_id = uuid4()
        target_id = uuid4()
        
        scan = Scan(
            id=scan_id,
            target_id=target_id,
            name="Test Scan"
        )
        
        target = Target(
            id=target_id,
            name="Test Target",
            url="http://example.com"
        )
        
        result = exporter.export([], scan, target)
        
        # Should be valid JSON
        data = json.loads(result)
        assert data["summary"]["total_findings"] == 0
    
    def test_export_with_findings(self):
        exporter = JSONExporter()
        
        scan_id = uuid4()
        target_id = uuid4()
        
        findings = [
            Finding(
                id=uuid4(),
                scan_id=scan_id,
                target_id=target_id,
                title="SQL Injection",
                description="SQL injection vulnerability",
                severity=Severity.CRITICAL,
                vulnerability_type=VulnerabilityType.SQL_INJECTION,
                status=Status.PENDING
            ),
            Finding(
                id=uuid4(),
                scan_id=scan_id,
                target_id=target_id,
                title="XSS",
                description="Cross-site scripting",
                severity=Severity.HIGH,
                vulnerability_type=VulnerabilityType.XSS,
                status=Status.PENDING
            ),
        ]
        
        scan = Scan(
            id=scan_id,
            target_id=target_id,
            name="Test Scan"
        )
        
        target = Target(
            id=target_id,
            name="Test Target",
            url="http://example.com"
        )
        
        result = exporter.export(findings, scan, target)
        
        data = json.loads(result)
        assert data["summary"]["total_findings"] == 2
        assert data["summary"]["by_severity"]["critical"] == 1
        assert data["summary"]["by_severity"]["high"] == 1
    
    def test_export_to_file(self):
        exporter = JSONExporter()
        
        scan_id = uuid4()
        target_id = uuid4()
        
        scan = Scan(id=scan_id, target_id=target_id, name="Test")
        target = Target(id=target_id, name="Test", url="http://example.com")
        
        with patch('pathlib.Path.mkdir'):
            with patch('builtins.open', create=True) as mock_open:
                mock_open.return_value.__enter__.return_value.write = Mock()
                
                result = exporter.export_to_file([], scan, target, "/tmp/report.json")
                
                assert result is not None


class TestXMLExporter:
    """Test XML exporter"""
    
    def test_format_property(self):
        exporter = XMLExporter()
        assert exporter.format == "xml"
    
    def test_export_empty_findings(self):
        exporter = XMLExporter()
        
        scan_id = uuid4()
        target_id = uuid4()
        
        scan = Scan(id=scan_id, target_id=target_id, name="Test Scan")
        target = Target(id=target_id, name="Test Target", url="http://example.com")
        
        result = exporter.export([], scan, target)
        
        assert "<?xml" in result
        assert "vulnscope-report" in result
    
    def test_export_with_findings(self):
        exporter = XMLExporter()
        
        scan_id = uuid4()
        target_id = uuid4()
        
        findings = [
            Finding(
                id=uuid4(),
                scan_id=scan_id,
                target_id=target_id,
                title="SQL Injection",
                description="SQLi",
                severity=Severity.CRITICAL,
                vulnerability_type=VulnerabilityType.SQL_INJECTION,
                status=Status.PENDING
            ),
        ]
        
        scan = Scan(id=scan_id, target_id=target_id, name="Test Scan")
        target = Target(id=target_id, name="Test Target", url="http://example.com")
        
        result = exporter.export(findings, scan, target)
        
        assert "<?xml" in result
        assert "SQL Injection" in result
        assert "CRITICAL" in result


class TestHTMLExporter:
    """Test HTML exporter"""
    
    def test_format_property(self):
        exporter = HTMLExporter()
        assert exporter.format == "html"
    
    def test_export_empty_findings(self):
        exporter = HTMLExporter()
        
        scan_id = uuid4()
        target_id = uuid4()
        
        scan = Scan(id=scan_id, target_id=target_id, name="Test Scan")
        target = Target(id=target_id, name="Test Target", url="http://example.com")
        
        result = exporter.export([], scan, target)
        
        assert "<!DOCTYPE html>" in result
        assert "VulnScope" in result
    
    def test_export_with_findings(self):
        exporter = HTMLExporter()
        
        scan_id = uuid4()
        target_id = uuid4()
        
        findings = [
            Finding(
                id=uuid4(),
                scan_id=scan_id,
                target_id=target_id,
                title="XSS Vulnerability",
                description="XSS found",
                severity=Severity.HIGH,
                vulnerability_type=VulnerabilityType.XSS,
                status=Status.PENDING
            ),
        ]
        
        scan = Scan(id=scan_id, target_id=target_id, name="Test Scan")
        target = Target(id=target_id, name="Test Target", url="http://example.com")
        
        result = exporter.export(findings, scan, target)
        
        assert "<!DOCTYPE html>" in result
        assert "XSS Vulnerability" in result
    
    def test_html_includes_summary(self):
        exporter = HTMLExporter()
        
        scan_id = uuid4()
        target_id = uuid4()
        
        findings = [
            Finding(
                id=uuid4(),
                scan_id=scan_id,
                target_id=target_id,
                title="Critical Issue",
                description="Critical",
                severity=Severity.CRITICAL,
                vulnerability_type=VulnerabilityType.SQL_INJECTION,
                status=Status.PENDING
            ),
            Finding(
                id=uuid4(),
                scan_id=scan_id,
                target_id=target_id,
                title="High Issue",
                description="High",
                severity=Severity.HIGH,
                vulnerability_type=VulnerabilityType.XSS,
                status=Status.PENDING
            ),
        ]
        
        scan = Scan(id=scan_id, target_id=target_id, name="Test")
        target = Target(id=target_id, name="Test", url="http://example.com")
        
        result = exporter.export(findings, scan, target)
        
        # Check severity counts in HTML
        assert "stat-card critical" in result
        assert "stat-card high" in result


class TestSARIFExporter:
    """Test SARIF exporter"""
    
    def test_format_property(self):
        exporter = SARIFExporter()
        assert exporter.format == "sarif"
    
    def test_export_empty_findings(self):
        exporter = SARIFExporter()
        
        scan_id = uuid4()
        target_id = uuid4()
        
        scan = Scan(id=scan_id, target_id=target_id, name="Test Scan")
        target = Target(id=target_id, name="Test Target", url="http://example.com")
        
        result = exporter.export([], scan, target)
        
        data = json.loads(result)
        assert data["version"] == "2.1.0"
        assert "$schema" in data
    
    def test_export_with_findings(self):
        exporter = SARIFExporter()
        
        scan_id = uuid4()
        target_id = uuid4()
        
        findings = [
            Finding(
                id=uuid4(),
                scan_id=scan_id,
                target_id=target_id,
                title="SQL Injection",
                description="SQLi",
                severity=Severity.CRITICAL,
                vulnerability_type=VulnerabilityType.SQL_INJECTION,
                status=Status.PENDING
            ),
        ]
        
        scan = Scan(id=scan_id, target_id=target_id, name="Test Scan")
        target = Target(id=target_id, name="Test Target", url="http://example.com")
        
        result = exporter.export(findings, scan, target)
        
        data = json.loads(result)
        assert len(data["runs"]) == 1
        assert data["runs"][0]["tool"]["driver"]["name"] == "VulnScope"
    
    def test_map_severity_to_sarif_level(self):
        exporter = SARIFExporter()
        
        assert exporter._map_severity_to_sarif_level(Severity.CRITICAL) == "error"
        assert exporter._map_severity_to_sarif_level(Severity.HIGH) == "error"
        assert exporter._map_severity_to_sarif_level(Severity.MEDIUM) == "warning"
        assert exporter._map_severity_to_sarif_level(Severity.LOW) == "note"
        assert exporter._map_severity_to_sarif_level(Severity.INFO) == "note"


class TestCSVExporter:
    """Test CSV exporter"""
    
    def test_format_property(self):
        exporter = CSVExporter()
        assert exporter.format == "csv"
    
    def test_export_empty_findings(self):
        exporter = CSVExporter()
        
        scan_id = uuid4()
        target_id = uuid4()
        
        scan = Scan(id=scan_id, target_id=target_id, name="Test Scan")
        target = Target(id=target_id, name="Test Target", url="http://example.com")
        
        result = exporter.export([], scan, target)
        
        # Should have header row
        lines = result.strip().split("\n")
        assert len(lines) == 1
        assert "ID" in lines[0]
        assert "Title" in lines[0]
    
    def test_export_with_findings(self):
        exporter = CSVExporter()
        
        scan_id = uuid4()
        target_id = uuid4()
        
        findings = [
            Finding(
                id=uuid4(),
                scan_id=scan_id,
                target_id=target_id,
                title="SQL Injection",
                description="SQL injection in login form",
                severity=Severity.CRITICAL,
                vulnerability_type=VulnerabilityType.SQL_INJECTION,
                status=Status.PENDING
            ),
            Finding(
                id=uuid4(),
                scan_id=scan_id,
                target_id=target_id,
                title="XSS",
                description="Reflected XSS",
                severity=Severity.HIGH,
                vulnerability_type=VulnerabilityType.XSS,
                status=Status.PENDING
            ),
        ]
        
        scan = Scan(id=scan_id, target_id=target_id, name="Test Scan")
        target = Target(id=target_id, name="Test Target", url="http://example.com")
        
        result = exporter.export(findings, scan, target)
        
        lines = result.strip().split("\n")
        # Header + 2 findings
        assert len(lines) == 3
        assert "SQL Injection" in result
        assert "XSS" in result
    
    def test_csv_header_format(self):
        exporter = CSVExporter()
        
        scan_id = uuid4()
        target_id = uuid4()
        
        scan = Scan(id=scan_id, target_id=target_id, name="Test")
        target = Target(id=target_id, name="Test", url="http://example.com")
        
        result = exporter.export([], scan, target)
        
        expected_headers = ["ID", "Title", "Description", "Severity", "Type", "Status", "CWE", "CVE", "Remediation", "Discovered At"]
        for header in expected_headers:
            assert header in result


if __name__ == "__main__":
    pytest.main([__file__, "-v"])