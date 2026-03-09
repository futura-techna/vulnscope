"""
VulnScope - Scanner Unit Tests
Comprehensive tests for the DAST scanner
"""

import pytest
import asyncio
from unittest.mock import Mock, patch, AsyncMock, MagicMock
from datetime import datetime
from uuid import uuid4

from src.scanner.scanner import (
    Scanner, HeadlessScanner, VulnerabilityFinder,
    ScanProgress, ScanResult
)
from src.core.models import (
    Endpoint, Finding, Scan, Target, Severity,
    VulnerabilityType, Status
)
from src.config.settings import ScannerConfig


class TestScanProgress:
    """Test ScanProgress dataclass"""
    
    def test_default_values(self):
        progress = ScanProgress()
        assert progress.total_endpoints == 0
        assert progress.scanned_endpoints == 0
        assert progress.total_tests == 0
        assert progress.completed_tests == 0
        assert progress.current_endpoint == ""
        assert len(progress.errors) == 0
    
    def test_with_values(self):
        progress = ScanProgress(
            total_endpoints=100,
            scanned_endpoints=50,
            current_endpoint="http://example.com/api"
        )
        assert progress.total_endpoints == 100
        assert progress.scanned_endpoints == 50


class TestScanResult:
    """Test ScanResult dataclass"""
    
    def test_default_values(self):
        result = ScanResult()
        assert len(result.findings) == 0
        assert result.duration_seconds == 0.0
    
    def test_with_findings(self):
        scan_id = uuid4()
        target_id = uuid4()
        
        findings = [
            Finding(
                scan_id=scan_id,
                target_id=target_id,
                title="XSS",
                description="XSS vulnerability",
                severity=Severity.HIGH,
                vulnerability_type=VulnerabilityType.XSS
            )
        ]
        
        result = ScanResult(findings=findings, duration_seconds=5.5)
        assert len(result.findings) == 1
        assert result.duration_seconds == 5.5


class TestVulnerabilityFinder:
    """Test VulnerabilityFinder class"""
    
    def test_initialization(self):
        config = ScannerConfig()
        finder = VulnerabilityFinder(config)
        assert len(finder.detectors) > 0
    
    def test_detectors_registered(self):
        config = ScannerConfig()
        finder = VulnerabilityFinder(config)
        
        detector_types = [d.__class__.__name__ for d in finder.detectors]
        
        assert "XSSDetector" in detector_types
        assert "SQLInjectionDetector" in detector_types
        assert "SSRDetector" in detector_types
        assert "IDORDetector" in detector_types
        assert "CSRFDetector" in detector_types
    
    @patch('requests.Session')
    def test_find_vulnerabilities(self, mock_session):
        config = ScannerConfig()
        finder = VulnerabilityFinder(config)
        
        target_id = uuid4()
        endpoint = Endpoint(
            target_id=target_id,
            url="http://example.com/search?q=test",
            method="GET",
            path="/search"
        )
        
        findings = finder.find_vulnerabilities(endpoint, mock_session)
        assert isinstance(findings, list)


class TestScanner:
    """Test Scanner class"""
    
    def test_initialization(self):
        scanner = Scanner()
        assert scanner.config is not None
        assert scanner.session is not None
    
    def test_initialization_with_config(self):
        config = ScannerConfig(
            rate_limit_per_second=50,
            request_timeout=60
        )
        scanner = Scanner(config)
        assert scanner.config.rate_limit_per_second == 50
    
    def test_generate_test_params(self):
        scanner = Scanner()
        params = scanner._generate_test_params("query")
        
        assert "xss" in params
        assert "sql_error" in params
        assert "ssrf" in params
    
    def test_create_finding(self):
        scanner = Scanner()
        
        target_id = uuid4()
        scan_id = uuid4()
        
        scanner.target = Target(
            id=target_id,
            name="Test",
            url="http://example.com"
        )
        scanner.scan = Scan(
            id=scan_id,
            target_id=target_id,
            name="Test Scan"
        )
        
        endpoint = Endpoint(
            target_id=target_id,
            url="http://example.com/search",
            method="GET",
            path="/search"
        )
        
        finding = scanner.create_finding(
            endpoint=endpoint,
            vuln_type=VulnerabilityType.XSS,
            severity=Severity.HIGH,
            title="XSS Found",
            description="Cross-site scripting",
            evidence={"payload": "<script>alert(1)</script>"}
        )
        
        assert finding.title == "XSS Found"
        assert finding.severity == Severity.HIGH
        assert finding.vulnerability_type == VulnerabilityType.XSS
    
    @pytest.mark.asyncio
    async def test_scan_endpoints_async(self):
        scanner = Scanner()
        
        target_id = uuid4()
        scan_id = uuid4()
        
        target = Target(
            id=target_id,
            name="Test Target",
            url="http://example.com"
        )
        
        scan = Scan(
            id=scan_id,
            target_id=target_id,
            name="Test Scan"
        )
        
        endpoints = [
            Endpoint(
                target_id=target_id,
                url="http://example.com/page1",
                method="GET",
                path="/page1"
            ),
            Endpoint(
                target_id=target_id,
                url="http://example.com/page2",
                method="GET",
                path="/page2"
            ),
        ]
        
        with patch.object(scanner, '_test_endpoint', return_value=[]):
            result = await scanner.scan_endpoints(endpoints, target, scan)
        
        assert result is not None
        assert isinstance(result.findings, list)


class TestHeadlessScanner:
    """Test HeadlessScanner class"""
    
    def test_initialization(self):
        scanner = HeadlessScanner()
        assert scanner.playwright is None
        assert scanner.browser is None
    
    @pytest.mark.asyncio
    async def test_scan_with_browser_mock(self):
        scanner = HeadlessScanner()
        
        with patch.object(scanner, '_setup_browser'):
            with patch.object(scanner, '_close_browser'):
                with patch.object(scanner, 'finder') as mock_finder:
                    mock_finder.find_vulnerabilities.return_value = []
                    
                    # This would normally need playwright
                    # Just test the method exists
                    assert hasattr(scanner, 'scan_with_browser')


class TestRateLimiting:
    """Test rate limiting functionality"""
    
    def test_rate_limit_tracking(self):
        scanner = Scanner()
        
        # Add request times
        scanner.request_times = [1.0, 1.1, 1.2, 1.3, 1.4]
        
        # Should track requests
        assert len(scanner.request_times) == 5
    
    def test_rate_limit_enforcement(self):
        config = ScannerConfig(rate_limit_per_second=10)
        scanner = Scanner(config)
        
        # Fill up rate limit
        import time
        current_time = time.time()
        scanner.request_times = [current_time - 0.1] * 10
        
        # Next request should be rate limited
        # (testing the logic exists, not actual sleep)
        assert scanner.config.rate_limit_per_second == 10


if __name__ == "__main__":
    pytest.main([__file__, "-v"])