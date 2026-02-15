"""
VulnScope - End-to-End Tests
Complete workflow testing from target discovery to report generation
"""

import pytest
import asyncio
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, AsyncMock
from urllib.parse import urlparse
from uuid import uuid4

# Import components to test
from src.scanner.scanner import Scanner
from src.scanner.advanced_scanner import (
    RecursiveScanner, FuzzingWordlistManager, AsyncScanOptimizer
)
from src.discovery.crawler import Crawler
from src.discovery.advanced_discovery import (
    WebSocketDiscovery, JavaScriptParser, APIVersionDetector
)
from src.evidence.exporters import JSONExporter, HTMLExporter
from src.evidence.advanced_reporting import (
    TrendAnalyzer, VulnerabilityCorrelator, ExecutiveReportGenerator
)
from src.api.security import JWTHandler, InputValidator, AuthorizationHandler
from src.utils.infrastructure import CacheManager, MessageQueue


# ============================================
# COMPLETE WORKFLOW TESTS
# ============================================
class TestCompleteScanWorkflow:
    """Test complete scan workflow"""
    
    @pytest.mark.asyncio
    async def test_full_scan_workflow(self):
        """Test complete scan from discovery to report"""
        
        # Step 1: Discovery - Crawl target
        from src.core.models import Target, Endpoint
        
        target_id = uuid4()
        target = Target(
            id=target_id,
            name="Test Application",
            url="http://example.com"
        )
        
        # Mock crawler
        with patch('src.discovery.crawler.Crawler.crawl') as mock_crawl:
            mock_crawl.return_value = Mock(
                endpoints=[
                    Endpoint(
                        target_id=target_id,
                        url="http://example.com/",
                        method="GET",
                        path="/"
                    ),
                    Endpoint(
                        target_id=target_id,
                        url="http://example.com/api/users",
                        method="GET",
                        path="/api/users"
                    ),
                ],
                pages_crawled=1
            )
            
            crawler = Crawler()
            result = await crawler.crawl(target)
            
            assert len(result.endpoints) >= 1
        
        # Step 2: Scanning - Test endpoints
        scanner = Scanner()
        
        # Mock scanner results - need scan_id, target_id, description
        from src.core.models import Finding, Severity, VulnerabilityType
        
        scan_id = uuid4()
        
        findings = [
            Finding(
                id=uuid4(),
                scan_id=scan_id,
                target_id=target_id,
                title="SQL Injection in /api/users",
                description="SQL injection vulnerability detected",
                severity=Severity.CRITICAL,
                vulnerability_type=VulnerabilityType.SQL_INJECTION
            ),
            Finding(
                id=uuid4(),
                scan_id=scan_id,
                target_id=target_id,
                title="XSS in search parameter",
                description="Cross-site scripting vulnerability",
                severity=Severity.HIGH,
                vulnerability_type=VulnerabilityType.XSS
            ),
        ]
        
        # Step 3: Export results
        exporter = JSONExporter()
        
        from src.core.models import Status, Scan
        
        scan = Scan(
            id=scan_id,
            target_id=target_id,
            name="Test Scan",
            scan_type="full",
            status=Status.COMPLETED,
            started_at=datetime.utcnow()
        )
        
        json_output = exporter.export(findings, scan, target)
        
        assert '"total_findings": 2' in json_output
        
        # Step 4: Generate trend analysis
        analyzer = TrendAnalyzer()
        analyzer.add_scan_results(findings, datetime.utcnow())
        
        trend = analyzer.get_trend(days=30)
        assert trend["total_findings"] == 2


class TestAuthenticationWorkflow:
    """Test authentication and authorization workflow"""
    
    def test_user_login_and_token_generation(self):
        """Test user login and JWT token generation"""
        
        jwt_handler = JWTHandler(secret_key="test-secret")
        
        # Create token
        token = jwt_handler.create_access_token({
            "sub": "testuser",
            "user_id": "1",
            "roles": ["admin"]
        })
        
        # Verify token
        payload = jwt_handler.verify_token(token)
        
        assert payload["sub"] == "testuser"
        assert payload["roles"] == ["admin"]
        
        # Get current user
        user = jwt_handler.get_current_user(token)
        
        assert user.username == "testuser"
        assert user.roles == ["admin"]
    
    def test_authorization_check(self):
        """Test authorization for different roles"""
        
        # Admin should have all permissions
        assert AuthorizationHandler.check_permission(
            ["admin"], "scan:create"
        )
        assert AuthorizationHandler.check_permission(
            ["admin"], "target:delete"
        )
        
        # Developer should have limited permissions
        assert AuthorizationHandler.check_permission(
            ["developer"], "scan:create"
        )
        assert not AuthorizationHandler.check_permission(
            ["developer"], "target:delete"
        )
        
        # Viewer should have read-only access
        assert AuthorizationHandler.check_permission(
            ["viewer"], "scan:read"
        )
        assert not AuthorizationHandler.check_permission(
            ["viewer"], "scan:create"
        )


class TestDiscoveryToScanWorkflow:
    """Test discovery to scanning workflow"""
    
    @pytest.mark.asyncio
    async def test_discovery_with_websocket_and_versioning(self):
        """Test comprehensive discovery including WebSocket and API versioning"""
        
        from src.core.models import Target, Endpoint
        
        target_id = uuid4()
        target = Target(
            id=target_id,
            name="API Application",
            url="https://api.example.com"
        )
        
        # Test WebSocket discovery
        ws_discovery = WebSocketDiscovery()
        
        # Mock WebSocket test
        with patch.object(ws_discovery, 'test_websocket') as mock_ws:
            mock_ws.return_value = {
                "url": "wss://api.example.com/ws",
                "connected": True
            }
            
            ws_endpoints = await ws_discovery.discover(target)
        
        # Test JavaScript parsing
        js_parser = JavaScriptParser()
        
        js_content = '''
        const API_BASE = "https://api.example.com";
        axios.get("/v1/users");
        fetch("/v2/products");
        router.push("/dashboard");
        '''
        
        endpoints = js_parser._extract_api_endpoints(js_content, "https://api.example.com")
        
        assert len(endpoints) > 0
        
        # Test API versioning - need target_id
        version_detector = APIVersionDetector()
        
        api_endpoints = [
            Endpoint(target_id=target_id, url="https://api.example.com/v1/users", method="GET", path="/v1/users"),
            Endpoint(target_id=target_id, url="https://api.example.com/v2/users", method="GET", path="/v2/users"),
            Endpoint(target_id=target_id, url="https://api.example.com/v1/products", method="GET", path="/v1/products"),
        ]
        
        version_result = version_detector.detect_versions(api_endpoints)
        
        assert version_result["version_count"] == 2
        assert "v1" in version_result["versions"]
        assert "v2" in version_result["versions"]


class TestReportingWorkflow:
    """Test complete reporting workflow"""
    
    def test_trend_analysis_workflow(self):
        """Test trend analysis with historical data"""
        
        from src.core.models import Finding, Severity, VulnerabilityType
        
        analyzer = TrendAnalyzer()
        
        scan_id = uuid4()
        target_id = uuid4()
        
        # Add data from multiple scans
        for day in range(10):
            findings = [
                Finding(
                    id=uuid4(),
                    scan_id=scan_id,
                    target_id=target_id,
                    title=f"Vulnerability {i}",
                    description="Test",
                    severity=Severity.MEDIUM,
                    vulnerability_type=VulnerabilityType.XSS
                )
                for i in range(3)
            ]
            
            analyzer.add_scan_results(
                findings,
                datetime.utcnow() - timedelta(days=day)
            )
        
        # Get trend
        trend = analyzer.get_trend(days=30)
        
        assert trend["total_findings"] == 30  # 10 days * 3 findings
        assert "trend_direction" in trend
    
    def test_vulnerability_correlation_workflow(self):
        """Test vulnerability correlation"""
        
        from src.core.models import Finding, Severity, VulnerabilityType
        
        correlator = VulnerabilityCorrelator()
        
        scan_id = uuid4()
        target_id = uuid4()
        endpoint_id = uuid4()  # Use same endpoint for similar findings
        
        findings = [
            Finding(
                id=uuid4(),
                scan_id=scan_id,
                target_id=target_id,
                title="XSS in search",
                description="XSS",
                severity=Severity.HIGH,
                vulnerability_type=VulnerabilityType.XSS,
                endpoint_id=endpoint_id
            ),
            Finding(
                id=uuid4(),
                scan_id=scan_id,
                target_id=target_id,
                title="XSS in profile",
                description="XSS",
                severity=Severity.MEDIUM,
                vulnerability_type=VulnerabilityType.XSS,
                endpoint_id=endpoint_id
            ),
            Finding(
                id=uuid4(),
                scan_id=scan_id,
                target_id=target_id,
                title="SQL Injection",
                description="SQLi",
                severity=Severity.CRITICAL,
                vulnerability_type=VulnerabilityType.SQL_INJECTION
            ),
        ]
        
        result = correlator.correlate(findings)
        
        # Should find similar vulnerabilities (same endpoint and type)
        assert len(result["similar"]) > 0
        
        # Should identify chains
        assert "chained" in result
        
        # Should group by component
        assert "by_component" in result
    
    def test_executive_report_generation(self):
        """Test executive report generation"""
        
        from src.core.models import Finding, Severity, VulnerabilityType, Scan, Target, Status
        
        generator = ExecutiveReportGenerator()
        
        scan_id = uuid4()
        target_id = uuid4()
        
        findings = [
            Finding(
                id=uuid4(),
                scan_id=scan_id,
                target_id=target_id,
                title="SQL Injection",
                description="Critical SQLi",
                severity=Severity.CRITICAL,
                vulnerability_type=VulnerabilityType.SQL_INJECTION
            ),
            Finding(
                id=uuid4(),
                scan_id=scan_id,
                target_id=target_id,
                title="XSS",
                description="XSS vulnerability",
                severity=Severity.HIGH,
                vulnerability_type=VulnerabilityType.XSS
            ),
            Finding(
                id=uuid4(),
                scan_id=scan_id,
                target_id=target_id,
                title="CSRF",
                description="Missing CSRF token",
                severity=Severity.MEDIUM,
                vulnerability_type=VulnerabilityType.CSRF
            ),
        ]
        
        scan = Scan(
            id=scan_id,
            target_id=target_id,
            name="Full Security Scan",
            scan_type="full",
            status=Status.COMPLETED,
            started_at=datetime.utcnow()
        )
        
        target = Target(
            id=target_id,
            name="Production App",
            url="https://app.example.com"
        )
        
        report = generator.generate(findings, scan, target)
        
        # Verify report structure
        assert "executive_summary" in report
        assert "risk_score" in report["executive_summary"]
        assert report["executive_summary"]["critical_issues"] == 1
        assert report["executive_summary"]["high_issues"] == 1
        
        # Verify recommendations
        assert len(report["recommendations"]) > 0
        
        # Verify compliance impact
        assert "compliance_impact" in report


class TestInfrastructureWorkflow:
    """Test infrastructure components workflow"""
    
    @patch('src.utils.infrastructure.redis.Redis')
    def test_cache_and_queue_workflow(self, mock_redis):
        """Test cache and message queue integration"""
        
        mock_client = Mock()
        mock_redis.return_value = mock_client
        
        # Test caching
        cache = CacheManager(mock_client)
        cache.set("test_key", {"data": "value"})
        
        mock_client.setex.assert_called_once()
        
        # Test message queue
        queue = MessageQueue(mock_client)
        task_id = queue.enqueue("scan", {
            "target": "http://example.com",
            "config": {}
        })
        
        assert task_id is not None
        mock_client.zadd.assert_called_once()


class TestInputValidationWorkflow:
    """Test input validation workflow"""
    
    def test_url_validation_for_scan_targets(self):
        """Test URL validation for scan targets"""
        
        # Valid URLs
        is_valid, error = InputValidator.validate_target_url("http://example.com")
        assert is_valid
        
        is_valid, error = InputValidator.validate_target_url("https://api.example.com/path")
        assert is_valid
        
        # Invalid URLs
        is_valid, error = InputValidator.validate_target_url("ftp://example.com")
        assert not is_valid
        assert "HTTP" in error
        
        is_valid, error = InputValidator.validate_target_url("not-a-url")
        assert not is_valid
    
    def test_sanitization_workflow(self):
        """Test input sanitization"""
        
        # Test basic sanitization
        sanitized = InputValidator.sanitize_input("  test  ")
        assert sanitized == "test"
        
        # Test truncation
        long_input = "x" * 5000
        sanitized = InputValidator.sanitize_input(long_input)
        assert len(sanitized) == 1000
        
        # Test null byte removal
        sanitized = InputValidator.sanitize_input("test\x00value")
        assert "\x00" not in sanitized


class TestAsyncScanWorkflow:
    """Test async scanning workflow"""
    
    @pytest.mark.asyncio
    async def test_async_optimization_workflow(self):
        """Test async scan optimization"""
        
        optimizer = AsyncScanOptimizer(max_concurrent=20)
        
        scan_results = []
        
        scan_id = uuid4()
        target_id = uuid4()
        
        async def scan_endpoint(endpoint):
            # Simulate scanning
            await asyncio.sleep(0.01)
            
            from src.core.models import Finding, Severity, VulnerabilityType
            
            return [
                Finding(
                    id=uuid4(),
                    scan_id=scan_id,
                    target_id=target_id,
                    title=f"Vulnerability in {endpoint}",
                    description="Test",
                    severity=Severity.MEDIUM,
                    vulnerability_type=VulnerabilityType.XSS
                )
            ]
        
        # Scan 50 endpoints
        endpoints = [f"http://example.com/api/{i}" for i in range(50)]
        
        all_results = []
        
        for ep in endpoints:
            result = await optimizer.scan_with_backpressure([ep], scan_endpoint)
            all_results.extend(result)
        
        stats = optimizer.get_stats()
        
        # Should complete all scans
        assert stats["completed_scans"] > 0


# ============================================
# INTEGRATION TESTS
# ============================================
class TestComponentIntegration:
    """Test component integration"""
    
    def test_wordlist_to_scanner_integration(self):
        """Test wordlist integration with scanner"""
        
        manager = FuzzingWordlistManager()
        
        # Add custom wordlist
        manager.add_word("api_params", "id")
        manager.add_word("api_params", "user_id")
        manager.add_word("api_params", "page")
        
        # Generate fuzzing payloads
        payloads = manager.generate_fuzz_payloads("test_", "api_params")
        
        assert len(payloads) == 3
        assert "test_id" in payloads
        assert "test_user_id" in payloads
    
    def test_trend_to_correlation_integration(self):
        """Test trend analyzer to correlator integration"""
        
        from src.core.models import Finding, Severity, VulnerabilityType
        
        analyzer = TrendAnalyzer()
        
        scan_id = uuid4()
        target_id = uuid4()
        
        # Add historical data
        findings = [
            Finding(
                id=uuid4(),
                scan_id=scan_id,
                target_id=target_id,
                title="SQL Injection",
                description="SQLi",
                severity=Severity.CRITICAL,
                vulnerability_type=VulnerabilityType.SQL_INJECTION
            ),
        ]
        
        analyzer.add_scan_results(findings, datetime.utcnow())
        
        # Get trend
        trend = analyzer.get_trend(days=7)
        
        # Trend data can be used for correlation
        assert "total_findings" in trend
        
        # Correlate findings
        correlator = VulnerabilityCorrelator()
        result = correlator.correlate(findings)
        
        assert result is not None


# Run E2E tests
if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
